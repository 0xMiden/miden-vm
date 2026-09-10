#!/usr/bin/env -S cargo +nightly -Zscript
---cargo
[package]
edition = "2024"

[dependencies]
miden-assembly-current = { package = "miden-assembly", path = "../crates/assembly" }
miden-assembly-syntax-current = { package = "miden-assembly-syntax", path = "../crates/assembly-syntax" }
miden-mast-package-current = { package = "miden-mast-package", path = "../crates/mast-package" }
miden-package-registry-current = { package = "miden-package-registry", path = "../crates/package-registry", features = ["resolver"] }

# The release wrapper rewrites these tags to the latest release tag on main.
miden-assembly-previous = { package = "miden-assembly", git = "https://github.com/0xMiden/miden-vm", tag = "v0.32.0" }
miden-assembly-syntax-previous = { package = "miden-assembly-syntax", git = "https://github.com/0xMiden/miden-vm", tag = "v0.32.0" }
miden-mast-package-previous = { package = "miden-mast-package", git = "https://github.com/0xMiden/miden-vm", tag = "v0.32.0" }
miden-package-registry-previous = { package = "miden-package-registry", git = "https://github.com/0xMiden/miden-vm", tag = "v0.32.0", features = ["resolver"] }
---

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::{Path, PathBuf},
    process,
};

// Release compatibility has four separate boundaries. Executable compatibility protects
// exported procedure paths and MAST digests while reporting source-facing interface corrections
// alongside the affected procedure. Fast ABI compatibility protects the number of input and
// output felts consumed by previously published Fast procedures when selected explicitly. Source
// compatibility reports changes to published nominal signatures, calling conventions, exported
// types, and source attributes. It is advisory during a release because a patch may preserve the
// Fast ABI without preserving source syntax.
// Package compatibility prevents one semantic version from identifying two dependency commitments
// and reports when old serialized dependents require the previous package to remain archived.

type Exports = BTreeMap<String, ExportInfo>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageInfo {
    name: String,
    version: String,
    exports: Exports,
    commitments: PackageCommitments,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageCommitments {
    interface: String,
    mast_forest: String,
    code: String,
    dependency: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExportInfo {
    Procedure(ProcedureInfo),
    Type(TypeInfo),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcedureInfo {
    digest: String,
    signature: Option<String>,
    calling_convention: Option<String>,
    felt_layout: Option<FeltLayoutInfo>,
    abi_attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FeltLayoutInfo {
    inputs: usize,
    outputs: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcedureCompatibility {
    Compatible,
    InterfaceChanged,
    ExecutableChanged { interface_changed: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TypeInfo {
    ty: String,
}

impl ExportInfo {
    fn describe(&self) -> String {
        match self {
            Self::Procedure(procedure) => procedure.describe(),
            Self::Type(ty) => ty.describe(),
        }
    }
}

impl ProcedureInfo {
    fn describe(&self) -> String {
        let Self {
            digest,
            signature,
            calling_convention,
            felt_layout,
            abi_attributes,
        } = self;
        format!(
            "procedure digest={digest}, signature={}, callconv={}, felt_layout={}, abi_attributes={}",
            signature.as_deref().unwrap_or("None"),
            calling_convention.as_deref().unwrap_or("None"),
            felt_layout
                .as_ref()
                .map(FeltLayoutInfo::describe)
                .unwrap_or_else(|| "None".to_string()),
            format_attributes(abi_attributes),
        )
    }

    fn interface_description(&self) -> String {
        format!(
            "signature={}, callconv={}, layout={}",
            self.signature.as_deref().unwrap_or("None"),
            self.calling_convention.as_deref().unwrap_or("None"),
            self.felt_layout
                .as_ref()
                .map(FeltLayoutInfo::describe)
                .unwrap_or_else(|| "unknown".to_string()),
        )
    }
}

impl FeltLayoutInfo {
    fn describe(&self) -> String {
        format!("{} input felts, {} output felts", self.inputs, self.outputs)
    }
}

fn classify_procedure_compatibility(
    previous: &ProcedureInfo,
    current: &ProcedureInfo,
) -> ProcedureCompatibility {
    let interface_changed = previous.calling_convention != current.calling_convention
        || previous.signature.as_deref().map(canonicalize_type_string)
            != current.signature.as_deref().map(canonicalize_type_string);

    match (previous.digest == current.digest, interface_changed) {
        (true, false) => ProcedureCompatibility::Compatible,
        (true, true) => ProcedureCompatibility::InterfaceChanged,
        (false, interface_changed) => {
            ProcedureCompatibility::ExecutableChanged { interface_changed }
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    All,
    Executable,
    FastAbi,
    Source,
    Package,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Diagnostic {
    Error,
    Warning,
}

impl Diagnostic {
    fn annotation(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

impl Check {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "all" => Ok(Self::All),
            "executable" => Ok(Self::Executable),
            "fast-abi" => Ok(Self::FastAbi),
            "source" => Ok(Self::Source),
            "package" => Ok(Self::Package),
            _ => Err(format!("unknown compatibility check '{value}'\n{}", usage())),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Executable => "Executable compatibility",
            Self::FastAbi => "Fast ABI compatibility",
            Self::Source => "Source compatibility",
            Self::Package => "Package compatibility",
        }
    }

    fn consequence(self) -> &'static str {
        match self {
            Self::All => "all compatibility checks run",
            Self::Executable => {
                "old compiled callers resolve the same paths to the same executable MAST roots"
            },
            Self::FastAbi => {
                "old compiled Fast callers provide and receive the same number of felts"
            },
            Self::Source => {
                "reports whether released MASM source continues to type-check without changes"
            },
            Self::Package => {
                "one semantic version identifies one dependency commitment; older commitments must remain archived"
            },
        }
    }
}

impl TypeInfo {
    fn describe(&self) -> String {
        format!("type={}", self.ty)
    }
}

fn format_attributes(attributes: &BTreeMap<String, String>) -> String {
    if attributes.is_empty() {
        return "None".to_string();
    }

    attributes
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let first = args.next().ok_or_else(usage)?;
    let (check, previous_input) = if first == "--check" {
        let check = args.next().ok_or_else(usage)?;
        let previous = args.next().map(PathBuf::from).ok_or_else(usage)?;
        (Check::parse(&check)?, previous)
    } else {
        (Check::All, PathBuf::from(first))
    };
    let current_input = args.next().map(PathBuf::from).ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }

    let previous = previous::collect_package(&previous_input)?;
    let current = current::collect_package(&current_input)?;
    compare_compatibility(check, &previous, &current)
}

fn usage() -> String {
    "usage: check-masm-export-digests.rs [--check all|executable|fast-abi|source|package] <previous-miden-project.toml|previous-project-dir> <current-miden-project.toml|current-project-dir>".to_string()
}

fn compare_compatibility(
    check: Check,
    previous: &PackageInfo,
    current: &PackageInfo,
) -> Result<(), String> {
    let release_check = check == Check::All;
    let checks = match check {
        Check::All => vec![Check::Executable, Check::Source, Check::Package],
        selected => vec![selected],
    };
    let mut failed = Vec::new();

    for selected in checks {
        println!("::group::{}", selected.label());
        println!("Consequence: {}", selected.consequence());
        let result = match selected {
            Check::Executable => compare_executable(&previous.exports, &current.exports),
            Check::FastAbi => compare_fast_abi(&previous.exports, &current.exports),
            Check::Source => compare_source(
                &previous.exports,
                &current.exports,
                if release_check {
                    Diagnostic::Warning
                } else {
                    Diagnostic::Error
                },
                !release_check,
            ),
            Check::Package => compare_package(previous, current),
            Check::All => unreachable!("all expands to individual checks"),
        };
        println!("::endgroup::");
        if result.is_err() && selected == Check::Source && release_check {
            println!(
                "::notice::source compatibility changed; source changes do not block this release"
            );
        } else if result.is_err() {
            failed.push(selected.label());
        }
    }

    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("compatibility checks failed: {}", failed.join(", ")))
    }
}

fn compare_executable(previous: &Exports, current: &Exports) -> Result<(), String> {
    let mut status = Ok(());
    let mut checked = 0usize;
    for (name, previous_export) in previous {
        let ExportInfo::Procedure(previous_procedure) = previous_export else {
            continue;
        };
        checked += 1;
        match current.get(name) {
            Some(ExportInfo::Procedure(current_procedure)) => {
                match classify_procedure_compatibility(previous_procedure, current_procedure) {
                    ProcedureCompatibility::Compatible => {},
                    ProcedureCompatibility::InterfaceChanged => {
                        println!(
                            "::warning::procedure interface changed for {name} without an executable change; source callers may need updates: previous={}, current={}",
                            previous_procedure.interface_description(),
                            current_procedure.interface_description(),
                        );
                    },
                    ProcedureCompatibility::ExecutableChanged { interface_changed } => {
                        println!(
                            "::error::procedure executable changed for {name}: MAST root previous={}, current={}; interface={}",
                            previous_procedure.digest,
                            current_procedure.digest,
                            if interface_changed { "changed" } else { "unchanged" },
                        );
                        if interface_changed {
                            println!(
                                "::error::procedure interface also changed for {name}: previous={}, current={}",
                                previous_procedure.interface_description(),
                                current_procedure.interface_description(),
                            );
                        }
                        status = Err("executable exports changed".to_string());
                    },
                }
            },
            Some(current_export) => {
                println!(
                    "::error::executable export kind changed for {name}: previous={}, current={}",
                    previous_export.describe(),
                    current_export.describe(),
                );
                status = Err("executable exports changed".to_string());
            },
            None => {
                println!("::error::executable export removed: {name}");
                status = Err("executable exports changed".to_string());
            },
        }
    }
    println!("checked {checked} previously published procedure digests");
    status
}

fn compare_fast_abi(previous: &Exports, current: &Exports) -> Result<(), String> {
    let mut status = Ok(());
    let mut checked = 0usize;
    for (name, previous_export) in previous {
        let ExportInfo::Procedure(previous_procedure) = previous_export else {
            continue;
        };
        if previous_procedure.calling_convention.as_deref() != Some("fast") {
            continue;
        }
        let Some(previous_abi) = &previous_procedure.felt_layout else {
            continue;
        };
        checked += 1;
        match current.get(name) {
            Some(ExportInfo::Procedure(current_procedure))
                if current_procedure.calling_convention.as_deref() == Some("fast")
                    && current_procedure.felt_layout.as_ref() == Some(previous_abi) => {},
            Some(ExportInfo::Procedure(current_procedure)) => {
                let current_abi = current_procedure
                    .felt_layout
                    .as_ref()
                    .map(FeltLayoutInfo::describe)
                    .unwrap_or_else(|| "not Fast".to_string());
                println!(
                    "::error::Fast ABI changed for {name}: previous={}, current={current_abi}",
                    previous_abi.describe(),
                );
                status = Err("Fast ABI changed".to_string());
            },
            _ => {
                println!("::error::Fast ABI export removed: {name}");
                status = Err("Fast ABI changed".to_string());
            },
        }
    }
    println!("checked {checked} previously published Fast procedure layouts");
    status
}

fn compare_source(
    previous: &Exports,
    current: &Exports,
    diagnostic: Diagnostic,
    report_interfaces: bool,
) -> Result<(), String> {
    let mut status = Ok(());
    let mut added = 0usize;
    let export_names = previous.keys().chain(current.keys()).cloned().collect::<BTreeSet<_>>();

    for name in export_names {
        match (previous.get(&name), current.get(&name)) {
            (Some(previous_export), Some(current_export)) if previous_export == current_export => {
            },
            (Some(ExportInfo::Procedure(previous)), Some(ExportInfo::Procedure(current))) => {
                if compare_source_procedure(
                    &name,
                    previous,
                    current,
                    diagnostic,
                    report_interfaces,
                ) {
                    status = Err("source exports changed".to_string());
                }
            },
            (Some(ExportInfo::Type(previous)), Some(ExportInfo::Type(current))) => {
                if canonicalize_type_string(&previous.ty) != canonicalize_type_string(&current.ty) {
                    println!(
                        "::{}::source type changed for {name}: previous={}, current={}",
                        diagnostic.annotation(),
                        previous.ty,
                        current.ty,
                    );
                    status = Err("source exports changed".to_string());
                }
            },
            (Some(previous_export), Some(current_export)) => {
                println!(
                    "::{}::source export kind changed for {name}: previous={}, current={}",
                    diagnostic.annotation(),
                    previous_export.describe(),
                    current_export.describe(),
                );
                status = Err("source exports changed".to_string());
            },
            (Some(previous_export), None) => {
                println!(
                    "::{}::source export removed: {name} previous={}",
                    diagnostic.annotation(),
                    previous_export.describe(),
                );
                status = Err("source exports changed".to_string());
            },
            (None, Some(_)) => {
                added += 1;
            },
            (None, None) => unreachable!("name came from at least one side"),
        }
    }
    if added > 0 {
        println!("::notice::{added} source exports added; additions are source-compatible");
    }
    status
}

fn compare_source_procedure(
    name: &str,
    previous: &ProcedureInfo,
    current: &ProcedureInfo,
    diagnostic: Diagnostic,
    report_interface: bool,
) -> bool {
    let mut changed = false;

    if report_interface
        && previous.signature.is_some()
        && canonicalize_type_string(previous.signature.as_deref().unwrap_or(""))
            != canonicalize_type_string(current.signature.as_deref().unwrap_or(""))
    {
        println!(
            "::{}::source signature changed for {name}: previous={}, current={}",
            diagnostic.annotation(),
            previous.signature.as_deref().unwrap_or("None"),
            current.signature.as_deref().unwrap_or("None"),
        );
        changed = true;
    }

    if report_interface
        && previous.calling_convention.is_some()
        && previous.calling_convention != current.calling_convention
    {
        println!(
            "::{}::source calling convention changed for {name}: previous={}, current={}",
            diagnostic.annotation(),
            previous.calling_convention.as_deref().unwrap_or("None"),
            current.calling_convention.as_deref().unwrap_or("None"),
        );
        changed = true;
    }

    // Adding source metadata is compatible. Removing or changing published metadata is not.
    for (attr, previous_value) in &previous.abi_attributes {
        let current_value = current.abi_attributes.get(attr).map(String::as_str).unwrap_or("None");
        if previous_value != current_value {
            println!(
                "::{}::source attribute changed for {name}: {attr} previous={previous_value}, current={current_value}",
                diagnostic.annotation(),
            );
            changed = true;
        }
    }

    changed
}

fn compare_package(previous: &PackageInfo, current: &PackageInfo) -> Result<(), String> {
    let mut status = Ok(());
    if previous.name != current.name {
        println!(
            "::error::package name changed: previous={}, current={}",
            previous.name, current.name,
        );
        status = Err("package identity changed".to_string());
    }

    report_commitment("interface", &previous.commitments.interface, &current.commitments.interface);
    report_commitment(
        "MAST forest",
        &previous.commitments.mast_forest,
        &current.commitments.mast_forest,
    );
    report_commitment("code", &previous.commitments.code, &current.commitments.code);
    report_commitment(
        "dependency",
        &previous.commitments.dependency,
        &current.commitments.dependency,
    );

    if previous.commitments.dependency != current.commitments.dependency {
        if previous.version == current.version {
            println!(
                "::error::package dependency commitment changed without a version change: package={} version={} previous={}, current={}",
                current.name,
                current.version,
                previous.commitments.dependency,
                current.commitments.dependency,
            );
            status = Err("package version identifies two dependency commitments".to_string());
        } else {
            println!(
                "::notice::package dependency commitment changed with version {} -> {}; serialized dependents remain loadable only while the {} {} package is archived",
                previous.version, current.version, previous.name, previous.version,
            );
        }
    }

    status
}

fn report_commitment(label: &str, previous: &str, current: &str) {
    if previous == current {
        println!("{label} commitment unchanged: {current}");
    } else {
        println!("::notice::{label} commitment changed: previous={previous}, current={current}");
    }
}

fn is_abi_attribute(name: &str) -> bool {
    matches!(
        name,
        "account_procedure" | "auth_script" | "callconv" | "note_script" | "transaction_script"
    )
}

/// Compare a pretty-printed signature or type string ignoring struct field labels.
///
/// Struct field names are display-only metadata in Miden Assembly: they do not affect the
/// wire/memory layout, procedure MAST roots, or operand-stack encoding of a type. Changes that
/// only add, remove, or rename field labels are therefore non-breaking, even though the resolved
/// `StructType` derives `PartialEq`/`Hash` over the (now populated) name field. This helper strips
/// the `name :` prefix from each struct field so such deltas compare equal.
///
/// It deliberately preserves the nominal source contract: field types, field count, field order,
/// struct names, `repr` attributes (`@packed`, etc.), and all non-struct syntax. Only the leading
/// `ident :` of a struct field is removed.
fn canonicalize_type_string(value: &str) -> String {
    normalize(&strip_field_labels(value))
}

/// Remove the `ident :` prefix from each struct field.
///
/// We track brace depth: inside a `{...}` struct body, an identifier immediately followed (after
/// optional spaces) by `:` is a field label and is dropped along with the colon. Everything else
/// is emitted verbatim. Nested structs are handled because the depth counter tracks every brace.
fn strip_field_labels(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let mut brace_depth: i32 = 0;
    let mut at_field_start = false;

    while i < n {
        match chars[i] {
            '{' => {
                brace_depth += 1;
                at_field_start = true;
                out.push('{');
                i += 1;
            },
            '}' => {
                if brace_depth > 0 {
                    brace_depth -= 1;
                }
                at_field_start = false;
                out.push('}');
                i += 1;
            },
            ',' if brace_depth > 0 => {
                at_field_start = true;
                out.push(',');
                i += 1;
            },
            '\n' | '\r' if brace_depth > 0 => {
                at_field_start = true;
                out.push(chars[i]);
                i += 1;
            },
            c if brace_depth > 0 && at_field_start && (c.is_alphabetic() || c == '_') => {
                let start = i;
                while i < n && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '-') {
                    i += 1;
                }
                let ident: String = chars[start..i].iter().collect();
                let mut j = i;
                while j < n && (chars[j] == ' ' || chars[j] == '\t') {
                    j += 1;
                }
                if j < n && chars[j] == ':' && (j + 1 == n || chars[j + 1] != ':') {
                    i = j + 1;
                } else {
                    out.push_str(&ident);
                }
                at_field_start = false;
            },
            c => {
                if brace_depth > 0 && !c.is_whitespace() {
                    at_field_start = false;
                }
                out.push(c);
                i += 1;
            },
        }
    }

    out
}

/// Normalize whitespace and field separators so the single-line and multi-line pretty-printed
/// forms of the same type compare equal.
///
/// Inside a struct body the pretty-printer separates fields with `, ` (single-line) or a newline
/// (multi-line). We treat both as field separators and collapse any separator to a single `,`.
/// Outside struct bodies, whitespace runs collapse to a single space. A final pass drops spaces
/// adjacent to structural punctuation.
fn normalize(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    let is_ws = |c: char| c == ' ' || c == '\t' || c == '\n' || c == '\r';

    let mut pass1 = String::with_capacity(n);
    let mut brace_depth: i32 = 0;
    let mut i = 0;
    let mut pending_field_sep = false;
    while i < n {
        match chars[i] {
            '{' => {
                brace_depth += 1;
                pass1.push('{');
                pending_field_sep = false;
                i += 1;
            },
            '}' => {
                if brace_depth > 0 {
                    brace_depth -= 1;
                }
                pass1.push('}');
                pending_field_sep = false;
                i += 1;
            },
            ',' if brace_depth > 0 => {
                if pending_field_sep {
                    pass1.push(',');
                    pending_field_sep = false;
                }
                i += 1;
            },
            _ if is_ws(chars[i]) => {
                let mut has_newline = false;
                while i < n && is_ws(chars[i]) {
                    has_newline |= matches!(chars[i], '\n' | '\r');
                    i += 1;
                }
                if brace_depth > 0 {
                    let next = if i < n { Some(chars[i]) } else { None };
                    if has_newline && pending_field_sep && !matches!(next, None | Some('}' | ',')) {
                        pass1.push(',');
                        pending_field_sep = false;
                    } else if !pass1.is_empty() && !pass1.ends_with(' ') {
                        pass1.push(' ');
                    }
                } else if !pass1.is_empty() && !pass1.ends_with(' ') {
                    pass1.push(' ');
                }
            },
            c => {
                pass1.push(c);
                if brace_depth > 0 {
                    pending_field_sep = true;
                }
                i += 1;
            },
        }
    }

    let chars2: Vec<char> = pass1.chars().collect();
    let n2 = chars2.len();
    let is_punct = |c: char| matches!(c, '{' | '}' | '(' | ')' | ',' | ':' | '<' | '>');
    let mut out = String::with_capacity(n2);
    for idx in 0..n2 {
        if chars2[idx] == ' ' {
            let prev = if idx == 0 { None } else { Some(chars2[idx - 1]) };
            let next = if idx + 1 == n2 { None } else { Some(chars2[idx + 1]) };
            if matches!(prev, Some(p) if is_punct(p)) || matches!(next, Some(p) if is_punct(p)) {
                continue;
            }
        }
        out.push(chars2[idx]);
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn procedure(digest: &str) -> ExportInfo {
        ExportInfo::Procedure(ProcedureInfo {
            digest: digest.to_string(),
            signature: None,
            calling_convention: None,
            felt_layout: None,
            abi_attributes: BTreeMap::new(),
        })
    }

    #[test]
    fn compare_exports_allows_added_procedure() {
        let previous = PackageInfo::for_test(Exports::new());
        let current = Exports::from([("new_proc".to_string(), procedure("0x01"))]);
        let current = PackageInfo::for_test(current);

        assert_eq!(compare_compatibility(Check::All, &previous, &current), Ok(()));
    }

    #[test]
    fn compare_exports_rejects_changed_procedure() {
        let previous = Exports::from([("existing_proc".to_string(), procedure("0x01"))]);
        let current = Exports::from([("existing_proc".to_string(), procedure("0x02"))]);
        let previous = PackageInfo::for_test(previous);
        let current = PackageInfo::for_test(current);

        assert!(compare_compatibility(Check::All, &previous, &current).is_err());
    }

    fn procedure_info(digest: &str, signature: &str, callconv: &str) -> ProcedureInfo {
        ProcedureInfo {
            digest: digest.to_string(),
            signature: Some(signature.to_string()),
            calling_convention: Some(callconv.to_string()),
            felt_layout: Some(FeltLayoutInfo { inputs: 1, outputs: 1 }),
            abi_attributes: BTreeMap::new(),
        }
    }

    #[test]
    fn procedure_compatibility_accepts_unchanged_root_and_interface() {
        let previous = procedure_info("0x01", "extern \"fast\" fn(u32) -> u32", "fast");
        let current = previous.clone();

        assert_eq!(
            classify_procedure_compatibility(&previous, &current),
            ProcedureCompatibility::Compatible
        );
    }

    #[test]
    fn procedure_compatibility_warns_for_interface_only_change() {
        let previous = procedure_info("0x01", "extern \"fast\" fn(u32) -> u32", "fast");
        let current = procedure_info("0x01", "extern \"fast\" fn(u64) -> u32", "fast");

        assert_eq!(
            classify_procedure_compatibility(&previous, &current),
            ProcedureCompatibility::InterfaceChanged
        );
    }

    #[test]
    fn procedure_compatibility_rejects_root_only_change() {
        let previous = procedure_info("0x01", "extern \"fast\" fn(u32) -> u32", "fast");
        let current = procedure_info("0x02", "extern \"fast\" fn(u32) -> u32", "fast");

        assert_eq!(
            classify_procedure_compatibility(&previous, &current),
            ProcedureCompatibility::ExecutableChanged { interface_changed: false }
        );
    }

    #[test]
    fn procedure_compatibility_rejects_and_reports_combined_change() {
        let previous = procedure_info("0x01", "extern \"fast\" fn(u32) -> u32", "fast");
        let current = procedure_info("0x02", "extern \"wasm\" fn(u32) -> u32", "wasm");

        assert_eq!(
            classify_procedure_compatibility(&previous, &current),
            ProcedureCompatibility::ExecutableChanged { interface_changed: true }
        );
    }

    #[test]
    fn fast_abi_compares_total_felt_widths() {
        let old = ProcedureInfo {
            digest: "0x01".to_string(),
            signature: Some("extern \"fast\" fn(u32, u32)".to_string()),
            calling_convention: Some("fast".to_string()),
            felt_layout: Some(FeltLayoutInfo { inputs: 2, outputs: 0 }),
            abi_attributes: BTreeMap::new(),
        };
        let new = ProcedureInfo {
            digest: "0x01".to_string(),
            signature: Some("extern \"fast\" fn(struct pair {u32, u32})".to_string()),
            calling_convention: Some("fast".to_string()),
            felt_layout: Some(FeltLayoutInfo { inputs: 2, outputs: 0 }),
            abi_attributes: BTreeMap::new(),
        };
        let previous = Exports::from([("p".to_string(), ExportInfo::Procedure(old))]);
        let current = Exports::from([("p".to_string(), ExportInfo::Procedure(new))]);

        assert_eq!(compare_fast_abi(&previous, &current), Ok(()));
        assert!(compare_source(&previous, &current, Diagnostic::Error, true).is_err());
    }

    #[test]
    fn release_allows_source_only_changes() {
        let old = ProcedureInfo {
            digest: "0x01".to_string(),
            signature: Some("extern \"fast\" fn(u32, u32)".to_string()),
            calling_convention: Some("fast".to_string()),
            felt_layout: Some(FeltLayoutInfo { inputs: 2, outputs: 0 }),
            abi_attributes: BTreeMap::new(),
        };
        let new = ProcedureInfo {
            digest: "0x01".to_string(),
            signature: Some("extern \"fast\" fn(struct pair {u32, u32})".to_string()),
            calling_convention: Some("fast".to_string()),
            felt_layout: Some(FeltLayoutInfo { inputs: 2, outputs: 0 }),
            abi_attributes: BTreeMap::new(),
        };
        let previous =
            PackageInfo::for_test(Exports::from([("p".to_string(), ExportInfo::Procedure(old))]));
        let current =
            PackageInfo::for_test(Exports::from([("p".to_string(), ExportInfo::Procedure(new))]));

        assert_eq!(compare_compatibility(Check::All, &previous, &current), Ok(()));
        assert!(compare_compatibility(Check::Source, &previous, &current).is_err());
    }

    #[test]
    fn package_change_requires_a_new_version() {
        let previous = PackageInfo::for_test(Exports::new());
        let mut current = previous.clone();
        current.commitments.dependency = "0x02".to_string();

        assert!(compare_package(&previous, &current).is_err());

        current.version = "0.1.1".to_string();
        assert_eq!(compare_package(&previous, &current), Ok(()));
    }

    #[test]
    fn canonicalize_strips_struct_field_labels() {
        let previous = "struct u256 {u128, u128}";
        let current = "struct u256 {lo : u128, hi : u128}";
        assert_eq!(canonicalize_type_string(previous), canonicalize_type_string(current));
    }

    #[test]
    fn canonicalize_strips_field_labels_in_signature() {
        let previous = "extern \"fast\" fn(struct u256 {u128, u128}) -> struct u256 {u128, u128}";
        let current = "extern \"fast\" fn(struct u256 {lo : u128, hi : u128}) -> struct u256 {lo : u128, hi : u128}";
        assert_eq!(canonicalize_type_string(previous), canonicalize_type_string(current));
    }

    #[test]
    fn canonicalize_preserves_field_type_changes() {
        let previous = "struct u256 {u128, u128}";
        let current = "struct u256 {u64, u64}";
        assert_ne!(canonicalize_type_string(previous), canonicalize_type_string(current));
    }

    #[test]
    fn canonicalize_preserves_field_count_changes() {
        let previous = "struct u256 {u128, u128}";
        let current = "struct u256 {u128, u128, u128}";
        assert_ne!(canonicalize_type_string(previous), canonicalize_type_string(current));
    }

    #[test]
    fn canonicalize_preserves_struct_name_changes() {
        let previous = "struct u256 {u128, u128}";
        let current = "struct u512 {u128, u128}";
        assert_ne!(canonicalize_type_string(previous), canonicalize_type_string(current));
    }

    #[test]
    fn canonicalize_preserves_repr_attributes() {
        let previous = "struct u256 {u128, u128}";
        let current = "@packed struct u256 {u128, u128}";
        assert_ne!(canonicalize_type_string(previous), canonicalize_type_string(current));
    }

    #[test]
    fn canonicalize_handles_nested_structs() {
        let previous = "struct outer {struct inner {u128}, u128}";
        let current = "struct outer {x : struct inner {lo : u128}, y : u128}";
        assert_eq!(canonicalize_type_string(previous), canonicalize_type_string(current));
    }

    #[test]
    fn canonicalize_handles_multiline_signatures_from_ci() {
        // Exact form reported by the release gate after #3269: the second struct body uses the
        // multi-line layout with newline-separated fields and no commas.
        let previous =
            "extern \"fast\" fn(struct u256 {u128, u128}, struct u256 {u128, u128}) -> i1";
        let current = "extern \"fast\" fn(struct u256 {lo : u128, hi : u128}, struct u256 {\n    lo : u128\n    hi : u128}) -> i1";
        assert_eq!(canonicalize_type_string(previous), canonicalize_type_string(current));
    }

    #[test]
    fn canonicalize_treats_label_renames_as_equal() {
        let a = "struct u256 {lo : u128, hi : u128}";
        let b = "struct u256 {low : u128, high : u128}";
        assert_eq!(canonicalize_type_string(a), canonicalize_type_string(b));
    }

    #[test]
    fn canonicalize_catches_field_count_diff_in_multiline_form() {
        let a = "struct u256 {u128, u128}";
        let b = "struct u256 {\n    lo : u128}";
        assert_ne!(canonicalize_type_string(a), canonicalize_type_string(b));
    }

    #[test]
    fn canonicalize_ignores_struct_body_padding() {
        let a = "struct u128 {u64}";
        let b = "struct u128 { u64 }";
        assert_eq!(canonicalize_type_string(a), canonicalize_type_string(b));
    }

    #[test]
    fn canonicalize_ignores_trailing_multiline_struct_body_padding() {
        let a = "struct u128 {u64}";
        let b = "struct u128 {\n    u64\n}";
        assert_eq!(canonicalize_type_string(a), canonicalize_type_string(b));
    }

    #[test]
    fn canonicalize_preserves_qualified_type_changes() {
        let a = "struct wrapper {foo::T}";
        let b = "struct wrapper {bar::T}";
        assert_ne!(canonicalize_type_string(a), canonicalize_type_string(b));
    }

    #[test]
    fn canonicalize_preserves_qualified_type_changes_after_label() {
        let a = "struct wrapper {value : foo::T}";
        let b = "struct wrapper {value : bar::T}";
        assert_ne!(canonicalize_type_string(a), canonicalize_type_string(b));
    }

    #[test]
    fn canonicalize_ignores_label_changes_on_qualified_types() {
        let a = "struct wrapper {left : foo::T}";
        let b = "struct wrapper {right : foo::T}";
        assert_eq!(canonicalize_type_string(a), canonicalize_type_string(b));
    }
}

#[cfg(test)]
impl PackageInfo {
    fn for_test(exports: Exports) -> Self {
        Self {
            name: "test".to_string(),
            version: "0.1.0".to_string(),
            exports,
            commitments: PackageCommitments {
                interface: "0x01".to_string(),
                mast_forest: "0x01".to_string(),
                code: "0x01".to_string(),
                dependency: "0x01".to_string(),
            },
        }
    }
}

mod current {
    use miden_assembly_current::{Assembler, ProjectTargetSelector};
    use miden_assembly_syntax_current::prettier::PrettyPrint;
    use miden_mast_package_current::{Package, PackageExport};
    use miden_package_registry_current::InMemoryPackageRegistry;

    use super::*;

    pub fn collect_package(input: &Path) -> Result<PackageInfo, String> {
        let mut store = InMemoryPackageRegistry::default();
        let mut project =
            Assembler::default().for_project_at_path(input, &mut store).map_err(|err| {
                format!("current: failed to load project '{}': {err}", input.display())
            })?;
        let package =
            project.assemble(ProjectTargetSelector::Library, "release").map_err(|err| {
                format!("current: failed to assemble project '{}': {err}", input.display())
            })?;

        collect_package_info(package.as_ref())
    }

    fn collect_package_info(package: &Package) -> Result<PackageInfo, String> {
        let exports = package
            .manifest
            .exports()
            .filter_map(|export| match export {
                PackageExport::Procedure(procedure) => Some((
                    procedure.path.to_string(),
                    ExportInfo::Procedure(ProcedureInfo {
                        digest: procedure.digest.to_string(),
                        signature: procedure.signature.as_ref().map(PrettyPrint::to_pretty_string),
                        calling_convention: procedure
                            .signature
                            .as_ref()
                            .map(|signature| signature.abi.to_string()),
                        felt_layout: procedure.signature.as_ref().map(|signature| FeltLayoutInfo {
                            inputs: signature.params.iter().map(|ty| ty.size_in_felts()).sum(),
                            outputs: signature
                                .results
                                .iter()
                                .map(|ty| ty.size_in_felts())
                                .sum(),
                        }),
                        abi_attributes: procedure
                            .attributes
                            .iter()
                            .filter(|attr| is_abi_attribute(attr.name()))
                            .map(|attr| (attr.name().to_string(), attr.to_string()))
                            .collect(),
                    }),
                )),
                PackageExport::Type(ty) => Some((
                    ty.path.to_string(),
                    ExportInfo::Type(TypeInfo { ty: ty.ty.to_pretty_string() }),
                )),
                PackageExport::Constant(_) => None,
            })
            .collect();
        Ok(PackageInfo {
            name: package.name.to_string(),
            version: package.version.to_string(),
            exports,
            commitments: PackageCommitments {
                interface: package
                    .interface_commitment()
                    .map_err(|err| err.to_string())?
                    .to_string(),
                mast_forest: package.mast_forest_commitment().to_string(),
                code: package.code_commitment().to_string(),
                dependency: package.dependency_commitment().to_string(),
            },
        })
    }
}

mod previous {
    use miden_assembly_previous::{Assembler, ProjectTargetSelector};
    use miden_assembly_syntax_previous::prettier::PrettyPrint;
    use miden_mast_package_previous::{Package, PackageExport};
    use miden_package_registry_previous::InMemoryPackageRegistry;

    use super::*;

    pub fn collect_package(input: &Path) -> Result<PackageInfo, String> {
        let mut store = InMemoryPackageRegistry::default();
        let mut project =
            Assembler::default().for_project_at_path(input, &mut store).map_err(|err| {
                format!("previous: failed to load project '{}': {err}", input.display())
            })?;
        let package =
            project.assemble(ProjectTargetSelector::Library, "release").map_err(|err| {
                format!("previous: failed to assemble project '{}': {err}", input.display())
            })?;

        collect_package_info(package.as_ref())
    }

    fn collect_package_info(package: &Package) -> Result<PackageInfo, String> {
        let exports = package
            .manifest
            .exports()
            .filter_map(|export| match export {
                PackageExport::Procedure(procedure) => Some((
                    procedure.path.to_string(),
                    ExportInfo::Procedure(ProcedureInfo {
                        digest: procedure.digest.to_string(),
                        signature: procedure.signature.as_ref().map(PrettyPrint::to_pretty_string),
                        calling_convention: procedure
                            .signature
                            .as_ref()
                            .map(|signature| signature.abi.to_string()),
                        felt_layout: procedure.signature.as_ref().map(|signature| FeltLayoutInfo {
                            inputs: signature.params.iter().map(|ty| ty.size_in_felts()).sum(),
                            outputs: signature
                                .results
                                .iter()
                                .map(|ty| ty.size_in_felts())
                                .sum(),
                        }),
                        abi_attributes: procedure
                            .attributes
                            .iter()
                            .filter(|attr| is_abi_attribute(attr.name()))
                            .map(|attr| (attr.name().to_string(), attr.to_string()))
                            .collect(),
                    }),
                )),
                PackageExport::Type(ty) => Some((
                    ty.path.to_string(),
                    ExportInfo::Type(TypeInfo { ty: ty.ty.to_pretty_string() }),
                )),
                PackageExport::Constant(_) => None,
            })
            .collect();
        Ok(PackageInfo {
            name: package.name.to_string(),
            version: package.version.to_string(),
            exports,
            commitments: PackageCommitments {
                interface: package
                    .interface_commitment()
                    .map_err(|err| err.to_string())?
                    .to_string(),
                mast_forest: package.mast_forest_commitment().to_string(),
                code: package.code_commitment().to_string(),
                dependency: package.dependency_commitment().to_string(),
            },
        })
    }
}
