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
miden-assembly-previous = { package = "miden-assembly", git = "https://github.com/0xMiden/miden-vm", tag = "v0.23.0" }
miden-assembly-syntax-previous = { package = "miden-assembly-syntax", git = "https://github.com/0xMiden/miden-vm", tag = "v0.23.0" }
miden-mast-package-previous = { package = "miden-mast-package", git = "https://github.com/0xMiden/miden-vm", tag = "v0.23.0" }
miden-package-registry-previous = { package = "miden-package-registry", git = "https://github.com/0xMiden/miden-vm", tag = "v0.23.0", features = ["resolver"] }
---

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::{Path, PathBuf},
    process,
};

type Exports = BTreeMap<String, ExportInfo>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExportInfo {
    Procedure(ProcedureInfo),
    Type(TypeInfo),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcedureInfo {
    digest: String,
    signature: Option<String>,
    abi_attributes: BTreeMap<String, String>,
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
        let Self { digest, signature, abi_attributes } = self;
        format!(
            "procedure digest={digest}, signature={}, abi_attributes={}",
            signature.as_deref().unwrap_or("None"),
            format_attributes(abi_attributes),
        )
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
    let previous_input = args.next().map(PathBuf::from).ok_or_else(usage)?;
    let current_input = args.next().map(PathBuf::from).ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }

    let previous = previous::collect_exports(&previous_input)?;
    let current = current::collect_exports(&current_input)?;
    compare_exports(previous, current)
}

fn usage() -> String {
    "usage: check-masm-export-digests.rs <previous-miden-project.toml|previous-project-dir> <current-miden-project.toml|current-project-dir>".to_string()
}

fn compare_exports(previous: Exports, current: Exports) -> Result<(), String> {
    let mut status = Ok(());
    let export_names = previous.keys().chain(current.keys()).cloned().collect::<BTreeSet<_>>();

    for name in export_names {
        match (previous.get(&name), current.get(&name)) {
            (Some(previous_export), Some(current_export)) if previous_export == current_export => {
                println!("{name} {}", current_export.describe());
            },
            (Some(previous_export), Some(current_export)) => {
                if compare_export(&name, previous_export, current_export) {
                    status = Err("exports changed".to_string());
                }
            },
            (Some(previous_export), None) => {
                eprintln!(
                    "::error::export removed: {name} previous={}",
                    previous_export.describe()
                );
                status = Err("procedure exports changed".to_string());
            },
            (None, Some(current_export)) => match current_export {
                ExportInfo::Procedure(_) => {
                    eprintln!(
                        "::error::export added: {name} current={}",
                        current_export.describe()
                    );
                    status = Err("procedure exports changed".to_string());
                },
                ExportInfo::Type(_) => {
                    println!("{name} {}", current_export.describe());
                },
            },
            (None, None) => unreachable!("name came from at least one side"),
        }
    }

    status
}

fn compare_export(name: &str, previous: &ExportInfo, current: &ExportInfo) -> bool {
    match (previous, current) {
        (ExportInfo::Procedure(previous), ExportInfo::Procedure(current)) => {
            compare_procedure(name, previous, current)
        },
        (ExportInfo::Type(previous), ExportInfo::Type(current)) => {
            if canonicalize_type_string(&previous.ty) == canonicalize_type_string(&current.ty) {
                false
            } else {
                eprintln!(
                    "::error::exported type changed for {name}: previous={}, current={}",
                    previous.ty, current.ty,
                );
                true
            }
        },
        _ => {
            eprintln!(
                "::error::export kind changed for {name}: previous={}, current={}",
                previous.describe(),
                current.describe(),
            );
            true
        },
    }
}

fn compare_procedure(name: &str, previous: &ProcedureInfo, current: &ProcedureInfo) -> bool {
    let mut changed = false;

    if previous.digest != current.digest {
        eprintln!(
            "::error::export digest changed for {name}: previous={}, current={}",
            previous.digest, current.digest,
        );
        changed = true;
    }

    if previous.signature.is_some()
        && canonicalize_type_string(previous.signature.as_deref().unwrap_or(""))
            != canonicalize_type_string(current.signature.as_deref().unwrap_or(""))
    {
        eprintln!(
            "::error::export signature changed for {name}: previous={}, current={}",
            previous.signature.as_deref().unwrap_or("None"),
            current.signature.as_deref().unwrap_or("None"),
        );
        changed = true;
    }

    // Adding ABI metadata is non-breaking; removing or changing previously published ABI metadata
    // is not.
    for (attr, previous_value) in &previous.abi_attributes {
        let current_value = current.abi_attributes.get(attr).map(String::as_str).unwrap_or("None");
        if previous_value != current_value {
            eprintln!(
                "::error::export ABI attribute changed for {name}: {attr} previous={previous_value}, current={current_value}",
            );
            changed = true;
        }
    }

    changed
}

fn is_abi_attribute(name: &str) -> bool {
    matches!(name, "auth_script" | "callconv")
}

/// Compare a pretty-printed signature or type string ignoring struct field labels.
///
/// Struct field names are display-only metadata in Miden Assembly: they do not affect the
/// wire/memory layout, procedure MAST roots, or operand-stack encoding of a type. Changes that
/// only add, remove, or rename field labels are therefore non-breaking, even though the resolved
/// `StructType` derives `PartialEq`/`Hash` over the (now populated) name field. This helper strips
/// the `name :` prefix from each struct field so such deltas compare equal.
///
/// It deliberately preserves everything that *is* part of the ABI: field types, field count, field
/// order, struct names, `repr` attributes (`@bigendian`, `@packed`, etc.), and all non-struct
/// syntax. Only the leading `ident :` of a struct field is removed.
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
                    if has_newline
                        && pending_field_sep
                        && !matches!(next, None | Some('}' | ','))
                    {
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

mod current {
    use miden_assembly_current::{Assembler, ProjectTargetSelector};
    use miden_assembly_syntax_current::prettier::PrettyPrint;
    use miden_mast_package_current::{Package, PackageExport};
    use miden_package_registry_current::InMemoryPackageRegistry;

    use super::*;

    pub fn collect_exports(input: &Path) -> Result<Exports, String> {
        let mut store = InMemoryPackageRegistry::default();
        let mut project =
            Assembler::default().for_project_at_path(input, &mut store).map_err(|err| {
                format!("current: failed to load project '{}': {err}", input.display())
            })?;
        let package =
            project.assemble(ProjectTargetSelector::Library, "release").map_err(|err| {
                format!("current: failed to assemble project '{}': {err}", input.display())
            })?;

        collect_package_exports(package.as_ref())
    }

    fn collect_package_exports(package: &Package) -> Result<Exports, String> {
        Ok(package
            .manifest
            .exports()
            .filter_map(|export| match export {
                PackageExport::Procedure(procedure) => Some((
                    procedure.path.to_string(),
                    ExportInfo::Procedure(ProcedureInfo {
                        digest: procedure.digest.to_string(),
                        signature: procedure.signature.as_ref().map(PrettyPrint::to_pretty_string),
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
            .collect())
    }
}

mod previous {
    use miden_assembly_previous::{Assembler, ProjectTargetSelector};
    use miden_assembly_syntax_previous::prettier::PrettyPrint;
    use miden_mast_package_previous::{Package, PackageExport};
    use miden_package_registry_previous::InMemoryPackageRegistry;

    use super::*;

    pub fn collect_exports(input: &Path) -> Result<Exports, String> {
        let mut store = InMemoryPackageRegistry::default();
        let mut project =
            Assembler::default().for_project_at_path(input, &mut store).map_err(|err| {
                format!("previous: failed to load project '{}': {err}", input.display())
            })?;
        let package =
            project.assemble(ProjectTargetSelector::Library, "release").map_err(|err| {
                format!("previous: failed to assemble project '{}': {err}", input.display())
            })?;

        collect_package_exports(package.as_ref())
    }

    fn collect_package_exports(package: &Package) -> Result<Exports, String> {
        Ok(package
            .manifest
            .exports()
            .filter_map(|export| match export {
                PackageExport::Procedure(procedure) => Some((
                    procedure.path.to_string(),
                    ExportInfo::Procedure(ProcedureInfo {
                        digest: procedure.digest.to_string(),
                        signature: procedure.signature.as_ref().map(PrettyPrint::to_pretty_string),
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
            .collect())
    }
}
