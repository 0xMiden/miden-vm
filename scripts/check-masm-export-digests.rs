#!/usr/bin/env -S cargo +nightly -Zscript
---cargo
[package]
edition = "2024"

[dependencies]
miden-assembly-current = { package = "miden-assembly", path = "../crates/assembly" }
miden-assembly-syntax-current = { package = "miden-assembly-syntax", path = "../crates/assembly-syntax" }
miden-mast-package-current = { package = "miden-mast-package", path = "../crates/mast-package" }
miden-package-registry-current = { package = "miden-package-registry", path = "../crates/package-registry", features = ["resolver"] }

miden-assembly-previous = { package = "miden-assembly", git = "https://github.com/0xMiden/miden-vm", tag = "v0.22.4" }
miden-assembly-syntax-previous = { package = "miden-assembly-syntax", git = "https://github.com/0xMiden/miden-vm", tag = "v0.22.4" }
miden-mast-package-previous = { package = "miden-mast-package", git = "https://github.com/0xMiden/miden-vm", tag = "v0.22.4" }
miden-package-registry-previous = { package = "miden-package-registry", git = "https://github.com/0xMiden/miden-vm", tag = "v0.22.4", features = ["resolver"] }
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
            if previous.ty == current.ty {
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

    if previous.signature.is_some() && previous.signature != current.signature {
        eprintln!(
            "::error::export signature changed for {name}: previous={}, current={}",
            previous.signature.as_deref().unwrap_or("None"),
            current.signature.as_deref().unwrap_or("None"),
        );
        changed = true;
    }

    // Adding ABI metadata is non-breaking; removing or changing previously published ABI metadata is not.
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

mod current {
    use super::*;
    use miden_assembly_current::{Assembler, ProjectTargetSelector};
    use miden_assembly_syntax_current::prettier::PrettyPrint;
    use miden_mast_package_current::{Package, PackageExport};
    use miden_package_registry_current::InMemoryPackageRegistry;

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
    use super::*;
    use miden_assembly_previous::{Assembler, ProjectTargetSelector};
    use miden_assembly_syntax_previous::prettier::PrettyPrint;
    use miden_mast_package_previous::{Package, PackageExport};
    use miden_package_registry_previous::InMemoryPackageRegistry;

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
