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
struct ExportInfo {
    digest: String,
    signature: String,
    attributes: String,
}

impl ExportInfo {
    fn describe(&self) -> String {
        let Self { digest, signature, attributes } = self;
        format!("digest={digest}, signature={signature}, attributes={attributes}")
    }
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
                if previous_export.digest != current_export.digest {
                    eprintln!(
                        "::error::export digest changed for {name}: previous={}, current={}",
                        previous_export.digest, current_export.digest,
                    );
                }
                if previous_export.signature != current_export.signature {
                    eprintln!(
                        "::error::export signature changed for {name}: previous={}, current={}",
                        previous_export.signature, current_export.signature,
                    );
                }
                if previous_export.attributes != current_export.attributes {
                    eprintln!(
                        "::error::export attributes changed for {name}: previous={}, current={}",
                        previous_export.attributes, current_export.attributes,
                    );
                }
                status = Err("procedure exports changed".to_string());
            },
            (Some(previous_export), None) => {
                eprintln!(
                    "::error::export removed: {name} previous={}",
                    previous_export.describe()
                );
                status = Err("procedure exports changed".to_string());
            },
            (None, Some(current_export)) => {
                eprintln!("::error::export added: {name} current={}", current_export.describe());
                status = Err("procedure exports changed".to_string());
            },
            (None, None) => unreachable!("name came from at least one side"),
        }
    }

    status
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
                    ExportInfo {
                        digest: procedure.digest.to_string(),
                        signature: procedure
                            .signature
                            .as_ref()
                            .map(PrettyPrint::to_pretty_string)
                            .unwrap_or_else(|| "None".to_string()),
                        attributes: procedure
                            .attributes
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(" "),
                    },
                )),
                PackageExport::Constant(_) | PackageExport::Type(_) => None,
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
                    ExportInfo {
                        digest: procedure.digest.to_string(),
                        signature: procedure
                            .signature
                            .as_ref()
                            .map(PrettyPrint::to_pretty_string)
                            .unwrap_or_else(|| "None".to_string()),
                        attributes: procedure
                            .attributes
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(" "),
                    },
                )),
                PackageExport::Constant(_) | PackageExport::Type(_) => None,
            })
            .collect())
    }
}
