#!/usr/bin/env -S cargo +nightly -Zscript

---
[dependencies]
miden-assembly = { path = "../crates/assembly" }
miden-package-registry = { path = "../crates/package-registry" }
---

use std::{env, path::PathBuf};

use miden_assembly::{Assembler, ProjectTargetSelector, Report, diagnostics::IntoDiagnostic};
use miden_package_registry::InMemoryPackageRegistry;

fn main() -> Result<(), Report> {
    // We obtain the workspace root like so becaue CARGO_TARGET_DIR is not set
    // for cargo scripts.
    // This does mean that this script is only intended to be run from the
    // project's rootk.
    let workspace_root = env::current_dir().expect("could not read PWD");
    let core_lib_project_dir = workspace_root.join("crates/lib/core/asm");

    let target_dir = workspace_root.join("target");
    let packages_dir = target_dir.join("packages");
    std::fs::create_dir_all(&packages_dir)
        .unwrap_or_else(|_| panic!("could not create packages/ directory in {}", packages_dir.display()));

    let assembler = Assembler::default();
    let mut registry = InMemoryPackageRegistry::default();
    let mut project_assembler = assembler
        .for_project_at_path(core_lib_project_dir.join("miden-project.toml"), &mut registry)?;
    let package = project_assembler.assemble(ProjectTargetSelector::Library, "release")?;

    package.write_masp_file(&packages_dir).into_diagnostic()?;

    println!("wrote miden-core.masp to {}", packages_dir.display());
    Ok(())
}
