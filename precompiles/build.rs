use std::{
    env,
    path::{Path, PathBuf},
};

use miden_assembly::{Assembler, ProjectTargetSelector, Report, diagnostics::IntoDiagnostic};

// CONSTANTS
// ================================================================================================

const ASM_DIR_PATH: &str = "asm";
const ASSETS_DIR_PATH: &str = "assets";

// PRE-PROCESSING
// ================================================================================================

/// Assembles the `./asm` MASM project into `[OUT_DIR]/assets/miden-precompiles.masp`.
fn main() -> Result<(), Report> {
    use miden_assembly::diagnostics::reporting::ReportHandlerOpts;

    // Re-assemble the package whenever the MASM sources or the assembler change. The assembler path
    // is relative to the package root (precompiles/), so `../crates/assembly/src` reaches it.
    println!("cargo:rerun-if-changed=asm");
    println!("cargo:rerun-if-changed=../crates/assembly/src");

    miden_assembly::diagnostics::reporting::set_hook(Box::new(|_| {
        Box::new(ReportHandlerOpts::new().build())
    }))
    .unwrap();
    miden_assembly::diagnostics::reporting::set_panic_hook();

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let asm_dir = Path::new(manifest_dir).join(ASM_DIR_PATH);

    let assembler = Assembler::default();
    let mut registry = miden_package_registry::InMemoryPackageRegistry::default();
    let mut project_assembler =
        assembler.for_project_at_path(asm_dir.join("miden-project.toml"), &mut registry)?;

    let package = project_assembler.assemble(ProjectTargetSelector::Library, "release")?;

    let build_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    package.write_masp_file(build_dir.join(ASSETS_DIR_PATH)).into_diagnostic()?;

    Ok(())
}
