use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

use miden_assembly::{Assembler, ProjectTargetSelector, Report, diagnostics::IntoDiagnostic};

// CONSTANTS
// ================================================================================================

const ASM_DIR_PATH: &str = "asm";
const ASSETS_DIR_PATH: &str = "assets";
const GENERATED_ASM_DIR_PATH: &str = "asm";
const GENERATED_MATH_FILES: &[&str] = &[
    "math/curve/ed25519_sw.masm",
    "math/curve/secp256k1.masm",
    "math/curve/secp256r1.masm",
    "math/field/ed25519_base.masm",
    "math/field/ed25519_scalar.masm",
    "math/field/k1_base.masm",
    "math/field/k1_scalar.masm",
    "math/field/r1_base.masm",
    "math/field/r1_scalar.masm",
    "math/u256.masm",
];

// PRE-PROCESSING
// ================================================================================================

/// Assembles the generated MASM project into `[OUT_DIR]/assets/miden-precompiles.masp`.
fn main() -> Result<(), Report> {
    use miden_assembly::diagnostics::reporting::ReportHandlerOpts;

    // Re-assemble the package whenever handwritten MASM, generator inputs, or the assembler change.
    // The assembler path is relative to the package root (precompiles/), so
    // `../crates/assembly/src` reaches it.
    println!("cargo:rerun-if-changed=asm");
    println!("cargo:rerun-if-changed=codegen");
    println!("cargo:rerun-if-changed=../crates/assembly/src");

    miden_assembly::diagnostics::reporting::set_hook(Box::new(|_| {
        Box::new(ReportHandlerOpts::new().build())
    }))
    .unwrap();
    miden_assembly::diagnostics::reporting::set_panic_hook();

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let source_asm_dir = Path::new(manifest_dir).join(ASM_DIR_PATH);
    let build_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let generated_asm_dir = build_dir.join(GENERATED_ASM_DIR_PATH);

    prepare_generated_asm_dir(&source_asm_dir, &generated_asm_dir)?;
    miden_precompiles_codegen::masm::write_math_masm(&generated_asm_dir).map_err(Report::msg)?;

    let package = {
        let _current_dir = CurrentDirGuard::push(&build_dir)?;
        let assembler = Assembler::default();
        let mut registry = miden_package_registry::InMemoryPackageRegistry::default();
        let mut project_assembler = assembler
            .for_project_at_path(generated_asm_dir.join("miden-project.toml"), &mut registry)?;
        project_assembler.assemble(ProjectTargetSelector::Library, "release")?
    };

    package.write_masp_file(build_dir.join(ASSETS_DIR_PATH)).into_diagnostic()?;

    Ok(())
}

fn prepare_generated_asm_dir(
    source_asm_dir: &Path,
    generated_asm_dir: &Path,
) -> Result<(), Report> {
    if generated_asm_dir.exists() {
        fs::remove_dir_all(generated_asm_dir).into_diagnostic()?;
    }

    copy_handwritten_asm(source_asm_dir, generated_asm_dir, source_asm_dir).into_diagnostic()
}

fn copy_handwritten_asm(
    source_dir: &Path,
    destination_dir: &Path,
    source_asm_dir: &Path,
) -> io::Result<()> {
    fs::create_dir_all(destination_dir)?;

    for entry in fs::read_dir(source_dir)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination_dir.join(entry.file_name());
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            copy_handwritten_asm(&source_path, &destination_path, source_asm_dir)?;
        } else if !is_generated_math_file(&source_path, source_asm_dir) {
            fs::copy(&source_path, destination_path)?;
        }
    }

    Ok(())
}

fn is_generated_math_file(path: &Path, source_asm_dir: &Path) -> bool {
    path.strip_prefix(source_asm_dir)
        .ok()
        .and_then(Path::to_str)
        .is_some_and(|relative_path| GENERATED_MATH_FILES.contains(&relative_path))
}

struct CurrentDirGuard {
    previous: PathBuf,
}

impl CurrentDirGuard {
    fn push(path: &Path) -> Result<Self, Report> {
        let previous = env::current_dir().into_diagnostic()?;
        env::set_current_dir(path).into_diagnostic()?;
        Ok(Self { previous })
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        let _ = env::set_current_dir(&self.previous);
    }
}
