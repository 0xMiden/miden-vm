use std::{fs, path::Path, sync::Arc};

use miden_assembly::{
    DefaultSourceManager,
    diagnostics::{IntoDiagnostic, Report, WrapErr},
};
use miden_mast_package::{MastArtifact, Package};
use miden_prover::utils::Deserializable;

use crate::cli::data::{Debug, Libraries, ProgramFile};

/// Returns a `Program` type from a `.masp` package file.
pub fn get_masp_program(path: &Path) -> Result<miden_core::Program, Report> {
    let bytes = fs::read(path).into_diagnostic().wrap_err("Failed to read package file")?;
    // Use `read_from_bytes` provided by the Deserializable trait.
    let package = Package::read_from_bytes(&bytes)
        .into_diagnostic()
        .wrap_err("Failed to deserialize package")?;
    let program_arc = match package.into_mast_artifact() {
        MastArtifact::Executable(prog_arc) => prog_arc,
        _ => return Err(Report::msg("The provided package is not a program package.")),
    };
    // Unwrap the Arc. If multiple references exist, clone the inner program.
    let program = Arc::try_unwrap(program_arc).unwrap_or_else(|arc| (*arc).clone());
    Ok(program)
}

/// Returns a `Program` type from a `.masm` assembly file.
pub fn get_masm_program(
    path: &Path,
    libraries: &Libraries,
    debug_on: bool,
) -> Result<(miden_core::Program, Arc<DefaultSourceManager>), Report> {
    let debug_mode = if debug_on { Debug::On } else { Debug::Off };
    let program_file = ProgramFile::read(path)?;
    let program = program_file.compile(debug_mode, &libraries.libraries)?;

    Ok((program, program_file.source_manager().clone()))
}
