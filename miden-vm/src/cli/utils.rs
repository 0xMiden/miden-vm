use std::{fs, path::Path, sync::Arc};

use miden_assembly::{
    Assembler, DefaultSourceManager, KernelLibrary,
    diagnostics::{IntoDiagnostic, Report, WrapErr},
};
use miden_core_lib::CoreLibrary;
use miden_mast_package::{MastArtifact, Package};
use miden_prover::utils::Deserializable;

use crate::cli::data::{Libraries, ProgramFile};

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
    _debug_on: bool,
    kernel_file: Option<&Path>,
) -> Result<(miden_core::Program, Arc<DefaultSourceManager>), Report> {
    // Assembler debug mode is always enabled (issue #1821)
    let program_file = ProgramFile::read(path)?;
    let source_manager = program_file.source_manager().clone();

    // If kernel is provided, compile it and use it when compiling the program
    let program = if let Some(kernel_path) = kernel_file {
        // Determine file type based on extension
        let ext = kernel_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

        // Load kernel from .masp package or compile from .masm source
        let kernel_lib = match ext.as_str() {
            "masp" => {
                // Load kernel from package file
                let bytes = fs::read(kernel_path).into_diagnostic().wrap_err_with(|| {
                    format!("Failed to read kernel package `{}`", kernel_path.display())
                })?;
                let package =
                    Package::read_from_bytes(&bytes).into_diagnostic().wrap_err_with(|| {
                        format!("Failed to deserialize kernel package `{}`", kernel_path.display())
                    })?;

                match package.into_mast_artifact() {
                    MastArtifact::Library(lib) => {
                        let library = Arc::try_unwrap(lib).unwrap_or_else(|arc| (*arc).clone());
                        KernelLibrary::try_from(library).wrap_err_with(|| {
                            format!(
                                "The package `{}` is not a valid kernel package",
                                kernel_path.display()
                            )
                        })?
                    },
                    MastArtifact::Executable(_) => {
                        return Err(Report::msg(format!(
                            "Kernel package `{}` contains a program, not a kernel library",
                            kernel_path.display()
                        )));
                    },
                }
            },
            "masm" => {
                // Compile kernel from assembly source
                // Assembler debug mode is always enabled (issue #1821)
                Assembler::default().assemble_kernel(kernel_path).wrap_err_with(|| {
                    format!("Failed to compile kernel from `{}`", kernel_path.display())
                })?
            },
            _ => {
                return Err(Report::msg(format!(
                    "Kernel file `{}` must have a .masm or .masp extension",
                    kernel_path.display()
                )));
            },
        };

        // Create assembler with kernel
        // Assembler debug mode is always enabled (issue #1821)
        let mut assembler = Assembler::with_kernel(source_manager.clone(), kernel_lib);

        // Link standard library
        assembler
            .link_dynamic_library(CoreLibrary::default())
            .wrap_err("Failed to load stdlib")?;

        // Link user libraries
        for library in &libraries.libraries {
            assembler.link_dynamic_library(library).wrap_err("Failed to load libraries")?;
        }

        // Compile the program
        assembler
            .assemble_program(program_file.ast())
            .wrap_err("Failed to compile program")?
    } else {
        // No kernel, use the standard compilation path
        program_file.compile(&libraries.libraries)?
    };

    Ok((program, source_manager))
}
