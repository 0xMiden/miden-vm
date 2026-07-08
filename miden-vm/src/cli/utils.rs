use std::{fs, path::Path, sync::Arc};

use miden_assembly::{
    Assembler, DefaultSourceManager, Linkage,
    diagnostics::{IntoDiagnostic, Report, WrapErr},
};
use miden_core::program::Program;
use miden_core_lib::CoreLibrary;
use miden_mast_package::{
    Package,
    debug_info::{DebugSourceNodeId, PackageDebugInfo},
};
use miden_prover::serde::Deserializable;

use crate::cli::data::{Libraries, ProgramFile};

/// Returns a `Program` type from a `.masp` package file.
pub fn get_masp_program(path: &Path) -> Result<Program, Report> {
    let package = Package::deserialize_from_file(path)
        .into_diagnostic()
        .wrap_err("Failed to deserialize package")?;
    package.try_into_program()
}

/// Returns a `Program` type from a `.masm` assembly file.
pub fn get_masm_program(
    path: &Path,
    libraries: &Libraries,
    kernel_file: Option<&Path>,
) -> Result<
    (
        Program,
        Option<PackageDebugInfo>,
        Option<DebugSourceNodeId>,
        Arc<DefaultSourceManager>,
    ),
    Report,
> {
    // Assembler debug mode is always enabled (issue #1821)
    let program_file = ProgramFile::read(path)?;
    let source_manager = program_file.source_manager().clone();

    // If kernel is provided, compile it and use it when compiling the program
    let package = if let Some(kernel_path) = kernel_file {
        // Determine file type based on extension
        let ext = kernel_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

        // Load kernel from .masp package or compile from .masm source
        let kernel_lib = match ext.as_str() {
            "masp" => {
                // Load kernel from package file
                let bytes = fs::read(kernel_path).into_diagnostic().wrap_err_with(|| {
                    format!("Failed to read kernel package `{}`", kernel_path.display())
                })?;
                Package::read_from_bytes(&bytes)
                    .map(Arc::from)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!("Failed to deserialize kernel package `{}`", kernel_path.display())
                    })?
            },
            "masm" => {
                // Compile kernel from assembly source
                // Assembler debug mode is always enabled (issue #1821)
                Assembler::new(source_manager.clone())
                    .assemble_kernel_from_root("kernel", kernel_path)
                    .map(Arc::from)
                    .wrap_err_with(|| {
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
        let mut assembler = Assembler::with_kernel(source_manager.clone(), kernel_lib)?;

        // Link standard library
        assembler
            .link_package(CoreLibrary::default().package(), Linkage::Dynamic)
            .wrap_err("Failed to load stdlib")?;

        // Link user libraries
        for library in libraries.libraries.iter().cloned() {
            assembler
                .link_package(library, Linkage::Dynamic)
                .wrap_err("Failed to load libraries")?;
        }

        // Compile the program
        assembler
            .assemble_program("program", program_file.ast().clone())
            .wrap_err("Failed to compile program")?
    } else {
        // No kernel, use the standard compilation path
        program_file.compile_package(libraries.libraries.iter().cloned())?
    };
    let debug_info = package
        .debug_info()
        .into_diagnostic()
        .wrap_err("Failed to read program debug info")?;
    let entrypoint_source_node = package.entrypoint_source_node();
    let program = package.unwrap_program();

    Ok((program, debug_info, entrypoint_source_node, source_manager))
}
