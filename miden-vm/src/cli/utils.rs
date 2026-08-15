use std::{fs, path::Path, sync::Arc};

use miden_assembly::{
    Assembler, Linkage, SourceMap,
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

/// The artifacts produced while compiling a Miden Assembly program.
///
/// The kernel package is retained separately because kernel procedures are dynamically resolved by
/// the host at execution time. The source map contains the complete compilation session, including
/// sources discovered while assembling a source kernel and the program itself.
pub(crate) struct MasmProgram {
    pub program: Program,
    pub package_debug_info: Option<PackageDebugInfo>,
    pub entrypoint_source_node: Option<DebugSourceNodeId>,
    pub sources: Arc<SourceMap>,
    pub kernel: Option<Arc<Package>>,
}

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
) -> Result<MasmProgram, Report> {
    // Assembler debug mode is always enabled (issue #1821)
    let program_file = ProgramFile::read(path).into_result()?;
    let mut sources = program_file.sources().clone();

    // If kernel is provided, compile it and use it when compiling the program
    let kernel_lib = if let Some(kernel_path) = kernel_file {
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
                let mut kernel_assembler = Assembler::with_sources(sources);
                let kernel = kernel_assembler
                    .assemble_kernel_from_root_in_place("kernel", kernel_path)
                    .into_result()
                    .map(Arc::from)?;
                sources = kernel_assembler.sources().clone();
                kernel
            },
            _ => {
                return Err(Report::msg(format!(
                    "Kernel file `{}` must have a .masm or .masp extension",
                    kernel_path.display()
                )));
            },
        };
        Some(kernel_lib)
    } else {
        None
    };

    // Create the final program assembler from the complete source session. For a source kernel,
    // this includes every file discovered while assembling the kernel tree.
    let mut assembler = match kernel_lib.as_ref() {
        Some(kernel_lib) => Assembler::with_sources_and_kernel(sources, Arc::clone(kernel_lib))?,
        None => Assembler::with_sources(sources),
    };

    assembler
        .link_package(CoreLibrary::default().package(), Linkage::Dynamic)
        .wrap_err("Failed to load stdlib")?;

    for library in libraries.libraries.iter().cloned() {
        assembler
            .link_package(library, Linkage::Dynamic)
            .wrap_err("Failed to load libraries")?;
    }

    let package = assembler
        .assemble_program_in_place("program", program_file.ast().clone())
        .into_result()?;
    let sources = Arc::new(assembler.sources().clone());
    let debug_info = package
        .debug_info()
        .into_diagnostic()
        .wrap_err("Failed to read program debug info")?;
    let entrypoint_source_node = package.entrypoint_source_node();
    let program = package.unwrap_program();

    Ok(MasmProgram {
        program,
        package_debug_info: debug_info,
        entrypoint_source_node,
        sources,
        kernel: kernel_lib,
    })
}
