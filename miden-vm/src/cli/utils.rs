use std::{fs, path::Path, sync::Arc};

use miden_assembly::{
    Assembler, DefaultSourceManager,
    diagnostics::{IntoDiagnostic, Report, WrapErr},
};
use miden_debug_types::{SourceLanguage, SourceManager};
use miden_stdlib::StdLibrary;
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

/// Returns a `Program` type from a `.masm` assembly file with a kernel.
pub fn get_masm_program_with_kernel(
    path: &Path,
    libraries: &Libraries,
    debug_on: bool,
    kernel_path: &Path,
) -> Result<(miden_core::Program, Arc<DefaultSourceManager>), Report> {
    let debug_mode = if debug_on { Debug::On } else { Debug::Off };
    let source_manager = Arc::new(DefaultSourceManager::default());
    
    // Load kernel file into source manager (same approach as in tests)
    let kernel_source = source_manager.load(
        SourceLanguage::Masm,
        kernel_path.to_string_lossy().to_string().into(),
        fs::read_to_string(kernel_path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to read kernel file `{}`", kernel_path.display()))?,
    );
    
    // Compile kernel
    println!("Compiling kernel from: {}", kernel_path.display());
    let kernel_lib = Assembler::new(source_manager.clone())
        .assemble_kernel(kernel_source)
        .wrap_err_with(|| format!("Failed to compile kernel from `{}`", kernel_path.display()))?;
    println!("Kernel compiled successfully!");
    
    // Create assembler with kernel
    let mut assembler = Assembler::with_kernel(source_manager.clone(), kernel_lib)
        .with_debug_mode(debug_mode.is_on());
    
    // Load stdlib
    assembler
        .link_dynamic_library(StdLibrary::default())
        .wrap_err("Failed to load stdlib")?;
    
    // Load libraries
    for library in &libraries.libraries {
        assembler.link_dynamic_library(library).wrap_err("Failed to load libraries")?;
    }
    
    // Load program file into source manager (same approach as in tests)
    let program_source = source_manager.load(
        SourceLanguage::Masm,
        path.to_string_lossy().to_string().into(),
        fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to read program file `{}`", path.display()))?,
    );
    
    // Compile program
    println!("Compiling program from: {}", path.display());
    let program = assembler
        .assemble_program(program_source)
        .wrap_err("Failed to compile program")?;
    println!("Program compiled successfully!");

    Ok((program, source_manager))
}

/// Returns a `KernelLibrary` from a `.masm` kernel file.
pub fn get_kernel_from_file(path: &Path) -> Result<miden_assembly::KernelLibrary, Report> {
    let source_manager = Arc::new(DefaultSourceManager::default());
    get_kernel_from_file_with_source_manager(path, source_manager)
}

/// Returns a `KernelLibrary` from a `.masm` kernel file using the provided source manager.
pub fn get_kernel_from_file_with_source_manager(
    path: &Path,
    source_manager: Arc<DefaultSourceManager>,
) -> Result<miden_assembly::KernelLibrary, Report> {
    let assembler = Assembler::new(source_manager.clone());
    
    // Load the kernel file into the source manager
    let kernel_source = source_manager.load(
        SourceLanguage::Masm,
        path.to_string_lossy().to_string().into(),
        fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to read kernel file `{}`", path.display()))?,
    );
    
    // Assemble the kernel
    assembler
        .assemble_kernel(kernel_source)
        .wrap_err_with(|| format!("Failed to compile kernel from `{}`", path.display()))
}
