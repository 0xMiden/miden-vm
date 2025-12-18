use std::{fs, path::PathBuf, sync::Arc, time::Instant};

use clap::Parser;
use miden_assembly::{
    Assembler, KernelLibrary,
    diagnostics::{IntoDiagnostic, Report, Result, WrapErr},
};
use miden_mast_package::{MastArtifact, Package};
use miden_prover::utils::Deserializable;
use miden_vm::{Kernel, ProgramInfo, internal::InputFile};

use super::data::{OutputFile, ProgramHash, ProofFile};

#[derive(Debug, Clone, Parser)]
#[command(about = "Verify a Miden program")]
pub struct VerifyCmd {
    /// Path to input file
    #[arg(short = 'i', long = "input", value_parser)]
    input_file: Option<PathBuf>,
    /// Path to output file
    #[arg(short = 'o', long = "output", value_parser)]
    output_file: Option<PathBuf>,
    /// Path to proof file
    #[arg(short = 'p', long = "proof", value_parser)]
    proof_file: PathBuf,
    /// Program hash (hex)
    #[arg(short = 'x', long = "program-hash")]
    program_hash: String,

    /// Path to a file (.masm or .masp) containing the kernel to be loaded with the program
    #[arg(long = "kernel", value_parser)]
    kernel_file: Option<PathBuf>,
}

impl VerifyCmd {
    pub fn execute(&self) -> Result<(), Report> {
        let (input_file, output_file) = self.infer_defaults()?;

        println!("===============================================================================");
        println!("Verifying proof: {}", self.proof_file.display());
        println!("-------------------------------------------------------------------------------");

        // read program hash from input
        let program_hash = ProgramHash::read(&self.program_hash).map_err(Report::msg)?;

        // load input data from file
        let input_data = InputFile::read(&Some(input_file), self.proof_file.as_ref())?;

        // fetch the stack inputs from the arguments
        let stack_inputs = input_data.parse_stack_inputs().map_err(Report::msg)?;

        // load outputs data from file
        let outputs_data =
            OutputFile::read(&Some(output_file), self.proof_file.as_ref()).map_err(Report::msg)?;

        // load proof from file
        let proof = ProofFile::read(&Some(self.proof_file.clone()), self.proof_file.as_ref())
            .map_err(Report::msg)?;

        let now = Instant::now();

        // Load kernel if provided, otherwise use default
        let kernel = if let Some(ref kernel_path) = self.kernel_file {
            if !kernel_path.is_file() {
                return Err(Report::msg(format!(
                    "Kernel file `{}` must be a file.",
                    kernel_path.display()
                )));
            }
            load_kernel(kernel_path)?
        } else {
            Kernel::default()
        };
        let program_info = ProgramInfo::new(program_hash, kernel);

        // verify proof
        let stack_outputs = outputs_data.stack_outputs().map_err(Report::msg)?;
        miden_vm::verify(program_info, stack_inputs, stack_outputs, proof)
            .into_diagnostic()
            .wrap_err("Program failed verification!")?;

        println!("Verification complete in {} ms", now.elapsed().as_millis());

        Ok(())
    }

    fn infer_defaults(&self) -> Result<(PathBuf, PathBuf), Report> {
        if !self.proof_file.exists() {
            return Err(Report::msg("Proof file does not exist"));
        }
        let default_path = |ext: &str| self.proof_file.with_extension(ext);

        let input_file =
            self.input_file.as_ref().map_or_else(|| default_path("inputs"), PathBuf::clone);
        let output_file = self
            .output_file
            .as_ref()
            .map_or_else(|| default_path("outputs"), PathBuf::clone);

        Ok((input_file, output_file))
    }
}

/// Loads a kernel from a file (.masm or .masp) and returns the Kernel.
fn load_kernel(kernel_path: &PathBuf) -> Result<Kernel, Report> {
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
            Assembler::default().assemble_kernel(kernel_path.clone()).wrap_err_with(|| {
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

    // Extract kernel from kernel library
    Ok(kernel_lib.kernel().clone())
}

#[cfg(test)]
mod tests {
    use std::{fs, fs::File};

    use super::*;

    #[test]
    fn infer_defaults_uses_proof_file_basename_for_defaults() {
        // prepare a unique temp directory
        let base =
            std::env::temp_dir().join(format!("miden_vm_verify_test_{}", std::process::id()));
        fs::create_dir_all(&base).expect("create temp test dir");

        // create a dummy proof file
        let proof_path = base.join("proof_file");
        File::create(&proof_path).expect("create proof file");

        // build command with no explicit input/output
        let cmd = VerifyCmd {
            input_file: None,
            output_file: None,
            proof_file: proof_path.clone(),
            program_hash: "00".to_string(),
            kernel_file: None,
        };

        // exercise
        let (input, output) = cmd.infer_defaults().expect("infer defaults");

        // verify: defaults are proof file with replaced extensions
        assert_eq!(input, proof_path.with_extension("inputs"));
        assert_eq!(output, proof_path.with_extension("outputs"));

        // cleanup best-effort
        let _ = fs::remove_file(&proof_path);
        let _ = fs::remove_dir_all(&base);
    }
}
