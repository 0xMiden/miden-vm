use std::{
    path::{Path, PathBuf},
    time::Instant,
};

use clap::Parser;
use miden_assembly::diagnostics::{IntoDiagnostic, Report, Result, WrapErr};
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
}

impl VerifyCmd {
    pub fn execute(&self) -> Result<(), Report> {
        let (input_file, output_file) = self.infer_defaults().unwrap();

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

        // TODO accept kernel as CLI argument
        let kernel = Kernel::default();
        let program_info = ProgramInfo::new(program_hash, kernel);

        // verify proof
        let stack_outputs = outputs_data.stack_outputs().map_err(Report::msg)?;
        miden_verifier::verify(program_info, stack_inputs, stack_outputs, proof)
            .into_diagnostic()
            .wrap_err("Program failed verification!")?;

        println!("Verification complete in {} ms", now.elapsed().as_millis());

        Ok(())
    }

    fn infer_defaults(&self) -> Result<(PathBuf, PathBuf), Report> {
        if !self.proof_file.exists() {
            return Err(Report::msg("Proof file does not exist"));
        }
        let proof_file = self.proof_file.clone();

        let input_file = self.input_file.clone().unwrap_or_else(|| {
            let mut input_path = proof_file.clone();
            input_path.set_extension("inputs");
            input_path
        });
        let output_file = self.output_file.clone().unwrap_or_else(|| {
            let mut output_path = proof_file.clone();
            output_path.set_extension("outputs");
            output_path
        });

        Ok((input_file.to_path_buf(), output_file.to_path_buf()))
    }
}
