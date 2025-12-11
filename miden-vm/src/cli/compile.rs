use std::path::PathBuf;

use clap::Parser;
use miden_assembly::diagnostics::{IntoDiagnostic, Report, WrapErr};

use super::data::{Libraries, ProgramFile};

#[derive(Debug, Clone, Parser)]
#[command(about = "Assemble a Miden program")]
pub struct CompileCmd {
    /// Path to .masm assembly file
    #[arg(short = 'a', long = "assembly", value_parser)]
    assembly_file: PathBuf,
    /// Paths to .masl library files
    #[arg(short = 'l', long = "libraries", value_parser)]
    library_paths: Vec<PathBuf>,
    /// Path to output file
    #[arg(short = 'o', long = "output", value_parser)]
    output_file: Option<PathBuf>,
}

impl CompileCmd {
    pub fn execute(&self) -> Result<(), Report> {
        println!("============================================================");
        println!("Compile program");
        println!("============================================================");

        // load the program from file and parse it
        let program = ProgramFile::read(&self.assembly_file)?;

        // load libraries from files
        let libraries = Libraries::new(&self.library_paths)?;

        // compile the program
        // Note: assembler debug mode is always enabled (issue #1821)
        let compiled_program = program.compile(&libraries.libraries)?;

        // report program hash to user
        let program_hash: [u8; 32] = compiled_program.hash().into();
        println!("program hash is {}", hex::encode(program_hash));

        // write the compiled program into the specified path if one is provided; if the path is
        // not provided, writes the file into the same directory as the source file, but with
        // `.masb` extension.
        let out_path = self.output_file.clone().unwrap_or_else(|| {
            let mut out_file = self.assembly_file.clone();
            out_file.set_extension("masb");
            out_file
        });

        compiled_program
            .write_to_file(out_path)
            .into_diagnostic()
            .wrap_err("Failed to write the compiled file")
    }
}
