use std::{path::PathBuf, time::Instant};

use clap::Parser;
use miden_assembly::diagnostics::{IntoDiagnostic, Report, WrapErr};
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, ExecutionOptions, ExecutionTrace};
use miden_vm::internal::InputFile;
use tracing::instrument;

use super::{
    data::{Libraries, OutputFile},
    utils::{get_masm_program, get_masp_program},
};

#[derive(Debug, Clone, Parser)]
#[command(about = "Run a Miden program")]
pub struct RunCmd {
    /// Path to a .masm assembly file or a .masp package file
    #[arg(value_parser)]
    program_file: PathBuf,

    /// Number of cycles the program is expected to consume
    #[arg(short = 'e', long = "exp-cycles", default_value = "64")]
    expected_cycles: u32,

    /// Path to input file
    #[arg(short = 'i', long = "input", value_parser)]
    input_file: Option<PathBuf>,

    /// Paths to .masl library files (only used for assembly files)
    #[arg(short = 'l', long = "libraries", value_parser)]
    library_paths: Vec<PathBuf>,

    /// Maximum number of cycles a program is allowed to consume
    #[arg(short = 'm', long = "max-cycles", default_value_t = ExecutionOptions::MAX_CYCLES)]
    max_cycles: u32,

    /// Number of outputs
    #[arg(short = 'n', long = "num-outputs", default_value = "16")]
    num_outputs: usize,

    /// Path to output file
    #[arg(short = 'o', long = "output", value_parser)]
    output_file: Option<PathBuf>,

    /// Enable tracing to monitor execution of the VM
    #[arg(short = 't', long = "trace")]
    trace: bool,

    /// Disable debug instructions (release mode)
    #[arg(short = 'r', long = "release")]
    release: bool,
}

impl RunCmd {
    pub fn execute(&self) -> Result<(), Report> {
        println!("===============================================================================");
        println!("Run program: {}", self.program_file.display());
        println!("-------------------------------------------------------------------------------");

        // determine file type based on extension
        let ext = self
            .program_file
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        let now = Instant::now();

        // use a single match expression based on file extension
        let (trace, program_hash) = match ext.as_str() {
            "masp" => run_masp_program(self)?,
            "masm" => run_masm_program(self)?,
            _ => return Err(Report::msg("The provided file must have a .masm or .masp extension")),
        };

        println!(
            "Executed the program with hash {} in {} ms",
            hex::encode(program_hash),
            now.elapsed().as_millis()
        );

        if let Some(output_path) = &self.output_file {
            // write outputs to file if one was specified
            OutputFile::write(trace.stack_outputs(), output_path).map_err(Report::msg)?;
        } else {
            // write the stack outputs to the terminal
            println!("Output: {:?}", trace.stack_outputs().stack_truncated(self.num_outputs));
        }

        // calculate the percentage of padded rows
        let padding_percentage = (trace.trace_len_summary().padded_trace_len()
            - trace.trace_len_summary().trace_len())
            * 100
            / trace.trace_len_summary().padded_trace_len();
        // print the required cycles for each component
        println!(
            "VM cycles: {} extended to {} steps ({}% padding).
├── Stack rows: {}
├── Range checker rows: {}
└── Chiplets rows: {}
    ├── Hash chiplet rows: {}
    ├── Bitwise chiplet rows: {}
    ├── Memory chiplet rows: {}
    └── Kernel ROM rows: {}",
            trace.trace_len_summary().trace_len(),
            trace.trace_len_summary().padded_trace_len(),
            padding_percentage,
            trace.trace_len_summary().main_trace_len(),
            trace.trace_len_summary().range_trace_len(),
            trace.trace_len_summary().chiplets_trace_len().trace_len(),
            trace.trace_len_summary().chiplets_trace_len().hash_chiplet_len(),
            trace.trace_len_summary().chiplets_trace_len().bitwise_chiplet_len(),
            trace.trace_len_summary().chiplets_trace_len().memory_chiplet_len(),
            trace.trace_len_summary().chiplets_trace_len().kernel_rom_len(),
        );

        Ok(())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[instrument(name = "run_program", skip_all)]
fn run_masp_program(params: &RunCmd) -> Result<(ExecutionTrace, [u8; 32]), Report> {
    let program = get_masp_program(&params.program_file)?;

    // use simplified input data reading
    let input_data = InputFile::read(&params.input_file, &params.program_file)?;

    let stack_inputs = input_data.parse_stack_inputs().map_err(Report::msg)?;
    let advice_inputs = input_data.parse_advice_inputs().map_err(Report::msg)?;
    let mut host = DefaultHost::default().with_library(&CoreLibrary::default())?;

    let execution_options = ExecutionOptions::new(
        Some(params.max_cycles),
        params.expected_cycles,
        params.trace,
        !params.release,
    )
    .into_diagnostic()?;

    let program_hash: [u8; 32] = program.hash().into();

    // execute program and generate outputs
    let trace = miden_processor::execute(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        execution_options,
    )
    .wrap_err("Failed to generate execution trace")?;

    Ok((trace, program_hash))
}

#[instrument(name = "run_program", skip_all)]
fn run_masm_program(params: &RunCmd) -> Result<(ExecutionTrace, [u8; 32]), Report> {
    for lib in &params.library_paths {
        if !lib.is_file() {
            let name = lib.display();
            return Err(Report::msg(format!("{name} must be a file.")));
        }
    }

    // load libraries from files
    let libraries = Libraries::new(&params.library_paths)?;

    // load program from file and compile
    let (program, source_manager) = get_masm_program(&params.program_file, &libraries)?;
    let input_data = InputFile::read(&params.input_file, &params.program_file)?;

    let execution_options = ExecutionOptions::new(
        Some(params.max_cycles),
        params.expected_cycles,
        params.trace,
        !params.release,
    )
    .into_diagnostic()?;

    // fetch the stack and program inputs from the arguments
    let stack_inputs = input_data.parse_stack_inputs().map_err(Report::msg)?;
    let advice_inputs = input_data.parse_advice_inputs().map_err(Report::msg)?;
    let mut host = DefaultHost::default().with_source_manager(source_manager);
    host.load_library(&CoreLibrary::default())
        .into_diagnostic()
        .wrap_err("Failed to load core library")?;
    for lib in libraries.libraries {
        host.load_library(lib.mast_forest())
            .into_diagnostic()
            .wrap_err("Failed to load library")?;
    }

    let program_hash: [u8; 32] = program.hash().into();

    let trace = miden_processor::execute(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        execution_options,
    )
    .wrap_err("Failed to generate execution trace")?;

    Ok((trace, program_hash))
}
