use std::{path::PathBuf, time::Instant};

use clap::Parser;
use miden_assembly::diagnostics::{IntoDiagnostic, Report, WrapErr};
use miden_core_lib::CoreLibrary;
use miden_processor::{
    DefaultHost, ExecutionClaim, ExecutionOptions, ExecutionPlan, PackageSourceDebugContext,
    RecordWitness,
    trace::{MIN_TRACE_LEN, TraceLenSummary},
};
use miden_vm::{Processor, internal::InputFile};
use tracing::instrument;

use super::{
    config::Settings,
    data::{Libraries, OutputFile},
    utils::{
        get_masm_program, get_masp_package, load_package_with_handlers,
        load_program_package_with_handlers,
    },
};

#[derive(Debug, Clone, Parser)]
#[command(about = "Run a Miden program")]
pub struct RunCmd {
    /// Path to a .masm assembly file or a .masp package file
    #[arg(value_parser)]
    program_file: PathBuf,

    /// Path to input file
    #[arg(short = 'i', long = "input", value_parser)]
    input_file: Option<PathBuf>,

    /// Paths to .masp library files (only used for assembly files)
    #[arg(short = 'l', long = "libraries", value_parser)]
    library_paths: Vec<PathBuf>,

    /// Path to output file
    #[arg(short = 'o', long = "output", value_parser)]
    output_file: Option<PathBuf>,

    /// Path to a file (.masm or .masp) containing the kernel to be loaded with the program
    #[arg(long = "kernel", value_parser)]
    kernel_file: Option<PathBuf>,
}

impl RunCmd {
    pub(crate) fn execute(&self, settings: &Settings) -> Result<(), Report> {
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
        let (claim, summary) = match ext.as_str() {
            "masp" => run_masp_program(self, settings.execution.clone())?,
            "masm" => run_masm_program(self, settings.execution.clone())?,
            _ => return Err(Report::msg("The provided file must have a .masm or .masp extension")),
        };

        println!(
            "Executed the program with hash {} in {} ms",
            hex::encode(claim.program_root().as_bytes()),
            now.elapsed().as_millis()
        );

        let budget = settings.prover.trace_budget();
        let max_prover_memory = settings.prover.max_prover_memory_bytes();
        let padded_heights = summary.padded_heights();
        if budget
            .prover_peak_bytes(&padded_heights)
            .is_none_or(|bytes| bytes > max_prover_memory)
        {
            let [core, chiplets, _, lookup] = padded_heights;
            let min_bytes = budget.prover_peak_bytes(&[core, chiplets, MIN_TRACE_LEN, lookup]);
            if min_bytes.is_none_or(|bytes| bytes > max_prover_memory) {
                return Err(Report::msg(format!(
                    "VM trace requires more than the {max_prover_memory} byte prover memory limit even at the minimum Eidos height"
                )));
            }
            eprintln!(
                "Warning: VM prover memory upper bound exceeds the {max_prover_memory} byte limit. The prover checks the exact padded heights."
            );
        }

        if let Some(output_path) = &self.output_file {
            // write outputs to file if one was specified
            OutputFile::write(claim.stack_outputs(), output_path).map_err(Report::msg)?;
        } else {
            // write the stack outputs to the terminal
            println!("Output: {:?}", claim.stack_outputs().get_num_elements(settings.num_outputs));
        }

        let chiplets = summary.chiplets();
        let padding_percent =
            |rows: usize, height: usize| (height - rows) as u128 * 100 / height as u128;

        // print the required cycles for each component
        println!(
            "VM trace rows:
├── Core rows: {} extended to {} ({}% padding)
├── Chiplets rows: {} extended to {} ({}% padding)
│   ├── Hash chiplet rows: {}
│   ├── Bitwise chiplet rows (including AEAD): {}
│   ├── Memory chiplet rows: {}
│   ├── ACE chiplet rows: {}
│   └── Kernel ROM rows: {}
├── Eidos compression rows: at most {} (padded height at most {})
└── Byte-pair lookup rows: {} (fixed table)",
            summary.core_rows(),
            summary.core_height(),
            padding_percent(summary.core_rows(), summary.core_height()),
            summary.chiplets_rows(),
            summary.chiplets_height(),
            padding_percent(summary.chiplets_rows(), summary.chiplets_height()),
            chiplets.hash_chiplet_len(),
            chiplets.bitwise_chiplet_len(),
            chiplets.memory_chiplet_len(),
            chiplets.ace_chiplet_len(),
            chiplets.kernel_rom_len(),
            summary.eidos_compression_rows(),
            summary.eidos_compression_height(),
            summary.byte_pair_lookup_rows(),
        );

        Ok(())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[instrument(target = "miden::cli", level = "trace", name = "run_program", skip_all)]
fn run_masp_program(
    params: &RunCmd,
    exec_options: ExecutionOptions,
) -> Result<(ExecutionClaim, TraceLenSummary), Report> {
    if params.kernel_file.is_some() {
        return Err(Report::msg(
            "The `--kernel` option does not apply to a `.masp` package: the package fixes its own kernel.",
        ));
    }

    let package = get_masp_package(&params.program_file)?;
    let program = package.try_into_program()?;

    // use simplified input data reading
    let input_data = InputFile::read(&params.input_file, &params.program_file)?;

    let stack_inputs = input_data.parse_stack_inputs().map_err(Report::msg)?;
    let advice_inputs = input_data
        .parse_advice_inputs_with_options(&exec_options)
        .map_err(Report::msg)?;
    let mut host = DefaultHost::default().with_library(&CoreLibrary::default())?;
    load_program_package_with_handlers(&mut host, &package, &mut Vec::new())?;

    let plan = Processor::new(&program)
        .with_options(exec_options)
        .with_stack_inputs(stack_inputs)
        .with_advice(advice_inputs)
        .record_witness();
    run_recording(plan, &mut host)
}

#[instrument(target = "miden::cli", level = "trace", name = "run_program", skip_all)]
fn run_masm_program(
    params: &RunCmd,
    exec_options: ExecutionOptions,
) -> Result<(ExecutionClaim, TraceLenSummary), Report> {
    for lib in &params.library_paths {
        if !lib.is_file() {
            let name = lib.display();
            return Err(Report::msg(format!("{name} must be a file.")));
        }
    }

    // load libraries from files
    let libraries = Libraries::new(&params.library_paths)?;

    // validate kernel file if provided
    if let Some(ref kernel_path) = params.kernel_file
        && !kernel_path.is_file()
    {
        return Err(Report::msg(format!(
            "Kernel file `{}` must be a file.",
            kernel_path.display()
        )));
    }

    // load program from file and compile
    let (program, package_debug_info, entrypoint_source_node, source_manager, kernel_package) =
        get_masm_program(&params.program_file, &libraries, params.kernel_file.as_deref())?;
    let input_data = InputFile::read(&params.input_file, &params.program_file)?;

    // fetch the stack and program inputs from the arguments
    let stack_inputs = input_data.parse_stack_inputs().map_err(Report::msg)?;
    let advice_inputs = input_data
        .parse_advice_inputs_with_options(&exec_options)
        .map_err(Report::msg)?;
    let mut host = DefaultHost::default().with_source_manager(source_manager);
    host.load_library(&CoreLibrary::default())
        .into_diagnostic()
        .wrap_err("Failed to load core library")?;
    let mut loaded_handler_sections = Vec::new();
    for lib in &libraries.libraries {
        load_package_with_handlers(&mut host, lib, &mut loaded_handler_sections)?;
    }
    if let Some(kernel_package) = &kernel_package {
        load_package_with_handlers(&mut host, kernel_package, &mut loaded_handler_sections)?;
    }

    let source = package_debug_info
        .as_ref()
        .map(|info| PackageSourceDebugContext::new_optional(info, entrypoint_source_node));
    let plan = Processor::new(&program)
        .with_options(exec_options)
        .with_stack_inputs(stack_inputs)
        .with_advice(advice_inputs)
        .with_source_context(source)
        .record_witness();
    run_recording(plan, &mut host)
}

fn run_recording(
    plan: ExecutionPlan<'_, RecordWitness>,
    host: &mut DefaultHost,
) -> Result<(ExecutionClaim, TraceLenSummary), Report> {
    let halted = plan
        .start()
        .and_then(|session| session.run_to_completion_sync(host))
        .wrap_err("Failed to execute program")?;
    let summary = halted
        .trace_len_upper_bound()
        .ok_or_else(|| Report::msg("Trace size estimate exceeds the platform row limit"))?;
    let output = halted.finish().wrap_err("Failed to export execution witness")?;
    Ok((output.claim, summary))
}
