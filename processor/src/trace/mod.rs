use alloc::vec::Vec;
use core::mem;

use miden_air::trace::{
    AUX_TRACE_RAND_ELEMENTS, AUX_TRACE_WIDTH, ColMatrix, DECODER_TRACE_OFFSET, MIN_TRACE_LEN,
    PADDED_TRACE_WIDTH, STACK_TRACE_OFFSET, TRACE_WIDTH,
    decoder::{NUM_USER_OP_HELPERS, USER_OP_HELPERS_OFFSET},
    main_trace::MainTrace,
};
use miden_core::{
    ExtensionField, ProgramInfo, StackInputs, StackOutputs, Word, ZERO, stack::MIN_STACK_DEPTH,
};

use super::{
    AdviceProvider, Felt, Process, chiplets::AuxTraceBuilder as ChipletsAuxTraceBuilder,
    crypto::RpoRandomCoin, decoder::AuxTraceBuilder as DecoderAuxTraceBuilder,
    range::AuxTraceBuilder as RangeCheckerAuxTraceBuilder,
    stack::AuxTraceBuilder as StackAuxTraceBuilder,
};

mod utils;
pub use utils::{AuxColumnBuilder, ChipletsLengths, TraceFragment, TraceLenSummary};

// Implementation of AuxTraceBuilder trait for integration with air crate
mod aux_builder_impl;

#[cfg(test)]
mod tests;
#[cfg(test)]
use super::EMPTY_WORD;

// CONSTANTS
// ================================================================================================

/// Number of rows at the end of an execution trace which are injected with random values.
pub const NUM_RAND_ROWS: usize = 1;

// TRACE METADATA
// ================================================================================================

/// Metadata about the execution trace dimensions.
///
/// This struct holds information about trace dimensions for documentation and debugging purposes.
/// Unlike Winterfell's TraceInfo, this is a lightweight struct specific to Plonky3.
#[derive(Debug, Clone)]
pub struct TraceMetadata {
    /// Number of columns in the main trace (padded to power of 2)
    main_width: usize,
    /// Number of columns in the auxiliary trace
    aux_width: usize,
    /// Number of random elements needed for auxiliary trace construction
    num_rand_elements: usize,
    /// Number of rows in the trace (power of 2)
    trace_len: usize,
}

impl TraceMetadata {
    /// Creates a new TraceMetadata instance.
    pub fn new(
        main_width: usize,
        aux_width: usize,
        num_rand_elements: usize,
        trace_len: usize,
    ) -> Self {
        Self {
            main_width,
            aux_width,
            num_rand_elements,
            trace_len,
        }
    }

    /// Returns the main trace width.
    pub fn main_width(&self) -> usize {
        self.main_width
    }

    /// Returns the auxiliary trace width.
    pub fn aux_width(&self) -> usize {
        self.aux_width
    }

    /// Returns the number of random elements needed.
    pub fn num_rand_elements(&self) -> usize {
        self.num_rand_elements
    }

    /// Returns the trace length (number of rows).
    pub fn trace_len(&self) -> usize {
        self.trace_len
    }
}

// VM EXECUTION TRACE
// ================================================================================================

#[derive(Debug, Clone)]
pub struct AuxTraceBuilders {
    pub(crate) decoder: DecoderAuxTraceBuilder,
    pub(crate) stack: StackAuxTraceBuilder,
    pub(crate) range: RangeCheckerAuxTraceBuilder,
    pub(crate) chiplets: ChipletsAuxTraceBuilder,
}

impl AuxTraceBuilders {
    /// Builds auxiliary columns for all components given a MainTrace and challenges.
    ///
    /// Returns a vector of extension field columns in the order:
    /// decoder, stack, range checker, chiplets.
    pub fn build_aux_columns<E>(&self, main_trace: &MainTrace, challenges: &[E]) -> Vec<Vec<E>>
    where
        E: ExtensionField<Felt>,
    {
        let decoder_cols = self.decoder.build_aux_columns(main_trace, challenges);
        let stack_cols = self.stack.build_aux_columns(main_trace, challenges);
        let range_cols = self.range.build_aux_columns(main_trace, challenges);
        let chiplets_cols = self.chiplets.build_aux_columns(main_trace, challenges);

        decoder_cols
            .into_iter()
            .chain(stack_cols)
            .chain(range_cols)
            .chain(chiplets_cols)
            .collect()
    }
}

/// Execution trace which is generated when a program is executed on the VM.
///
/// The trace consists of the following components:
/// - Main traces of System, Decoder, Operand Stack, Range Checker, and Auxiliary Co-Processor
///   components.
/// - Hints used during auxiliary trace segment construction.
/// - Metadata about trace dimensions.
#[derive(Debug)]
pub struct ExecutionTrace {
    meta: Vec<u8>,
    trace_metadata: TraceMetadata,
    pub main_trace: MainTrace,
    aux_trace_builders: AuxTraceBuilders,
    program_info: ProgramInfo,
    stack_outputs: StackOutputs,
    advice: AdviceProvider,
    trace_len_summary: TraceLenSummary,
}

impl ExecutionTrace {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of rows at the end of an execution trace which are injected with random values.
    pub const NUM_RAND_ROWS: usize = NUM_RAND_ROWS;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Builds an execution trace for the provided process.
    pub fn new(mut process: Process, stack_outputs: StackOutputs) -> Self {
        // use program hash to initialize random element generator; this generator will be used
        // to inject random values at the end of the trace; using program hash here is OK because
        // we are using random values only to stabilize constraint degrees, and not to achieve
        // perfect zero knowledge.
        let program_hash = process.decoder.program_hash().into();
        let rng = RpoRandomCoin::new(program_hash);

        // create a new program info instance with the underlying kernel
        let kernel = process.kernel().clone();
        let program_info = ProgramInfo::new(program_hash, kernel);
        let advice = mem::take(&mut process.advice);
        let (main_trace, aux_trace_builders, trace_len_summary) = finalize_trace(process, rng);
        let trace_metadata = TraceMetadata::new(
            PADDED_TRACE_WIDTH,
            AUX_TRACE_WIDTH,
            AUX_TRACE_RAND_ELEMENTS,
            main_trace.num_rows(),
        );

        Self {
            meta: Vec::new(),
            trace_metadata,
            aux_trace_builders,
            main_trace,
            program_info,
            stack_outputs,
            advice,
            trace_len_summary,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the trace metadata containing dimensions and other trace information.
    pub fn trace_metadata(&self) -> &TraceMetadata {
        &self.trace_metadata
    }

    /// Returns the program info of this execution trace.
    pub fn program_info(&self) -> &ProgramInfo {
        &self.program_info
    }

    /// Returns hash of the program execution of which resulted in this execution trace.
    pub fn program_hash(&self) -> &Word {
        self.program_info.program_hash()
    }

    /// Returns outputs of the program execution which resulted in this execution trace.
    pub fn stack_outputs(&self) -> &StackOutputs {
        &self.stack_outputs
    }

    /// Returns the initial state of the top 16 stack registers.
    pub fn init_stack_state(&self) -> StackInputs {
        let mut result = [ZERO; MIN_STACK_DEPTH];
        for (i, result) in result.iter_mut().enumerate() {
            *result = self.main_trace.get_column(i + STACK_TRACE_OFFSET)[0];
        }
        result.into()
    }

    /// Returns the final state of the top 16 stack registers.
    pub fn last_stack_state(&self) -> StackOutputs {
        let last_step = self.last_step();
        let mut result = [ZERO; MIN_STACK_DEPTH];
        for (i, result) in result.iter_mut().enumerate() {
            *result = self.main_trace.get_column(i + STACK_TRACE_OFFSET)[last_step];
        }
        result.into()
    }

    /// Returns a reference to the auxiliary trace builders.
    ///
    /// These builders are used during proving to generate auxiliary trace columns
    /// after the main trace has been committed and random challenges have been sampled.
    pub fn aux_trace_builders(&self) -> &AuxTraceBuilders {
        &self.aux_trace_builders
    }

    /// Returns helper registers state at the specified `clk` of the VM
    pub fn get_user_op_helpers_at(&self, clk: u32) -> [Felt; NUM_USER_OP_HELPERS] {
        let mut result = [ZERO; NUM_USER_OP_HELPERS];
        for (i, result) in result.iter_mut().enumerate() {
            *result = self.main_trace.get_column(DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + i)
                [clk as usize];
        }
        result
    }

    /// Returns the trace length.
    pub fn get_trace_len(&self) -> usize {
        self.main_trace.num_rows()
    }

    /// Returns a summary of the lengths of main, range and chiplet traces.
    pub fn trace_len_summary(&self) -> &TraceLenSummary {
        &self.trace_len_summary
    }

    /// Returns the final advice provider state.
    pub fn advice_provider(&self) -> &AdviceProvider {
        &self.advice
    }

    /// Returns the trace meta data.
    pub fn meta(&self) -> &[u8] {
        &self.meta
    }

    /// Destructures this execution trace into the process’s final stack and advice states.
    pub fn into_outputs(self) -> (StackOutputs, AdviceProvider) {
        (self.stack_outputs, self.advice)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the index of the last row in the trace.
    fn last_step(&self) -> usize {
        self.length() - NUM_RAND_ROWS - 1
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------
    #[cfg(feature = "std")]
    #[allow(dead_code)]
    pub fn print(&self) {
        let mut row = [ZERO; PADDED_TRACE_WIDTH];
        for i in 0..self.length() {
            self.main_trace.read_row_into(i, &mut row);
            std::println!(
                "{:?}",
                row.iter().take(TRACE_WIDTH).map(|v| v.as_int()).collect::<Vec<_>>()
            );
        }
    }

    #[cfg(test)]
    pub fn test_finalize_trace(process: Process) -> (MainTrace, AuxTraceBuilders, TraceLenSummary) {
        let rng = RpoRandomCoin::new(EMPTY_WORD);
        finalize_trace(process, rng)
    }

    pub fn build_aux_trace<E>(&self, rand_elements: &[E]) -> Option<ColMatrix<E>>
    where
        E: ExtensionField<Felt>,
    {
        // add decoder's running product columns
        let decoder_aux_columns = self
            .aux_trace_builders
            .decoder
            .build_aux_columns(&self.main_trace, rand_elements);

        // add stack's running product columns
        let stack_aux_columns =
            self.aux_trace_builders.stack.build_aux_columns(&self.main_trace, rand_elements);

        // add the range checker's running product columns
        let range_aux_columns =
            self.aux_trace_builders.range.build_aux_columns(&self.main_trace, rand_elements);

        // add the running product columns for the chiplets
        let chiplets = self
            .aux_trace_builders
            .chiplets
            .build_aux_columns(&self.main_trace, rand_elements);

        // combine all auxiliary columns into a single vector
        let aux_columns = decoder_aux_columns
            .into_iter()
            .chain(stack_aux_columns)
            .chain(range_aux_columns)
            .chain(chiplets)
            .collect::<Vec<_>>();

        // NOTE: Random row injection removed - not needed for Plonky3's symbolic degree inference
        // (Was only required for Winterfell's TransitionConstraintDegree inference)

        Some(ColMatrix::new(aux_columns))
    }

    fn length(&self) -> usize {
        self.main_trace.num_rows()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a process into a set of execution trace columns for each component of the trace.
///
/// The process includes:
/// - Determining the length of the trace required to accommodate the longest trace column.
/// - Padding the columns to make sure all columns are of the same length.
/// - Inserting random values in the last row of all columns. This helps ensure that there are no
///   repeating patterns in each column and each column contains a least two distinct values. This,
///   in turn, ensures that polynomial degrees of all columns are stable.
fn finalize_trace(
    process: Process,
    _rng: RpoRandomCoin,
) -> (MainTrace, AuxTraceBuilders, TraceLenSummary) {
    let (system, decoder, stack, mut range, chiplets) = process.into_parts();

    let clk = system.clk();

    // Trace lengths of system and stack components must be equal to the number of executed cycles
    assert_eq!(clk.as_usize(), system.trace_len(), "inconsistent system trace lengths");
    assert_eq!(clk.as_usize(), decoder.trace_len(), "inconsistent decoder trace length");
    assert_eq!(clk.as_usize(), stack.trace_len(), "inconsistent stack trace lengths");

    // Add the range checks required by the chiplets to the range checker.
    chiplets.append_range_checks(&mut range);

    // Generate number of rows for the range trace.
    let range_table_len = range.get_number_range_checker_rows();

    // Get the trace length required to hold all execution trace steps.
    let max_len = range_table_len.max(clk.into()).max(chiplets.trace_len());

    // Pad the trace length to the next power of two, ensuring it meets MIN_TRACE_LEN
    // NOTE: NUM_RAND_ROWS removed - not needed for Plonky3's symbolic degree inference
    // NOTE: MIN_TRACE_LEN enforced to satisfy FRI parameter constraints (log_height >
    // log_final_poly_len + log_blowup)
    let trace_len = max_len.next_power_of_two().max(MIN_TRACE_LEN);

    // Get the lengths of the traces: main, range, and chiplets
    let trace_len_summary =
        TraceLenSummary::new(clk.into(), range_table_len, ChipletsLengths::new(&chiplets));

    // Combine all trace segments into the main trace
    let system_trace = system.into_trace(trace_len, 0);
    let decoder_trace = decoder.into_trace(trace_len, 0);
    let stack_trace = stack.into_trace(trace_len, 0);
    let chiplets_trace = chiplets.into_trace(trace_len, 0);

    // Combine the range trace segment using the support lookup table
    let range_check_trace = range.into_trace_with_table(range_table_len, trace_len, 0);

    // Padding to make the number of columns a multiple of 8 i.e., the RPO permutation rate
    let padding = vec![vec![ZERO; trace_len]; PADDED_TRACE_WIDTH - TRACE_WIDTH];

    let trace = system_trace
        .into_iter()
        .chain(decoder_trace.trace)
        .chain(stack_trace.trace)
        .chain(range_check_trace.trace)
        .chain(chiplets_trace.trace)
        .chain(padding)
        .collect::<Vec<_>>();

    // NOTE: Random row injection removed - not needed for Plonky3's symbolic degree inference
    // (Was only required for Winterfell's TransitionConstraintDegree inference)

    let aux_trace_hints = AuxTraceBuilders {
        decoder: decoder_trace.aux_builder,
        stack: StackAuxTraceBuilder,
        range: range_check_trace.aux_builder,
        chiplets: chiplets_trace.aux_builder,
    };

    let main_trace = MainTrace::new(ColMatrix::new(trace), clk);

    (main_trace, aux_trace_hints, trace_len_summary)
}
