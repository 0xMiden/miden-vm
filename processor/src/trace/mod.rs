use alloc::vec::Vec;
use core::mem;

use miden_air::trace::{
    AUX_TRACE_RAND_ELEMENTS, AUX_TRACE_WIDTH, DECODER_TRACE_OFFSET, MIN_TRACE_LEN,
    PADDED_TRACE_WIDTH, STACK_TRACE_OFFSET, TRACE_WIDTH,
    decoder::{NUM_USER_OP_HELPERS, USER_OP_HELPERS_OFFSET},
    main_trace::{ColMatrix, MainTrace},
};
use miden_core::{
    Kernel, ProgramInfo, StackInputs, StackOutputs, Word, ZERO,
    precompile::{PrecompileRequest, PrecompileTranscript},
    stack::MIN_STACK_DEPTH,
    ExtensionField,
};

use super::{
    AdviceProvider, Felt, Process,
    chiplets::AuxTraceBuilder as ChipletsAuxTraceBuilder, crypto::RpoRandomCoin,
    decoder::AuxTraceBuilder as DecoderAuxTraceBuilder,
    range::AuxTraceBuilder as RangeCheckerAuxTraceBuilder,
    stack::AuxTraceBuilder as StackAuxTraceBuilder,
};
use crate::fast::ExecutionOutput;

mod utils;
pub use utils::{AuxColumnBuilder, ChipletsLengths, TraceFragment, TraceLenSummary};

mod aux_builder_impl;

#[cfg(test)]
mod tests;
#[cfg(test)]
use super::EMPTY_WORD;

// CONSTANTS
// ================================================================================================

/// Number of rows at the end of an execution trace which are injected with random values.
pub const NUM_RAND_ROWS: usize = 1;

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
    /// Builds auxiliary columns for all trace segments given the main trace and challenges.
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

// TRACE METADATA
// ================================================================================================

#[derive(Debug, Clone)]
pub struct TraceMetadata {
    main_width: usize,
    aux_width: usize,
    num_rand_elements: usize,
    trace_len: usize,
}

impl TraceMetadata {
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

    pub fn main_width(&self) -> usize {
        self.main_width
    }

    pub fn aux_width(&self) -> usize {
        self.aux_width
    }

    pub fn num_rand_elements(&self) -> usize {
        self.num_rand_elements
    }

    pub fn trace_len(&self) -> usize {
        self.trace_len
    }
}

/// Execution trace which is generated when a program is executed on the VM.
///
/// The trace consists of the following components:
/// - Main traces of System, Decoder, Operand Stack, Range Checker, and Auxiliary Co-Processor
///   components.
/// - Hints used during auxiliary trace segment construction.
/// - Metadata needed by the STARK prover.
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
    final_pc_transcript: PrecompileTranscript,
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
        let (main_trace, aux_trace_builders, trace_len_summary, final_pc_transcript) =
            finalize_trace(process, rng);
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
            final_pc_transcript,
        }
    }

    pub fn new_from_parts(
        program_hash: Word,
        kernel: Kernel,
        execution_output: ExecutionOutput,
        main_trace: MainTrace,
        aux_trace_builders: AuxTraceBuilders,
        trace_len_summary: TraceLenSummary,
    ) -> Self {
        let program_info = ProgramInfo::new(program_hash, kernel);
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
            stack_outputs: execution_output.stack,
            advice: execution_output.advice,
            trace_len_summary,
            final_pc_transcript: execution_output.final_pc_transcript,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the program info of this execution trace.
    pub fn program_info(&self) -> &ProgramInfo {
        &self.program_info
    }

    /// Returns hash of the program execution of which resulted in this execution trace.
    pub fn program_hash(&self) -> &Word {
        self.program_info.program_hash()
    }

    /// Returns a reference to the main trace segment.
    pub fn main_segment(&self) -> &MainTrace {
        &self.main_trace
    }

    /// Returns a mutable reference to the main trace segment.
    pub fn main_segment_mut(&mut self) -> &mut MainTrace {
        &mut self.main_trace
    }

    /// Returns outputs of the program execution which resulted in this execution trace.
    pub fn stack_outputs(&self) -> &StackOutputs {
        &self.stack_outputs
    }

    /// Returns the precompile requests generated during program execution.
    pub fn precompile_requests(&self) -> &[PrecompileRequest] {
        self.advice.precompile_requests()
    }

    /// Moves all accumulated precompile requests out of the trace, leaving it empty.
    ///
    /// Intended for proof packaging, where requests are serialized into the proof and no longer
    /// needed in the trace after consumption.
    pub fn take_precompile_requests(&mut self) -> Vec<PrecompileRequest> {
        self.advice.take_precompile_requests()
    }

    /// Returns the final precompile transcript after executing all precompile requests.
    pub fn final_precompile_transcript(&self) -> PrecompileTranscript {
        self.final_pc_transcript
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

    /// Legacy alias retained for tests that still call `length()`.
    pub fn length(&self) -> usize {
        self.get_trace_len()
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

    /// Returns metadata describing trace dimensions.
    pub fn trace_metadata(&self) -> &TraceMetadata {
        &self.trace_metadata
    }

    /// Returns auxiliary trace builders (decoder/stack/range/chiplets).
    pub fn aux_trace_builders(&self) -> AuxTraceBuilders {
        self.aux_trace_builders.clone()
    }

    /// Destructures this execution trace into the process’s final stack and advice states.
    pub fn into_outputs(self) -> (StackOutputs, AdviceProvider) {
        (self.stack_outputs, self.advice)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the index of the last row in the trace.
    fn last_step(&self) -> usize {
        self.main_trace.num_rows() - NUM_RAND_ROWS - 1
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------
    #[cfg(feature = "std")]
    pub fn print(&self) {
        let mut row = [ZERO; PADDED_TRACE_WIDTH];
        for i in 0..self.main_trace.num_rows() {
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
        let (main_trace, aux_trace_builders, trace_len_summary, _final_pc_transcript) =
            finalize_trace(process, rng);
        (main_trace, aux_trace_builders, trace_len_summary)
    }

    pub fn build_aux_trace<E>(&self, rand_elements: &[E]) -> Option<ColMatrix<E>>
    where
        E: ExtensionField<Felt>,
    {
        let aux_columns = self
            .aux_trace_builders
            .build_aux_columns(&self.main_trace, rand_elements);

        // NOTE: We no longer inject randomizers into auxiliary columns; Plonky3’s symbolic
        // degree tracking does not require them (they were only needed for Winterfell).

        Some(ColMatrix::new(aux_columns))
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
) -> (MainTrace, AuxTraceBuilders, TraceLenSummary, PrecompileTranscript) {
    let (system, decoder, stack, mut range, chiplets, final_capacity) = process.into_parts();
    let final_pc_transcript = PrecompileTranscript::from_state(final_capacity);

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

    // Pad the trace length to the next power of two (min MIN_TRACE_LEN). Random-row padding is
    // no longer required now that we rely on Plonky3’s static degree analysis.
    let trace_len = max_len.next_power_of_two().max(MIN_TRACE_LEN);

    // Get the lengths of the traces: main, range, and chiplets
    let trace_len_summary =
        TraceLenSummary::new(clk.into(), range_table_len, ChipletsLengths::new(&chiplets));

    // Combine all trace segments into the main trace
    let system_trace = system.into_trace(trace_len, 0);
    let decoder_trace = decoder.into_trace(trace_len, 0);
    let stack_trace = stack.into_trace(trace_len, 0);
    let chiplets_trace = chiplets.into_trace(trace_len, 0, final_capacity);

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

    // NOTE: Random row injection is no longer required for Plonky3’s prover (it was a
    // Winterfell-only degree-stabilization step).

    let aux_trace_hints = AuxTraceBuilders {
        decoder: decoder_trace.aux_builder,
        stack: StackAuxTraceBuilder,
        range: range_check_trace.aux_builder,
        chiplets: chiplets_trace.aux_builder,
    };

    let main_trace = MainTrace::new(ColMatrix::new(trace), clk);

    (main_trace, aux_trace_hints, trace_len_summary, final_pc_transcript)
}
