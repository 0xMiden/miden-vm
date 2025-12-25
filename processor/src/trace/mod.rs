use alloc::vec::Vec;
#[cfg(any(test, feature = "testing"))]
use core::ops::Range;

use miden_air::trace::{
    AUX_TRACE_RAND_ELEMENTS, AUX_TRACE_WIDTH, DECODER_TRACE_OFFSET, PADDED_TRACE_WIDTH,
    STACK_TRACE_OFFSET,
    decoder::{NUM_USER_OP_HELPERS, USER_OP_HELPERS_OFFSET},
    main_trace::MainTrace,
};
use miden_core::{
    Kernel, ProgramInfo, StackInputs, StackOutputs, Word, ZERO,
    precompile::{PrecompileRequest, PrecompileTranscript},
    stack::MIN_STACK_DEPTH,
};
use winter_prover::{EvaluationFrame, Trace, TraceInfo, crypto::RandomCoin};

use super::{
    AdviceProvider, ColMatrix, Felt, FieldElement,
    chiplets::AuxTraceBuilder as ChipletsAuxTraceBuilder, crypto::RpoRandomCoin,
    decoder::AuxTraceBuilder as DecoderAuxTraceBuilder,
    range::AuxTraceBuilder as RangeCheckerAuxTraceBuilder,
    stack::AuxTraceBuilder as StackAuxTraceBuilder,
};
use crate::fast::ExecutionOutput;

mod utils;
pub use utils::{AuxColumnBuilder, ChipletsLengths, TraceFragment, TraceLenSummary};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Number of rows at the end of an execution trace which are injected with random values.
pub const NUM_RAND_ROWS: usize = 1;

// VM EXECUTION TRACE
// ================================================================================================

#[derive(Debug)]
pub struct AuxTraceBuilders {
    pub(crate) decoder: DecoderAuxTraceBuilder,
    pub(crate) stack: StackAuxTraceBuilder,
    pub(crate) range: RangeCheckerAuxTraceBuilder,
    pub(crate) chiplets: ChipletsAuxTraceBuilder,
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
    trace_info: TraceInfo,
    main_trace: MainTrace,
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

    pub fn new_from_parts(
        program_hash: Word,
        kernel: Kernel,
        execution_output: ExecutionOutput,
        main_trace: MainTrace,
        aux_trace_builders: AuxTraceBuilders,
        trace_len_summary: TraceLenSummary,
    ) -> Self {
        let program_info = ProgramInfo::new(program_hash, kernel);
        let trace_info = TraceInfo::new_multi_segment(
            PADDED_TRACE_WIDTH,
            AUX_TRACE_WIDTH,
            AUX_TRACE_RAND_ELEMENTS,
            main_trace.num_rows(),
            vec![],
        );

        Self {
            meta: Vec::new(),
            trace_info,
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
    pub fn print(&self) {
        use miden_air::trace::TRACE_WIDTH;

        let mut row = [ZERO; PADDED_TRACE_WIDTH];
        for i in 0..self.length() {
            self.main_trace.read_row_into(i, &mut row);
            std::println!(
                "{:?}",
                row.iter().take(TRACE_WIDTH).map(|v| v.as_int()).collect::<Vec<_>>()
            );
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn get_column_range(&self, range: Range<usize>) -> Vec<Vec<Felt>> {
        self.main_trace.get_column_range(range)
    }

    pub fn build_aux_trace<E>(&self, rand_elements: &[E]) -> Option<ColMatrix<E>>
    where
        E: FieldElement<BaseField = Felt>,
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
        let mut aux_columns = decoder_aux_columns
            .into_iter()
            .chain(stack_aux_columns)
            .chain(range_aux_columns)
            .chain(chiplets)
            .collect::<Vec<_>>();

        // inject random values into the last rows of the trace
        let mut rng = RpoRandomCoin::new(*self.program_hash());
        for i in self.length() - NUM_RAND_ROWS..self.length() {
            for column in aux_columns.iter_mut() {
                column[i] = rng.draw().expect("failed to draw a random value");
            }
        }

        Some(ColMatrix::new(aux_columns))
    }
}

// TRACE TRAIT IMPLEMENTATION
// ================================================================================================

impl Trace for ExecutionTrace {
    type BaseField = Felt;

    fn length(&self) -> usize {
        self.main_trace.num_rows()
    }

    fn main_segment(&self) -> &ColMatrix<Felt> {
        &self.main_trace
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Felt>) {
        let next_row_idx = (row_idx + 1) % self.length();
        self.main_trace.read_row_into(row_idx, frame.current_mut());
        self.main_trace.read_row_into(next_row_idx, frame.next_mut());
    }

    fn info(&self) -> &TraceInfo {
        &self.trace_info
    }
}
