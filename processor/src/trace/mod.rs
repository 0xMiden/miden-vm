use alloc::vec::Vec;
#[cfg(any(test, feature = "testing"))]
use core::ops::Range;

#[cfg(feature = "std")]
use miden_air::trace::PADDED_TRACE_WIDTH;
use miden_air::{
    PublicInputs,
    trace::{
        AuxTraceBuilder, DECODER_TRACE_OFFSET, MainTrace, STACK_TRACE_OFFSET,
        decoder::{NUM_USER_OP_HELPERS, USER_OP_HELPERS_OFFSET},
    },
};
use miden_core::{
    Kernel, ProgramInfo, StackInputs, StackOutputs, Word, ZERO,
    field::ExtensionField,
    precompile::{PrecompileRequest, PrecompileTranscript},
    stack::MIN_STACK_DEPTH,
    utils::ColMatrix,
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use super::{
    AdviceProvider, Felt, chiplets::AuxTraceBuilder as ChipletsAuxTraceBuilder,
    decoder::AuxTraceBuilder as DecoderAuxTraceBuilder,
    range::AuxTraceBuilder as RangeCheckerAuxTraceBuilder,
    stack::AuxTraceBuilder as StackAuxTraceBuilder,
};
use crate::{fast::ExecutionOutput, row_major_adapter};

mod utils;
pub use utils::{AuxColumnBuilder, ChipletsLengths, TraceFragment, TraceLenSummary};

#[cfg(test)]
mod tests;

// VM EXECUTION TRACE
// ================================================================================================

#[derive(Debug, Clone)]
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
    main_trace: MainTrace,
    aux_trace_builders: AuxTraceBuilders,
    program_info: ProgramInfo,
    stack_outputs: StackOutputs,
    advice: AdviceProvider,
    trace_len_summary: TraceLenSummary,
    final_pc_transcript: PrecompileTranscript,
}

impl ExecutionTrace {
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

        Self {
            meta: Vec::new(),
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

    /// Returns the public values for this execution trace.
    pub fn to_public_values(&self) -> Vec<Felt> {
        let public_inputs = PublicInputs::new(
            self.program_info.clone(),
            self.init_stack_state(),
            self.stack_outputs.clone(),
            self.final_pc_transcript.state(),
        );
        public_inputs.to_elements()
    }

    /// Returns a clone of the auxiliary trace builders.
    pub fn aux_trace_builders(&self) -> AuxTraceBuilders {
        self.aux_trace_builders.clone()
    }

    /// Returns a reference to the main trace.
    pub fn main_trace(&self) -> &MainTrace {
        &self.main_trace
    }

    /// Returns a mutable reference to the main trace.
    pub fn main_trace_mut(&mut self) -> &mut MainTrace {
        &mut self.main_trace
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

    /// Returns the length of the trace (number of rows in the main trace).
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

    /// Destructures this execution trace into the process’s final stack and advice states.
    pub fn into_outputs(self) -> (StackOutputs, AdviceProvider) {
        (self.stack_outputs, self.advice)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the index of the last row in the trace.
    fn last_step(&self) -> usize {
        self.length() - 1
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------
    #[cfg(feature = "std")]
    pub fn print(&self) {
        use miden_air::trace::TRACE_WIDTH;
        use miden_core::field::PrimeField64;

        let mut row = [ZERO; PADDED_TRACE_WIDTH];
        for i in 0..self.length() {
            self.main_trace.read_row_into(i, &mut row);
            std::println!(
                "{:?}",
                row.iter().take(TRACE_WIDTH).map(|v| v.as_canonical_u64()).collect::<Vec<_>>()
            );
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn get_column_range(&self, range: Range<usize>) -> Vec<Vec<Felt>> {
        self.main_trace.get_column_range(range)
    }

    pub fn build_aux_trace<E>(&self, rand_elements: &[E]) -> Option<ColMatrix<E>>
    where
        E: ExtensionField<Felt>,
    {
        let aux_columns =
            self.aux_trace_builders.build_aux_columns(&self.main_trace, rand_elements);

        Some(ColMatrix::new(aux_columns))
    }
}

// TRACE TRAIT IMPLEMENTATION
// ================================================================================================

// AUX TRACE BUILDERS
// ================================================================================================

impl AuxTraceBuilders {
    /// Builds auxiliary columns for all trace segments given the main trace and challenges.
    ///
    /// This is the internal column-major version used by the processor.
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

// PLONKY3 AUX TRACE BUILDER ADAPTER
// ================================================================================================
//
// The `AuxTraceBuilder` trait is defined in `miden-air` to avoid a circular dependency:
// `miden-prover-p3` needs aux trace building logic from `miden-processor`, but `miden-processor`
// already depends on `miden-air`. By defining the trait in `miden-air` and implementing it here,
// `miden-prover-p3` can depend on both crates and use the trait without creating a cycle.
//
// Additionally, Plonky3 uses row-major matrices while our existing aux trace building logic uses
// column-major format. This impl adapts between the two by converting the main trace from
// row-major to column-major, delegating to the existing logic, and converting the result back.

impl<EF: ExtensionField<Felt>> AuxTraceBuilder<EF> for AuxTraceBuilders {
    /// Builds auxiliary trace columns from a row-major main trace.
    ///
    /// This adapts the column-major `build_aux_columns` method to work with Plonky3's
    /// row-major format by converting the input and output accordingly.
    fn build_aux_columns(
        &self,
        main_trace: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> RowMajorMatrix<Felt> {
        let _span = tracing::info_span!("build_aux_columns_wrapper").entered();

        // Convert row-major to column-major MainTrace
        let main_trace_col_major = row_major_adapter::row_major_to_main_trace(main_trace);

        // Build auxiliary columns using column-major logic
        let aux_columns = self.build_aux_columns(&main_trace_col_major, challenges);

        // Convert column-major aux columns back to row-major
        row_major_adapter::aux_columns_to_row_major(aux_columns, main_trace.height())
    }
}
