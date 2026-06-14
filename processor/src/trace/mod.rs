use alloc::vec::Vec;
#[cfg(any(test, feature = "testing"))]
use core::ops::Range;

use miden_air::{
    MidenMultiAir, ProverStatement, PublicInputs, StarkConfig, Statement, config, debug,
    trace::{MainTrace, decoder::NUM_USER_OP_HELPERS},
};
use miden_core::{crypto::hash::Blake3_256, serde::Serializable};

use crate::{
    Felt, MIN_STACK_DEPTH, Program, ProgramInfo, StackInputs, StackOutputs, Word, ZERO,
    fast::ExecutionOutput,
    field::QuadFelt,
    precompile::{PrecompileRequest, PrecompileTranscript},
    utils::RowMajorMatrix,
};

pub(crate) mod utils;
use utils::ChipletTraceFragment;

pub mod chiplets;
pub(crate) mod execution_tracer;

mod block_stack;
mod parallel;
mod range;
mod stack;
mod trace_state;

#[cfg(test)]
mod tests;

// RE-EXPORTS
// ================================================================================================

pub use execution_tracer::TraceGenerationContext;
pub use miden_air::trace::RowIndex;
pub use parallel::{CORE_TRACE_WIDTH, build_trace, build_trace_with_max_len};
pub use utils::{ChipletsLengths, TraceLenSummary};

/// Inputs required to build an execution trace from pre-executed data.
#[derive(Debug)]
pub struct TraceBuildInputs {
    trace_output: TraceBuildOutput,
    trace_generation_context: TraceGenerationContext,
    program_info: ProgramInfo,
}

#[derive(Debug)]
pub(crate) struct TraceBuildOutput {
    stack_outputs: StackOutputs,
    final_precompile_transcript: PrecompileTranscript,
    precompile_requests: Vec<PrecompileRequest>,
    precompile_requests_digest: [u8; 32],
}

impl TraceBuildOutput {
    fn from_execution_output(execution_output: ExecutionOutput) -> Self {
        let ExecutionOutput {
            stack,
            mut advice,
            memory: _,
            final_precompile_transcript,
        } = execution_output;

        Self {
            stack_outputs: stack,
            final_precompile_transcript,
            precompile_requests: advice.take_precompile_requests(),
            precompile_requests_digest: [0; 32],
        }
        .with_precompile_requests_digest()
    }

    fn with_precompile_requests_digest(mut self) -> Self {
        self.precompile_requests_digest =
            Blake3_256::hash(&self.precompile_requests.to_bytes()).into();
        self
    }

    fn has_matching_precompile_requests_digest(&self) -> bool {
        let expected_digest: [u8; 32] =
            Blake3_256::hash(&self.precompile_requests.to_bytes()).into();
        self.precompile_requests_digest == expected_digest
    }
}

impl TraceBuildInputs {
    pub(crate) fn from_execution(
        program: &Program,
        execution_output: ExecutionOutput,
        trace_generation_context: TraceGenerationContext,
    ) -> Self {
        let trace_output = TraceBuildOutput::from_execution_output(execution_output);
        let program_info = program.to_info();
        Self {
            trace_output,
            trace_generation_context,
            program_info,
        }
    }

    /// Returns the stack outputs captured for the execution being replayed.
    pub fn stack_outputs(&self) -> &StackOutputs {
        &self.trace_output.stack_outputs
    }

    /// Returns deferred precompile requests generated during execution.
    pub fn precompile_requests(&self) -> &[PrecompileRequest] {
        &self.trace_output.precompile_requests
    }

    /// Returns the final precompile transcript observed during execution.
    pub fn final_precompile_transcript(&self) -> &PrecompileTranscript {
        &self.trace_output.final_precompile_transcript
    }

    /// Returns the program info captured for the execution being replayed.
    pub fn program_info(&self) -> &ProgramInfo {
        &self.program_info
    }

    // Kept for mismatch and edge-case tests that mutate replay inputs directly.
    #[cfg(any(test, feature = "testing"))]
    #[cfg_attr(all(feature = "testing", not(test)), expect(dead_code))]
    pub(crate) fn into_parts(self) -> (TraceBuildOutput, TraceGenerationContext, ProgramInfo) {
        (self.trace_output, self.trace_generation_context, self.program_info)
    }

    #[cfg(any(test, feature = "testing"))]
    /// Returns the trace replay context captured during execution.
    pub fn trace_generation_context(&self) -> &TraceGenerationContext {
        &self.trace_generation_context
    }

    // Kept for tests that force invalid replay contexts without widening the public API.
    #[cfg(any(test, feature = "testing"))]
    #[cfg_attr(all(feature = "testing", not(test)), expect(dead_code))]
    pub(crate) fn trace_generation_context_mut(&mut self) -> &mut TraceGenerationContext {
        &mut self.trace_generation_context
    }

    #[cfg(test)]
    pub(crate) fn from_parts(
        trace_output: TraceBuildOutput,
        trace_generation_context: TraceGenerationContext,
        program_info: ProgramInfo,
    ) -> Self {
        Self {
            trace_output,
            trace_generation_context,
            program_info,
        }
    }
}

// VM EXECUTION TRACE
// ================================================================================================

/// Execution trace which is generated when a program is executed on the VM.
///
/// The trace consists of the following components:
/// - Main traces of System, Decoder, Operand Stack, Range Checker, and Chiplets.
/// - Information about the program (program hash and the kernel).
/// - Information about execution outputs (stack state, deferred precompile requests, and the final
///   precompile transcript).
/// - Summary of trace lengths of the main trace components.
#[derive(Debug)]
pub struct ExecutionTrace {
    main_trace: MainTrace,
    program_info: ProgramInfo,
    stack_outputs: StackOutputs,
    precompile_requests: Vec<PrecompileRequest>,
    final_precompile_transcript: PrecompileTranscript,
    trace_len_summary: TraceLenSummary,
}

impl ExecutionTrace {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    pub(crate) fn new_from_parts(
        program_info: ProgramInfo,
        trace_output: TraceBuildOutput,
        main_trace: MainTrace,
        trace_len_summary: TraceLenSummary,
    ) -> Self {
        let TraceBuildOutput {
            stack_outputs,
            final_precompile_transcript,
            precompile_requests,
            ..
        } = trace_output;

        Self {
            main_trace,
            program_info,
            stack_outputs,
            precompile_requests,
            final_precompile_transcript,
            trace_len_summary,
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

    /// Returns the public inputs for this execution trace.
    pub fn public_inputs(&self) -> PublicInputs {
        PublicInputs::new(
            self.program_info.clone(),
            self.init_stack_state(),
            self.stack_outputs,
            self.final_precompile_transcript.state(),
        )
    }

    /// Returns the public values for this execution trace.
    pub fn to_public_values(&self) -> Vec<Felt> {
        self.public_inputs().to_elements()
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
        &self.precompile_requests
    }

    /// Returns the final precompile transcript observed during execution.
    pub fn final_precompile_transcript(&self) -> PrecompileTranscript {
        self.final_precompile_transcript
    }

    /// Returns the owned execution outputs required for proof packaging.
    pub fn into_outputs(self) -> (StackOutputs, Vec<PrecompileRequest>, PrecompileTranscript) {
        (self.stack_outputs, self.precompile_requests, self.final_precompile_transcript)
    }

    /// Returns the initial state of the top 16 stack registers.
    pub fn init_stack_state(&self) -> StackInputs {
        let mut result = [ZERO; MIN_STACK_DEPTH];
        let row = RowIndex::from(0_u32);
        for (i, result) in result.iter_mut().enumerate() {
            *result = self.main_trace.stack_element(i, row);
        }
        result.into()
    }

    /// Returns the final state of the top 16 stack registers.
    pub fn last_stack_state(&self) -> StackOutputs {
        let last_step = RowIndex::from(self.last_step());
        let mut result = [ZERO; MIN_STACK_DEPTH];
        for (i, result) in result.iter_mut().enumerate() {
            *result = self.main_trace.stack_element(i, last_step);
        }
        result.into()
    }

    /// Returns helper registers state at the specified `clk` of the VM
    pub fn get_user_op_helpers_at(&self, clk: u32) -> [Felt; NUM_USER_OP_HELPERS] {
        let mut result = [ZERO; NUM_USER_OP_HELPERS];
        let row = RowIndex::from(clk);
        for (i, result) in result.iter_mut().enumerate() {
            *result = self.main_trace.helper_register(i, row);
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

    // DEBUG CONSTRAINT CHECKING
    // --------------------------------------------------------------------------------------------

    /// Validates this execution trace against all AIR constraints without generating a STARK
    /// proof.
    ///
    /// This is the recommended way to test trace correctness. It is much faster than full STARK
    /// proving and provides better error diagnostics (panics on the first constraint violation
    /// with the instance and row index).
    ///
    /// # Panics
    ///
    /// Panics if any AIR constraint evaluates to nonzero.
    pub fn check_constraints(&self) {
        let (core_matrix, chiplets_matrix, blakeg_compression_matrix, and8_lookup_matrix) =
            self.main_trace.to_air_matrices();
        let (public_values, kernel_felts) = self.public_inputs().to_air_inputs();

        let statement: Statement<Felt, QuadFelt, MidenMultiAir> =
            Statement::new(MidenMultiAir::new(), public_values, kernel_felts)
                .expect("statement construction failed");
        let prover_statement = ProverStatement::new(
            statement,
            vec![core_matrix, chiplets_matrix, blakeg_compression_matrix, and8_lookup_matrix],
        )
        .expect("prover statement construction failed");

        let config = config::poseidon2_config(config::pcs_params());
        debug::check_constraints(&prover_statement, config.challenger());
    }

    /// Splits the trace into the per-AIR matrices consumed by the multi-AIR prover.
    pub fn to_air_matrices(
        &self,
    ) -> (
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
    ) {
        self.main_trace.to_air_matrices()
    }

    /// Consuming variant for the proving hot path: moves the row-major buffers.
    pub fn into_air_matrices(
        self,
    ) -> (
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
    ) {
        self.main_trace.into_air_matrices()
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the index of the last row in the Core trace.
    fn last_step(&self) -> usize {
        self.main_trace.core_height() - 1
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn get_column_range(&self, range: Range<usize>) -> Vec<Vec<Felt>> {
        self.main_trace.get_column_range(range)
    }
}
