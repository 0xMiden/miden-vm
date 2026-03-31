use alloc::vec::Vec;
#[cfg(any(test, feature = "testing"))]
use core::ops::Range;

use miden_air::{
    AirWitness, AuxBuilder, ProcessorAir, PublicInputs, debug,
    trace::{
        DECODER_TRACE_OFFSET, MainTrace, PADDED_TRACE_WIDTH, TRACE_WIDTH,
        decoder::{NUM_USER_OP_HELPERS, USER_OP_HELPERS_OFFSET},
    },
};
use miden_core::{crypto::hash::Blake3_256, serde::Serializable};

use crate::{
    Felt, MIN_STACK_DEPTH, Program, ProgramInfo, StackInputs, StackOutputs, Word, ZERO,
    fast::ExecutionOutput,
    field::{ExtensionField, QuadFelt},
    precompile::{PrecompileRequest, PrecompileTranscript},
    utils::{ColMatrix, Matrix, RowMajorMatrix},
};

pub(crate) mod utils;
use miden_air::trace::Challenges;
use utils::{AuxColumnBuilder, TraceFragment};

pub mod chiplets;
pub(crate) mod execution_tracer;

mod decoder;
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
    precompile_requests_digest: [u8; 32],
}

#[derive(Debug)]
pub(crate) struct TraceBuildOutput {
    stack_outputs: StackOutputs,
    final_pc_transcript: PrecompileTranscript,
    precompile_requests: Vec<PrecompileRequest>,
}

impl TraceBuildOutput {
    fn from_execution_output(execution_output: ExecutionOutput) -> Self {
        let ExecutionOutput {
            stack,
            mut advice,
            memory: _,
            final_pc_transcript,
        } = execution_output;

        Self {
            stack_outputs: stack,
            final_pc_transcript,
            precompile_requests: advice.take_precompile_requests(),
        }
    }

    fn stack_outputs(&self) -> &StackOutputs {
        &self.stack_outputs
    }

    fn final_precompile_transcript(&self) -> PrecompileTranscript {
        self.final_pc_transcript
    }

    fn precompile_requests_digest(&self) -> [u8; 32] {
        Blake3_256::hash(&self.precompile_requests.to_bytes()).into()
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
            precompile_requests_digest: trace_output.precompile_requests_digest(),
            trace_output,
            trace_generation_context,
            program_info,
        }
    }

    pub fn stack_outputs(&self) -> &StackOutputs {
        self.trace_output.stack_outputs()
    }

    pub fn precompile_requests(&self) -> &[PrecompileRequest] {
        &self.trace_output.precompile_requests
    }

    pub fn final_precompile_transcript(&self) -> PrecompileTranscript {
        self.trace_output.final_precompile_transcript()
    }

    pub fn trace_generation_context(&self) -> &TraceGenerationContext {
        &self.trace_generation_context
    }

    pub fn program_info(&self) -> &ProgramInfo {
        &self.program_info
    }

    #[cfg(any(test, feature = "testing"))]
    #[allow(dead_code)]
    pub(crate) fn into_parts(
        self,
    ) -> (TraceBuildOutput, TraceGenerationContext, ProgramInfo, [u8; 32]) {
        (
            self.trace_output,
            self.trace_generation_context,
            self.program_info,
            self.precompile_requests_digest,
        )
    }

    #[cfg(any(test, feature = "testing"))]
    #[allow(dead_code)]
    pub(crate) fn trace_generation_context_mut(&mut self) -> &mut TraceGenerationContext {
        &mut self.trace_generation_context
    }

    #[cfg(test)]
    pub(crate) fn from_parts(
        trace_output: TraceBuildOutput,
        trace_generation_context: TraceGenerationContext,
        program_info: ProgramInfo,
        precompile_requests_digest: [u8; 32],
    ) -> Self {
        Self {
            trace_output,
            trace_generation_context,
            program_info,
            precompile_requests_digest,
        }
    }
}

// VM EXECUTION TRACE
// ================================================================================================

/// Execution trace which is generated when a program is executed on the VM.
///
/// The trace consists of the following components:
/// - Main traces of System, Decoder, Operand Stack, Range Checker, and Chiplets.
/// - Auxiliary trace builders.
/// - Information about the program (program hash and the kernel).
/// - Information about execution outputs (stack state, deferred precompile requests, and the final
///   precompile transcript).
/// - Summary of trace lengths of the main trace components.
#[derive(Debug)]
pub struct ExecutionTrace {
    main_trace: MainTrace,
    aux_trace_builders: AuxTraceBuilders,
    program_info: ProgramInfo,
    stack_outputs: StackOutputs,
    precompile_requests: Vec<PrecompileRequest>,
    final_pc_transcript: PrecompileTranscript,
    trace_len_summary: TraceLenSummary,
}

impl ExecutionTrace {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    pub(crate) fn new_from_parts(
        program_info: ProgramInfo,
        trace_output: TraceBuildOutput,
        main_trace: MainTrace,
        aux_trace_builders: AuxTraceBuilders,
        trace_len_summary: TraceLenSummary,
    ) -> Self {
        let TraceBuildOutput {
            stack_outputs,
            final_pc_transcript,
            precompile_requests,
        } = trace_output;

        Self {
            main_trace,
            aux_trace_builders,
            program_info,
            stack_outputs,
            precompile_requests,
            final_pc_transcript,
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
            self.final_pc_transcript.state(),
        )
    }

    /// Returns the public values for this execution trace.
    pub fn to_public_values(&self) -> Vec<Felt> {
        self.public_inputs().to_elements()
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
        &self.precompile_requests
    }

    /// Moves all accumulated precompile requests out of the trace, leaving it empty.
    ///
    /// Intended for proof packaging, where requests are serialized into the proof and no longer
    /// needed in the trace after consumption.
    pub fn take_precompile_requests(&mut self) -> Vec<PrecompileRequest> {
        core::mem::take(&mut self.precompile_requests)
    }

    /// Returns the final precompile transcript after executing all precompile requests.
    pub fn final_precompile_transcript(&self) -> PrecompileTranscript {
        self.final_pc_transcript
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
            *result = self.main_trace.get(row, DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + i);
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

    /// Destructures this execution trace into the process's final stack outputs, deferred
    /// precompile requests, and final precompile transcript.
    pub fn into_outputs(self) -> (StackOutputs, Vec<PrecompileRequest>, PrecompileTranscript) {
        (self.stack_outputs, self.precompile_requests, self.final_pc_transcript)
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
        let public_inputs = self.public_inputs();
        let trace_matrix = self.to_row_major_matrix();

        let (public_values, kernel_felts) = public_inputs.to_air_inputs();
        let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];

        let aux_builder = self.aux_trace_builders();

        // Derive deterministic challenges by hashing public values with Poseidon2.
        // The 4-element digest maps directly to 2 QuadFelt challenges.
        let digest = crate::crypto::hash::Poseidon2::hash_elements(&public_values);
        let challenges =
            [QuadFelt::new([digest[0], digest[1]]), QuadFelt::new([digest[2], digest[3]])];

        let witness = AirWitness::new(&trace_matrix, &public_values, var_len_public_inputs);
        debug::check_constraints(&ProcessorAir, witness, &aux_builder, &challenges);
    }

    /// Returns the main trace as a row-major matrix for proving.
    ///
    /// Only includes the first [`TRACE_WIDTH`] columns (excluding padding columns added for
    /// Poseidon2 rate alignment), which is the width expected by the AIR.
    // TODO: the padding columns can be removed once we use the lifted-stark's virtual trace
    // alignment, which pads to the required rate width without materializing extra columns.
    pub fn to_row_major_matrix(&self) -> RowMajorMatrix<Felt> {
        let stored_w = self.main_trace.width();
        if stored_w == TRACE_WIDTH {
            return self.main_trace.to_row_major();
        }

        assert_eq!(stored_w, PADDED_TRACE_WIDTH);
        self.main_trace.to_row_major_stripped(TRACE_WIDTH)
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

// AUX TRACE BUILDERS
// ================================================================================================

#[derive(Debug, Clone)]
pub struct AuxTraceBuilders {
    pub(crate) decoder: decoder::AuxTraceBuilder,
    pub(crate) stack: stack::AuxTraceBuilder,
    pub(crate) range: range::AuxTraceBuilder,
    pub(crate) chiplets: chiplets::AuxTraceBuilder,
}

impl AuxTraceBuilders {
    /// Builds auxiliary columns for all trace segments given the main trace and challenges.
    ///
    /// This is the internal column-major version used by the processor.
    pub fn build_aux_columns<E>(&self, main_trace: &MainTrace, challenges: &[E]) -> Vec<Vec<E>>
    where
        E: ExtensionField<Felt>,
    {
        // Expand raw challenges (alpha, beta) into coefficient array once, then pass
        // the expanded challenges to all sub-builders.
        let challenges = Challenges::<E>::new(challenges[0], challenges[1]);

        let (decoder_cols, stack_cols, range_cols, chiplets_cols) = {
            let ((decoder_cols, stack_cols), (range_cols, chiplets_cols)) = rayon::join(
                || {
                    rayon::join(
                        || self.decoder.build_aux_columns(main_trace, &challenges),
                        || self.stack.build_aux_columns(main_trace, &challenges),
                    )
                },
                || {
                    rayon::join(
                        || self.range.build_aux_columns(main_trace, &challenges),
                        || {
                            let [a, b, c] =
                                self.chiplets.build_aux_columns(main_trace, &challenges);
                            vec![a, b, c]
                        },
                    )
                },
            );
            (decoder_cols, stack_cols, range_cols, chiplets_cols)
        };

        decoder_cols
            .into_iter()
            .chain(stack_cols)
            .chain(range_cols)
            .chain(chiplets_cols)
            .collect()
    }
}

// PLONKY3 AUX TRACE BUILDER
// ================================================================================================

impl<EF: ExtensionField<Felt>> AuxBuilder<Felt, EF> for AuxTraceBuilders {
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let _span = tracing::info_span!("build_aux_trace").entered();

        // Transpose the row-major main trace into column-major `MainTrace` needed by the
        // auxiliary trace builders. The last program row is the point where the clock
        // (column 0) stops incrementing.
        let main_for_aux = {
            let num_rows = main.height();
            // Find the last program row by binary search on the clock column.
            let clk0 = main.get(0, 0).expect("valid indices");
            let last_program_row = if num_rows <= 1 {
                0
            } else if main.get(num_rows - 1, 0).expect("valid indices")
                == clk0 + Felt::new((num_rows - 1) as u64)
            {
                num_rows - 1
            } else {
                let mut lo = 1usize;
                let mut hi = num_rows - 1;
                while lo < hi {
                    let mid = lo + (hi - lo) / 2;
                    let expected = clk0 + Felt::new(mid as u64);
                    if main.get(mid, 0).expect("valid indices") == expected {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                lo - 1
            };
            let transposed = main.transpose();
            MainTrace::from_transposed(transposed, RowIndex::from(last_program_row))
        };

        let aux_columns = self.build_aux_columns(&main_for_aux, challenges);
        assert!(!aux_columns.is_empty(), "aux columns should not be empty");

        let trace_len = main.height();
        let num_ef_cols = aux_columns.len();
        for col in &aux_columns {
            debug_assert_eq!(col.len(), trace_len, "aux column length must match main height");
        }

        let mut flat = Vec::with_capacity(trace_len * num_ef_cols);
        for col in &aux_columns {
            flat.extend_from_slice(col);
        }
        let aux_trace = RowMajorMatrix::new(flat, trace_len).transpose();

        // Extract the last row from the row-major aux trace for Fiat-Shamir.
        let last_row = aux_trace
            .row_slice(trace_len - 1)
            .expect("aux trace has at least one row")
            .to_vec();

        (aux_trace, last_row)
    }
}
