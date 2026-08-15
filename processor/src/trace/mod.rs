use alloc::vec::Vec;
#[cfg(any(test, feature = "testing"))]
use core::ops::Range;

use miden_air::{
    MidenMultiAir, ProverStatement, PublicInputs, StarkConfig, Statement, config, debug,
    trace::{MainTrace, decoder::NUM_USER_OP_HELPERS},
};
use miden_core::{
    deferred::{Digest, TRUE_DIGEST},
    program::ExecutionClaim,
};

use crate::{
    Felt, MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs, Word, ZERO,
    fast::ExecutionOutput, field::QuadFelt, utils::RowMajorMatrix,
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

pub(crate) use execution_tracer::TraceReplay;
pub use miden_air::trace::RowIndex;
pub use miden_core::deferred::PrecompileWitness;
pub use parallel::{CORE_TRACE_WIDTH, build_trace, build_trace_with_max_len};
// Re-exported for the streaming trace-build path
// (`FastProcessor::execute_and_build_trace_sync`), which is std-only; the buffered path
// uses `build_hasher_chiplet` and `MAX_TRACE_LEN` directly within `parallel`.
#[cfg(feature = "std")]
pub(crate) use parallel::{MAX_TRACE_LEN, build_hasher_chiplet, build_trace_with_prebuilt_hasher};
#[cfg(feature = "std")]
pub(crate) use trace_state::ResolvedHasherOp;
pub use utils::{ChipletsLengths, TraceLenSummary};

/// Complete in-memory witness produced by a traced program execution.
///
/// The processor constructs its VM witness and optional singleton precompile witness from the same
/// execution output, so they retain the same deferred root. The aggregate may contain private and
/// potentially large prover data.
#[derive(Debug)]
pub struct ExecutionWitness {
    vm: VmWitness,
    precompile: Option<PrecompileWitness>,
}

impl ExecutionWitness {
    pub(crate) fn from_execution(
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        execution_output: ExecutionOutput,
        trace: TraceReplay,
    ) -> Self {
        let ExecutionOutput {
            stack: stack_outputs,
            advice: _,
            memory: _,
            deferred_state: precompiles,
        } = execution_output;
        let precompile_root = precompiles.root();
        let vm = VmWitness {
            program_info,
            stack_inputs,
            stack_outputs,
            trace,
            precompile_root,
        };
        let precompile = (precompile_root != TRUE_DIGEST).then(|| {
            PrecompileWitness::new(precompiles)
                .expect("a non-TRUE execution root must produce a singleton precompile witness")
        });

        Self { vm, precompile }
    }

    /// Returns the public claim associated with this witness.
    pub fn claim(&self) -> ExecutionClaim {
        self.vm.claim()
    }

    /// Consumes this witness and returns its supported low-level proving components.
    ///
    /// The [`VmWitness`] can be passed to [`build_trace`]. The optional [`PrecompileWitness`] is
    /// present only when execution authenticated deferred precompile work.
    pub fn into_parts(self) -> (VmWitness, Option<PrecompileWitness>) {
        (self.vm, self.precompile)
    }
}

/// Witness required to materialize and prove a VM execution trace.
///
/// This potentially large value contains private replay data and is consumed by trace-building and
/// proving operations. The processor does not define a serialized representation for it.
#[derive(Debug)]
pub struct VmWitness {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    trace: TraceReplay,
    precompile_root: Digest,
}

impl VmWitness {
    /// Returns the public claim associated with this witness.
    pub fn claim(&self) -> ExecutionClaim {
        ExecutionClaim::from_program_info(
            self.program_info.clone(),
            self.stack_inputs,
            self.stack_outputs,
        )
    }

    /// Takes the hasher replay out, leaving an empty buffered one.
    ///
    /// The streaming path uses this to drop the replay's channel sender once execution has
    /// finished, so the concurrently running hasher builder sees its input stream end.
    #[cfg(feature = "std")]
    pub(crate) fn take_hasher_replay(&mut self) -> trace_state::HasherRequestReplay {
        core::mem::take(&mut self.trace.hasher_for_chiplet)
    }

    /// Returns the replay data captured during execution.
    #[cfg(any(test, feature = "testing"))]
    #[cfg_attr(all(feature = "testing", not(test)), expect(dead_code))]
    pub(crate) fn trace_replay(&self) -> &TraceReplay {
        &self.trace
    }

    // Kept for tests that force invalid replay data without widening the public API.
    #[cfg(any(test, feature = "testing"))]
    #[cfg_attr(all(feature = "testing", not(test)), expect(dead_code))]
    pub(crate) fn trace_replay_mut(&mut self) -> &mut TraceReplay {
        &mut self.trace
    }
}

// VM EXECUTION TRACE
// ================================================================================================

/// Execution trace which is generated when a program is executed on the VM.
///
/// The trace consists of the following components:
/// - Per-AIR trace matrices for Core, Chiplets, and Poseidon2Permutation.
/// - Information about the program (program hash and the kernel).
/// - Information about the initial and final stack states and authenticated precompile root.
/// - Summary of trace lengths of the main trace components.
#[derive(Debug)]
pub struct VmTrace {
    main_trace: MainTrace,
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    precompile_root: Digest,
    trace_len_summary: TraceLenSummary,
}

impl VmTrace {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    pub(crate) fn new_from_parts(
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        precompile_root: Digest,
        main_trace: MainTrace,
        trace_len_summary: TraceLenSummary,
    ) -> Self {
        Self {
            main_trace,
            program_info,
            stack_inputs,
            stack_outputs,
            precompile_root,
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
            self.stack_inputs,
            self.stack_outputs,
            self.precompile_root,
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

    /// Returns the authenticated root of the deferred precompile state.
    pub fn precompile_root(&self) -> Digest {
        self.precompile_root
    }

    /// Returns the owned stack outputs required for proof packaging.
    pub fn into_outputs(self) -> StackOutputs {
        self.stack_outputs
    }

    /// Returns the initial state of the top 16 stack registers.
    pub fn init_stack_state(&self) -> StackInputs {
        self.stack_inputs
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

    /// Returns a summary of the per-component trace lengths.
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
        let public_inputs = self.public_inputs();
        let (core_matrix, chiplets_matrix, poseidon2_matrix) = self.main_trace.to_air_matrices();

        let (public_values, aux_inputs) = public_inputs.to_air_inputs();

        let statement =
            Statement::<Felt, QuadFelt, _>::new(MidenMultiAir::new(), public_values, aux_inputs)
                .expect("valid statement inputs");
        let prover_statement =
            ProverStatement::new(statement, vec![core_matrix, chiplets_matrix, poseidon2_matrix])
                .expect("valid trace shapes");

        // A deterministic challenger seeds the debug constraint check; this is a local
        // constraint debugger, not a full proof transcript, so any fixed challenge set works.
        let config = config::poseidon2_config(config::pcs_params(), config::RELATION_DIGEST);
        debug::check_constraints(&prover_statement, config.challenger());
    }

    /// Splits the trace into the per-AIR matrices consumed by the multi-AIR proving path.
    pub fn to_air_matrices(
        &self,
    ) -> (RowMajorMatrix<Felt>, RowMajorMatrix<Felt>, RowMajorMatrix<Felt>) {
        self.main_trace.to_air_matrices()
    }

    /// Consuming variant for the proving hot path.
    pub fn into_air_matrices(
        self,
    ) -> (RowMajorMatrix<Felt>, RowMajorMatrix<Felt>, RowMajorMatrix<Felt>) {
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
