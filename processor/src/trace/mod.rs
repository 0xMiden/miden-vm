use alloc::{format, sync::Arc, vec::Vec};
#[cfg(any(test, feature = "testing"))]
use core::ops::Range;

use miden_air::{
    MidenMultiAir, ProverStatement, PublicInputs, StarkConfig, Statement, config, debug,
    trace::{MainTrace, decoder::NUM_USER_OP_HELPERS},
};
use miden_core::{
    deferred::{DeferredState, DeferredStateWire, Digest, TRUE_DIGEST},
    program::ExecutionClaim,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
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
/// potentially large prover data. Its binary form is trusted replay data: sparse MAST node and
/// digest maps inside the trace replay are not checked against a source `MastForest` commitment;
/// see <https://github.com/0xMiden/miden-vm/issues/3303>.
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

/// Current wire format version for [`ExecutionWitness`] serialization.
///
/// The version is written as the first byte of every serialized witness. Deserialization only
/// accepts this exact value, so a future format change only needs to add a new accepted version
/// and keep the old readers where compatibility matters.
const EXECUTION_WITNESS_WIRE_VERSION: u8 = 1;

impl Serializable for ExecutionWitness {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        EXECUTION_WITNESS_WIRE_VERSION.write_into(target);
        self.vm.write_into(target);
        match &self.precompile {
            Some(precompile) => {
                target.write_u8(1);
                write_precompile_witness(precompile, target);
            },
            None => target.write_u8(0),
        }
    }
}

impl Deserializable for ExecutionWitness {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = u8::read_from(source)?;
        if version != EXECUTION_WITNESS_WIRE_VERSION {
            return Err(DeserializationError::InvalidValue(format!(
                "unsupported execution witness wire version {version} (expected \
                 {EXECUTION_WITNESS_WIRE_VERSION})"
            )));
        }
        let vm = VmWitness::read_from(source)?;
        let precompile = match source.read_u8()? {
            0 => {
                if vm.precompile_root != TRUE_DIGEST {
                    return Err(DeserializationError::InvalidValue(
                        "VM witness claims deferred work but no precompile witness is present"
                            .into(),
                    ));
                }
                None
            },
            1 => {
                let witness = read_precompile_witness(source)?;
                // `read_precompile_witness` only produces singleton witnesses, but do not index
                // blindly: keep deserialization panic-free even if that invariant changes.
                let [witness_root] = witness.roots() else {
                    return Err(DeserializationError::InvalidValue(
                        "expected a singleton precompile witness".into(),
                    ));
                };
                if *witness_root != vm.precompile_root {
                    return Err(DeserializationError::InvalidValue(
                        "precompile witness root does not match the VM witness precompile root"
                            .into(),
                    ));
                }
                Some(witness)
            },
            tag => {
                return Err(DeserializationError::InvalidValue(format!(
                    "invalid precompile witness option tag {tag}"
                )));
            },
        };
        Ok(Self { vm, precompile })
    }
}

/// Witness required to materialize and prove a VM execution trace.
///
/// This potentially large value contains private replay data and is consumed by trace-building and
/// proving operations. Its binary form is trusted replay data: sparse MAST node and digest maps
/// inside the trace replay are not checked against a source `MastForest` commitment; see
/// <https://github.com/0xMiden/miden-vm/issues/3303>.
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

impl Serializable for VmWitness {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.program_info.write_into(target);
        self.stack_inputs.write_into(target);
        self.stack_outputs.write_into(target);
        self.trace.write_into(target);
        self.precompile_root.write_into(target);
    }
}

impl Deserializable for VmWitness {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            program_info: ProgramInfo::read_from(source)?,
            stack_inputs: StackInputs::read_from(source)?,
            stack_outputs: StackOutputs::read_from(source)?,
            trace: TraceReplay::read_from(source)?,
            precompile_root: Digest::read_from(source)?,
        })
    }
}

/// Writes a singleton precompile witness as its ordered roots followed by its canonical deferred
/// wire.
fn write_precompile_witness<W: ByteWriter>(witness: &PrecompileWitness, target: &mut W) {
    let roots = witness.roots();
    debug_assert_eq!(roots.len(), 1, "only singleton precompile witnesses are serializable");
    target.write_usize(roots.len());
    for root in roots {
        root.write_into(target);
    }
    let deferred_wire = witness
        .state()
        .to_wire()
        .expect("deferred state must serialize to canonical wire");
    deferred_wire.write_into(target);
}

/// Reads a singleton precompile witness written by [`write_precompile_witness`].
fn read_precompile_witness<R: ByteReader>(
    source: &mut R,
) -> Result<PrecompileWitness, DeserializationError> {
    let roots = Vec::<Digest>::read_from(source)?;
    if roots.len() != 1 {
        return Err(DeserializationError::InvalidValue(
            "expected a singleton precompile witness".into(),
        ));
    }
    let deferred_wire = DeferredStateWire::read_from(source)?;
    let deferred_state =
        DeferredState::from_wire(Arc::new(miden_precompiles::registry()), &deferred_wire).map_err(
            |err| DeserializationError::InvalidValue(format!("invalid deferred state: {err}")),
        )?;

    let witness = PrecompileWitness::new(deferred_state).map_err(|err| {
        DeserializationError::InvalidValue(format!("invalid precompile witness: {err}"))
    })?;
    if witness.roots() != roots.as_slice() {
        return Err(DeserializationError::InvalidValue(
            "precompile witness roots do not match its deferred state".into(),
        ));
    }
    Ok(witness)
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

#[cfg(test)]
mod wire_tests {
    use miden_assembly::Assembler;
    use miden_core::deferred::TRUE_DIGEST;

    use super::{Deserializable, ExecutionWitness, Serializable};
    use crate::{DefaultHost, FastProcessor, StackInputs};

    fn deferred_witness_bytes() -> alloc::vec::Vec<u8> {
        let program = Assembler::default()
            .assemble_program("program", "begin log_deferred end")
            .expect("program should compile")
            .unwrap_program();
        let mut host = DefaultHost::default();
        let witness = FastProcessor::new(StackInputs::default())
            .execute_for_proving_sync(&program, &mut host)
            .expect("execution should produce a witness");
        witness.to_bytes()
    }

    #[test]
    fn witness_wire_rejects_unsupported_version() {
        let mut bytes = deferred_witness_bytes();
        assert!(ExecutionWitness::read_from_bytes(&bytes).is_ok());

        // The first byte of the wire is the format version; any other value must be rejected
        // before any payload is parsed.
        bytes[0] = bytes[0].wrapping_add(1);
        let err = ExecutionWitness::read_from_bytes(&bytes)
            .expect_err("witness with an unknown wire version should be rejected");
        assert!(
            format!("{err:?}").contains("unsupported execution witness wire version"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn witness_wire_rejects_mismatched_precompile_root() {
        let bytes = deferred_witness_bytes();
        let restored = ExecutionWitness::read_from_bytes(&bytes).expect("witness round trip");
        let (vm, precompile) = restored.into_parts();
        let precompile = precompile.expect("deferred execution should carry a precompile witness");
        assert_ne!(vm.precompile_root, TRUE_DIGEST);

        // Tamper only the VM-side precompile root and re-serialize: the two halves of the wire
        // no longer describe the same execution, so deserialization must reject them.
        let tampered = ExecutionWitness {
            vm: super::VmWitness { precompile_root: TRUE_DIGEST, ..vm },
            precompile: Some(precompile),
        };
        let err = ExecutionWitness::read_from_bytes(&tampered.to_bytes())
            .expect_err("tampered witness should be rejected");
        assert!(
            format!("{err:?}")
                .contains("precompile witness root does not match the VM witness precompile root"),
            "unexpected error: {err:?}"
        );

        // Sanity: the untampered wire still round-trips.
        assert!(ExecutionWitness::read_from_bytes(&bytes).is_ok());
    }

    #[test]
    fn witness_wire_rejects_missing_precompile_witness() {
        let bytes = deferred_witness_bytes();
        let restored = ExecutionWitness::read_from_bytes(&bytes).expect("witness round trip");
        let (vm, precompile) = restored.into_parts();
        assert!(precompile.is_some(), "deferred execution should carry a precompile witness");

        // Drop only the precompile witness while the VM side still claims deferred work: the
        // wire must not validate as a complete execution.
        let stripped = ExecutionWitness { vm, precompile: None };
        let err = ExecutionWitness::read_from_bytes(&stripped.to_bytes())
            .expect_err("witness without its precompile half should be rejected");
        assert!(
            format!("{err:?}")
                .contains("VM witness claims deferred work but no precompile witness is present"),
            "unexpected error: {err:?}"
        );
    }
}
