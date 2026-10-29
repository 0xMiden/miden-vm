use alloc::{format, string::String};
use core::borrow::BorrowMut;

use miden_air_definitions::vm::{
    CoreCols, TraceLenSummary,
    trace::{MainTrace, RowIndex},
};
use miden_core::{
    Felt,
    program::{ExecutionClaim, StackOutputs},
    proof::{ExecutionProof, HashFunction, PrecompileStatus, VmProof},
    utils::{Matrix, RowMajorMatrix},
};
use miden_processor::trace::VmTrace;
use miden_verifier::{VerificationError, VerificationOutcome, Verifier};
use miden_vm_stark::prover::prove;

/// Returns a mutable view of one core trace row.
pub fn core_row_mut(matrix: &mut RowMajorMatrix<Felt>, row: usize) -> &mut CoreCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow_mut()
}

/// Proof inputs shared by adversarial trace regression tests.
///
/// Scenario-specific fixtures own one of these and keep only their relevant row indices and
/// honest values alongside it.
pub struct ReproTrace {
    pub core: RowMajorMatrix<Felt>,
    chiplets: RowMajorMatrix<Felt>,
    eidos_compression: RowMajorMatrix<Felt>,
    and8: RowMajorMatrix<Felt>,
    program_info: miden_processor::ProgramInfo,
    init_stack: miden_processor::StackInputs,
    precompile_root: miden_core::deferred::DeferredRoot,
    outputs: StackOutputs,
    last_program_row: RowIndex,
    summary: TraceLenSummary,
}

impl ReproTrace {
    /// Captures the matrices and public inputs needed to prove mutations of `trace`.
    pub fn new(trace: &VmTrace) -> Self {
        let main = trace.main_trace();
        let (core, chiplets, eidos_compression, and8) = main.clone_air_matrices();
        Self {
            core,
            chiplets,
            eidos_compression,
            and8,
            program_info: trace.program_info().clone(),
            init_stack: trace.init_stack_state(),
            precompile_root: trace.precompile_root(),
            outputs: *trace.stack_outputs(),
            last_program_row: main.last_program_row(),
            summary: *trace.trace_len_summary(),
        }
    }

    pub fn outputs(&self) -> StackOutputs {
        self.outputs
    }

    /// Proves `core` against the honest public outputs and runs the resulting proof through the
    /// verifier. A low-level proving failure is unexpected in tests using this method.
    pub fn prove_and_verify(
        &self,
        core: RowMajorMatrix<Felt>,
    ) -> Result<VerificationOutcome, VerificationError> {
        self.prove_and_verify_with_outputs(core, self.outputs)
    }

    /// Proves and verifies the currently stored core matrix.
    pub fn prove_and_verify_current(&self) -> Result<VerificationOutcome, VerificationError> {
        self.prove_and_verify(self.core.clone())
    }

    /// Like [`Self::prove_and_verify`], but proves against caller-supplied public outputs.
    pub fn prove_and_verify_with_outputs(
        &self,
        core: RowMajorMatrix<Felt>,
        outputs: StackOutputs,
    ) -> Result<VerificationOutcome, VerificationError> {
        let proof = self
            .prove(
                core,
                self.chiplets.clone(),
                self.eidos_compression.clone(),
                self.and8.clone(),
                outputs,
            )
            .unwrap_or_else(|error| {
                panic!("the low-level prover should encode the forged trace: {error}")
            });
        self.verify(proof, outputs)
    }

    /// Proves and verifies caller-supplied AIR matrices while permitting lookup construction to
    /// reject an unbalanced adversarial trace. Other proving failures remain test failures.
    pub fn prove_and_verify_parts_allowing_lookup_rejection(
        &self,
        core: RowMajorMatrix<Felt>,
        chiplets: RowMajorMatrix<Felt>,
        eidos_compression: RowMajorMatrix<Felt>,
        and8: RowMajorMatrix<Felt>,
        outputs: StackOutputs,
    ) -> Result<VerificationOutcome, String> {
        let proof = match self.prove(core, chiplets, eidos_compression, and8, outputs) {
            Ok(proof) => proof,
            Err(error) => {
                assert!(
                    error.contains("external assertion 0 is non-zero"),
                    "unexpected prover failure: {error}"
                );
                return Err(format!("prover rejected an unbalanced lookup: {error}"));
            },
        };

        self.verify(proof, outputs)
            .map_err(|error| format!("verifier rejected: {error}"))
    }

    /// Runs the full proof pipeline while allowing the lookup construction itself to reject an
    /// unbalanced adversarial trace. Other proving failures remain test failures.
    pub fn prove_and_verify_allowing_lookup_rejection(
        &self,
        core: RowMajorMatrix<Felt>,
    ) -> Result<VerificationOutcome, String> {
        self.prove_and_verify_parts_allowing_lookup_rejection(
            core,
            self.chiplets.clone(),
            self.eidos_compression.clone(),
            self.and8.clone(),
            self.outputs,
        )
    }

    fn prove(
        &self,
        core: RowMajorMatrix<Felt>,
        chiplets: RowMajorMatrix<Felt>,
        eidos_compression: RowMajorMatrix<Felt>,
        and8: RowMajorMatrix<Felt>,
        outputs: StackOutputs,
    ) -> Result<VmProof, String> {
        let main = MainTrace::from_parts(
            core.values,
            chiplets.values,
            eidos_compression.values,
            and8.values,
            self.last_program_row,
        );
        // Rebuilt compression witnesses can have different heights from the honest fixture.
        let summary = TraceLenSummary::new(
            self.summary.core_rows(),
            self.summary.chiplets(),
            self.summary.eidos_compression_rows(),
            self.summary.byte_pair_lookup_rows(),
            [
                main.core_height(),
                main.chiplets_height(),
                main.eidos_compression_height(),
                main.byte_pair_lookup_height(),
            ],
        );
        let trace = VmTrace::new_from_parts(
            self.program_info.clone(),
            self.init_stack,
            outputs,
            self.precompile_root,
            main,
            summary,
        );
        prove(trace, HashFunction::Eidos, false).map_err(|error| format!("{error}"))
    }

    fn verify(
        &self,
        proof: VmProof,
        outputs: StackOutputs,
    ) -> Result<VerificationOutcome, VerificationError> {
        let proof = ExecutionProof::new(proof, PrecompileStatus::Empty);
        let claim =
            ExecutionClaim::from_program_info(self.program_info.clone(), self.init_stack, outputs);
        Verifier::new().verify(&claim, &proof)
    }
}
