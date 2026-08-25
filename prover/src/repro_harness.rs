use alloc::{format, string::String, vec::Vec};
use core::borrow::BorrowMut;

use miden_air::{CoreCols, PublicInputs};
use miden_core::{
    Felt,
    program::{ExecutionClaim, StackOutputs},
    proof::{ExecutionProof, HashFunction, StarkProof, VmProof},
    utils::{Matrix, RowMajorMatrix},
};
use miden_processor::trace::VmTrace;
use miden_verifier::{VerificationError, VerificationOutcome, Verifier};

use crate::{config, prove_stark};

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
    poseidon2: RowMajorMatrix<Felt>,
    program_info: miden_processor::ProgramInfo,
    init_stack: miden_processor::StackInputs,
    precompile_root: miden_core::deferred::DeferredRoot,
    outputs: StackOutputs,
}

impl ReproTrace {
    /// Captures the matrices and public inputs needed to prove mutations of `trace`.
    pub fn new(trace: &VmTrace) -> Self {
        let main = trace.main_trace();
        let (core, chiplets, poseidon2) = main.to_air_matrices();
        Self {
            core,
            chiplets,
            poseidon2,
            program_info: trace.program_info().clone(),
            init_stack: trace.init_stack_state(),
            precompile_root: trace.precompile_root(),
            outputs: *trace.stack_outputs(),
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
        let proof_bytes = self.prove(core, outputs).unwrap_or_else(|error| {
            panic!("the low-level prover should encode the forged trace: {error}")
        });
        self.verify(proof_bytes, outputs)
    }

    /// Runs the full proof pipeline while allowing the lookup construction itself to reject an
    /// unbalanced adversarial trace. Other proving failures remain test failures.
    pub fn prove_and_verify_allowing_lookup_rejection(
        &self,
        core: RowMajorMatrix<Felt>,
    ) -> Result<VerificationOutcome, String> {
        let proof_bytes = match self.prove(core, self.outputs) {
            Ok(bytes) => bytes,
            Err(error) => {
                assert!(
                    error.contains("external assertion 0 is non-zero"),
                    "unexpected prover failure: {error}"
                );
                return Err(format!("prover rejected an unbalanced lookup: {error}"));
            },
        };

        self.verify(proof_bytes, self.outputs)
            .map_err(|error| format!("verifier rejected: {error}"))
    }

    fn prove(&self, core: RowMajorMatrix<Felt>, outputs: StackOutputs) -> Result<Vec<u8>, String> {
        let public_inputs = PublicInputs::new(
            self.program_info.clone(),
            self.init_stack,
            outputs,
            self.precompile_root,
        );
        let (public_values, aux_inputs) = public_inputs.to_air_inputs();
        let config = config::poseidon2_config(config::pcs_params(), config::RELATION_DIGEST);
        prove_stark(
            &config,
            core,
            self.chiplets.clone(),
            self.poseidon2.clone(),
            &public_values,
            &aux_inputs,
        )
        .map_err(|error| format!("{error}"))
    }

    fn verify(
        &self,
        proof_bytes: Vec<u8>,
        outputs: StackOutputs,
    ) -> Result<VerificationOutcome, VerificationError> {
        let proof = ExecutionProof::Complete {
            vm: VmProof {
                proof: StarkProof::new(proof_bytes, HashFunction::Poseidon2),
                precompile_root: self.precompile_root,
            },
            precompile: None,
        };
        let claim =
            ExecutionClaim::from_program_info(self.program_info.clone(), self.init_stack, outputs);
        Verifier::new().verify(&claim, &proof)
    }
}
