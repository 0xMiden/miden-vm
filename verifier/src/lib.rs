#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{boxed::Box, sync::Arc};

use miden_air::{MidenMultiAir, PublicInputs, Statement, config};
use miden_core::{
    Felt,
    deferred::{DEFAULT_MAX_DEFERRED_ELEMENTS, TRUE_DIGEST},
    field::QuadFelt,
};
use miden_crypto::stark::{
    StarkConfig, VerifierInstance, lmcs::Lmcs, proof::StarkProofData, verifier::VerifierError,
};
use serde::de::DeserializeOwned;
use serde_wincode::SerdeCompat;

const MAX_STARK_PROOF_BYTES: usize = 64 * 1024 * 1024;

// RE-EXPORTS
// ================================================================================================
mod exports {
    pub use miden_core::{
        Word,
        deferred::{DeferredState, IntegrityError},
        program::{KernelDescriptor, ProgramInfo, StackInputs, StackOutputs},
        proof::{DeferredProof, ExecutionProof, HashFunction, StarkProof},
    };
    pub mod math {
        pub use miden_core::Felt;
    }
}
pub use exports::*;

// VERIFIER
// ================================================================================================

/// Configurable verifier for Miden execution proofs.
///
/// [`Verifier::verify`] performs final verification and rejects wire-backed partial proofs.
/// [`Verifier::verify_partial`] accepts wire-backed partial proofs, rehydrates their deferred
/// state using the standard precompile registry, verifies the Miden VM proof against the hydrated
/// root, and returns the Miden VM security level with the hydrated state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verifier {
    max_deferred_elements: usize,
}

impl Default for Verifier {
    fn default() -> Self {
        Self {
            max_deferred_elements: DEFAULT_MAX_DEFERRED_ELEMENTS,
        }
    }
}

impl Verifier {
    /// Creates a verifier with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates the deferred-state element budget used by [`Self::verify_partial`].
    pub const fn with_max_deferred_elements(mut self, max_deferred_elements: usize) -> Self {
        self.max_deferred_elements = max_deferred_elements;
        self
    }

    /// Returns the security level of the final proof if the specified program was executed
    /// correctly against the specified inputs and outputs.
    ///
    /// If the proof contains STARK-backed precompile VM proof material, both the precompile VM
    /// proof and the Miden VM proof are verified, and the returned security level is the minimum
    /// of the verified proof security levels. If no precompile claims were produced, only the
    /// Miden VM proof is verified.
    ///
    /// Stack inputs are expected to be ordered as if they would be pushed onto the stack one by
    /// one. Thus, their expected order on the stack will be the reverse of the order in which
    /// they are provided, and the last value in the `stack_inputs` slice is expected to be the
    /// value at the top of the stack.
    ///
    /// Stack outputs are expected to be ordered as if they would be popped off the stack one by
    /// one. Thus, the value at the top of the stack is expected to be in the first position of
    /// the `stack_outputs` slice, and the order of the rest of the output elements will also
    /// match the order on the stack. This is the reverse of the order of the `stack_inputs`
    /// slice.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The provided proof does not prove a correct execution of the program.
    /// - The proof carries wire-backed deferred proof material, which is a partial/delegable form.
    /// - The proof's STARK-backed precompile VM proof, if present, does not verify against its
    ///   public root.
    pub fn verify(
        &self,
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        proof: ExecutionProof,
    ) -> Result<u32, VerificationError> {
        let miden_security_level = proof.security_level();
        let (final_deferred_root, precompile_security_level) =
            resolve_final_deferred_root(proof.deferred_proof())?;

        verify_stark(
            program_info,
            stack_inputs,
            stack_outputs,
            final_deferred_root,
            proof.miden_proof(),
        )?;

        Ok(precompile_security_level
            .map(|level| miden_security_level.min(level))
            .unwrap_or(miden_security_level))
    }

    /// Verifies a partial proof and returns its Miden VM security level and hydrated deferred
    /// state.
    ///
    /// Partial verification accepts only wire-backed deferred proof material. The wire is hydrated
    /// using the standard precompile registry and this verifier's deferred-element budget, then the
    /// Miden VM STARK proof is verified against the hydrated state's root.
    ///
    /// If no budget override was configured with [`Self::with_max_deferred_elements`], partial
    /// verification uses [`DEFAULT_MAX_DEFERRED_ELEMENTS`].
    ///
    /// # Errors
    /// Returns an error if:
    /// - The proof is not wire-backed partial proof material.
    /// - The wire cannot be hydrated under the standard precompile registry and configured budget.
    /// - The provided proof does not prove a correct execution of the program against the hydrated
    ///   deferred root.
    pub fn verify_partial(
        &self,
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        proof: ExecutionProof,
    ) -> Result<(u32, DeferredState), VerificationError> {
        let security_level = proof.security_level();
        let deferred_state =
            hydrate_deferred_state(proof.deferred_proof(), self.max_deferred_elements)?;

        verify_stark(
            program_info,
            stack_inputs,
            stack_outputs,
            deferred_state.root(),
            proof.miden_proof(),
        )?;

        Ok((security_level, deferred_state))
    }
}

/// Returns the security level of the final proof if the specified program was executed correctly
/// against the specified inputs and outputs.
///
/// This is a compatibility shim for `Verifier::default().verify(...)`.
///
/// Specifically, verifies that if a program with the specified `program_hash` is executed against
/// the provided `stack_inputs` and some secret inputs, the result is equal to the `stack_outputs`.
///
/// Stack inputs are expected to be ordered as if they would be pushed onto the stack one by one.
/// Thus, their expected order on the stack will be the reverse of the order in which they are
/// provided, and the last value in the `stack_inputs` slice is expected to be the value at the top
/// of the stack.
///
/// Stack outputs are expected to be ordered as if they would be popped off the stack one by one.
/// Thus, the value at the top of the stack is expected to be in the first position of the
/// `stack_outputs` slice, and the order of the rest of the output elements will also match the
/// order on the stack. This is the reverse of the order of the `stack_inputs` slice.
///
/// # Errors
/// Returns an error if:
/// - The provided proof does not prove a correct execution of the program.
/// - The proof carries wire-backed deferred proof material, which is a partial/delegable form.
/// - The proof's STARK-backed deferred proof, if present, does not verify against its public root.
#[deprecated(since = "0.25.0", note = "use Verifier::new().verify(...) instead")]
pub fn verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
) -> Result<u32, VerificationError> {
    Verifier::default().verify(program_info, stack_inputs, stack_outputs, proof)
}

// HELPER FUNCTIONS
// ================================================================================================

fn resolve_final_deferred_root(
    deferred_proof: &DeferredProof,
) -> Result<(Word, Option<u32>), VerificationError> {
    match deferred_proof {
        DeferredProof::Empty => Ok((TRUE_DIGEST, None)),
        DeferredProof::Wire(_) => Err(VerificationError::UnsupportedDeferredProof),
        DeferredProof::Stark { proof, .. } => {
            let root = miden_precompiles_prover::session::verify_deferred(deferred_proof)?;
            Ok((root, Some(stark_security_level(proof))))
        },
    }
}

fn hydrate_deferred_state(
    deferred_proof: &DeferredProof,
    max_deferred_elements: usize,
) -> Result<DeferredState, VerificationError> {
    match deferred_proof {
        DeferredProof::Wire(wire) => Ok(DeferredState::from_wire(
            Arc::new(miden_precompiles::registry()),
            wire,
            max_deferred_elements,
        )?),
        DeferredProof::Empty | DeferredProof::Stark { .. } => {
            Err(VerificationError::UnsupportedDeferredProof)
        },
    }
}

fn stark_security_level(_proof: &StarkProof) -> u32 {
    // Mirrors `ExecutionProof::security_level` until the STARK security estimator is available.
    96
}

fn verify_stark(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    final_deferred_root: Word,
    stark_proof: &StarkProof,
) -> Result<(), VerificationError> {
    let program_hash = *program_info.program_hash();

    let pub_inputs =
        PublicInputs::new(program_info, stack_inputs, stack_outputs, final_deferred_root);
    let (public_values, aux_inputs) = pub_inputs.to_air_inputs();

    let hash_fn = stark_proof.hash_fn();
    let proof_bytes = stark_proof.bytes();
    let params = config::pcs_params();
    match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::blake3_256_config(params);
            verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
        },
        HashFunction::Rpo256 => {
            let config = config::rpo_config(params);
            verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
        },
        HashFunction::Rpx256 => {
            let config = config::rpx_config(params);
            verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
        },
        HashFunction::Poseidon2 => {
            let config = config::poseidon2_config(params);
            verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
        },
        HashFunction::Keccak => {
            let config = config::keccak_config(params);
            verify_stark_proof(&config, &public_values, &aux_inputs, proof_bytes)
        },
    }
    .map_err(|e| VerificationError::StarkVerificationError(program_hash, Box::new(e)))?;

    Ok(())
}

// ERRORS
// ================================================================================================

/// Errors that can occur during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("failed to verify STARK proof for program with hash {0}")]
    StarkVerificationError(Word, #[source] Box<StarkVerificationError>),
    #[error("deferred-DAG integrity check failed: {0}")]
    DeferredIntegrity(#[from] IntegrityError),
    #[error("failed to verify STARK-backed deferred proof: {0}")]
    DeferredStarkVerification(#[from] miden_precompiles_prover::session::VerifyError),
    #[error("deferred proof form is not supported by this verification mode")]
    UnsupportedDeferredProof,
}

// STARK PROOF VERIFICATION
// ================================================================================================

/// Errors that can occur during low-level STARK proof verification.
#[derive(Debug, thiserror::Error)]
pub enum StarkVerificationError {
    #[error("failed to deserialize proof: {0}")]
    Deserialization(#[from] wincode::error::ReadError),
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    #[error(transparent)]
    Verifier(#[from] VerifierError),
}

/// Verifies a multi-AIR STARK proof for the given (Core, Chiplets) split.
///
/// Pre-seeds the challenger with protocol parameters, AIR public values, and statement
/// `aux_inputs` (program hash, final deferred root, and kernel-procedure digests). Then delegates
/// to the lifted multi-AIR verifier.
fn verify_stark_proof<SC>(
    config: &SC,
    public_values: &[Felt],
    aux_inputs: &[Felt],
    proof_bytes: &[u8],
) -> Result<(), StarkVerificationError>
where
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: DeserializeOwned,
{
    if proof_bytes.len() > MAX_STARK_PROOF_BYTES {
        return Err(StarkVerificationError::ProofTooLarge {
            size: proof_bytes.len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof: StarkProofData<Felt, QuadFelt, SC> = <SerdeCompat<
        StarkProofData<Felt, QuadFelt, SC>,
    > as wincode::config::Deserialize<_>>::deserialize(
        proof_bytes, proof_encoding_config
    )?;

    let mut challenger = config.challenger();
    config::observe_protocol_params(&mut challenger);

    // `air_inputs` are the public values read by the AIRs (stack i/o); `aux_inputs` are the
    // statement inputs read during observation/boundary correction. The lifted verifier absorbs
    // both into Fiat-Shamir internally, and derives the multi-AIR ordering deterministically from
    // the proof's per-AIR trace heights.
    let statement = Statement::<Felt, QuadFelt, _>::new(
        MidenMultiAir::new(),
        public_values.to_vec(),
        aux_inputs.to_vec(),
    )
    .map_err(|e| StarkVerificationError::Verifier(VerifierError::from(e)))?;

    VerifierInstance::new(config, &statement, None)
        .expect("Miden AIRs declare no preprocessed columns")
        .verify(&proof, challenger)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::deferred::DeferredStateWire;

    use super::*;

    #[test]
    fn final_deferred_root_resolution_accepts_empty_rejects_wire_and_verifies_stark() {
        let (root, security_level) = resolve_final_deferred_root(&DeferredProof::Empty).unwrap();
        assert_eq!(root, TRUE_DIGEST);
        assert_eq!(security_level, None);

        let wire = DeferredProof::wire(DeferredStateWire::default());
        let err = resolve_final_deferred_root(&wire).unwrap_err();
        assert!(
            matches!(err, VerificationError::UnsupportedDeferredProof),
            "expected wire-backed partial proof to be rejected, got {err:?}"
        );

        let stark = DeferredProof::stark(
            StarkProof::new(Vec::from([0_u8]), HashFunction::Poseidon2),
            TRUE_DIGEST,
        );
        let err = resolve_final_deferred_root(&stark).unwrap_err();
        assert!(
            matches!(err, VerificationError::DeferredStarkVerification(_)),
            "expected invalid STARK-backed precompile VM proof to be verified and rejected, got {err:?}"
        );
    }

    #[test]
    fn partial_deferred_hydration_accepts_wire_and_rejects_final_forms() {
        let wire = DeferredStateWire::default();
        let deferred_proof = DeferredProof::wire(wire.clone());
        let deferred_state = hydrate_deferred_state(&deferred_proof, DEFAULT_MAX_DEFERRED_ELEMENTS)
            .expect("empty wire should hydrate under the standard precompile registry");

        assert_eq!(deferred_state.root(), TRUE_DIGEST);
        assert_eq!(deferred_state.to_wire().unwrap(), wire);

        for final_proof in [
            DeferredProof::Empty,
            DeferredProof::stark(
                StarkProof::new(Vec::from([0_u8]), HashFunction::Poseidon2),
                TRUE_DIGEST,
            ),
        ] {
            let err =
                hydrate_deferred_state(&final_proof, DEFAULT_MAX_DEFERRED_ELEMENTS).unwrap_err();
            assert!(
                matches!(err, VerificationError::UnsupportedDeferredProof),
                "expected final proof material to be rejected by partial hydration, got {err:?}"
            );
        }
    }

    #[test]
    fn proof_encoding_config_rejects_oversized_native_vec_preallocation() {
        let proof_encoding_config = wincode::config::Configuration::default()
            .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
        let element_count = MAX_STARK_PROOF_BYTES + 1;
        let mut length_prefix = Vec::new();

        <usize as wincode::config::Serialize<_>>::serialize_into(
            &mut length_prefix,
            &element_count,
            proof_encoding_config,
        )
        .unwrap();
        let err = <Vec<u8> as wincode::config::Deserialize<_>>::deserialize(
            &length_prefix,
            proof_encoding_config,
        )
        .unwrap_err();

        assert!(
            matches!(
                err,
                wincode::error::ReadError::PreallocationSizeLimit { needed, limit }
                    if needed == element_count && limit == MAX_STARK_PROOF_BYTES
            ),
            "expected proof encoding config to reject oversized allocation, got {err:?}"
        );
    }

    #[test]
    fn verify_stark_proof_rejects_oversized_proof_bytes() {
        let params = config::pcs_params();
        let config = config::poseidon2_config(params);
        let proof_bytes = Vec::from_iter(core::iter::repeat_n(0, MAX_STARK_PROOF_BYTES + 1));

        let err = verify_stark_proof(&config, &[], &[], &proof_bytes).unwrap_err();

        assert!(
            matches!(
                err,
                StarkVerificationError::ProofTooLarge {
                    size,
                    max: MAX_STARK_PROOF_BYTES,
                } if size == proof_bytes.len()
            ),
            "expected explicit proof byte limit to reject oversized proof, got {err:?}"
        );
    }
}
