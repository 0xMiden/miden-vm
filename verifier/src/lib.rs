#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use miden_air::{MidenMultiAir, PublicInputs, Statement, config};
use miden_core::{Felt, field::QuadFelt};
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
        deferred::{
            DEFAULT_MAX_DEFERRED_ELEMENTS, DeferredRoot, DeferredState, DeferredStateWire,
            IntegrityError,
        },
        program::{ExecutionClaim, KernelDescriptor, ProgramInfo, StackInputs, StackOutputs},
        proof::{ExecutionProof, HashFunction},
    };
    pub mod math {
        pub use miden_core::Felt;
    }
}
pub use exports::*;

pub mod recursive;

// VERIFIER
// ================================================================================================

/// An undischarged deferred obligation returned by [`verify_unsettled`].
///
/// Holds the deferred root the verified proof bound. There is no public constructor: the only
/// way to obtain one is verifying a proof, and the intended ways to dispose of it are [`settle`]
/// or explicitly re-exposing the root in the caller's own statement.
#[must_use = "an unsettled deferred obligation must be settled or explicitly re-exposed"]
#[derive(Debug)]
pub struct Unsettled(DeferredRoot);

impl Unsettled {
    /// Returns the deferred root of this obligation.
    pub const fn deferred_root(&self) -> DeferredRoot {
        self.0
    }
}

/// Verifies a fully settled proof of the given execution claim and returns its security level.
///
/// The proof package must carry settlement evidence; the STARK proof is verified against the
/// claim and the package's deferred root, and the evidence is then verified to discharge that
/// root under the built-in precompile registry and the default deferred-state budget.
///
/// # Errors
/// Returns an error if:
/// - The package carries no settlement evidence (use [`verify_unsettled`] instead).
/// - The proof does not prove a correct execution of the claim.
/// - The settlement evidence does not discharge the proof's deferred root.
pub fn verify(proof: ExecutionProof, claim: ExecutionClaim) -> Result<u32, VerificationError> {
    let security_level = proof.security_level();
    let (hash_fn, proof_bytes, deferred_root, settlement) = proof.into_parts();
    let wire = settlement.ok_or(VerificationError::MissingSettlementEvidence)?;

    verify_stark(claim, deferred_root, hash_fn, proof_bytes)?;
    settle_root(deferred_root, &wire, DEFAULT_MAX_DEFERRED_ELEMENTS)?;

    Ok(security_level)
}

/// Verifies only the VM STARK proof of the given execution claim, returning its security level
/// and the deferred obligation the proof bound.
///
/// The obligation must then be discharged with [`settle`] or explicitly re-exposed in the
/// caller's own statement; it must not be dropped.
///
/// # Errors
/// Returns an error if the proof does not prove a correct execution of the claim.
pub fn verify_unsettled(
    proof: ExecutionProof,
    claim: ExecutionClaim,
) -> Result<(u32, Unsettled), VerificationError> {
    let security_level = proof.security_level();
    let (hash_fn, proof_bytes, deferred_root, _settlement) = proof.into_parts();

    verify_stark(claim, deferred_root, hash_fn, proof_bytes)?;

    Ok((security_level, Unsettled(deferred_root)))
}

/// Discharges a deferred obligation with native request-replay evidence, using an explicit
/// deferred-state budget.
///
/// # Errors
/// Returns an error if the evidence fails the deferred-DAG integrity checks or does not
/// discharge the obligation's root.
pub fn settle(
    pending: Unsettled,
    evidence: &DeferredStateWire,
    max_deferred_elements: usize,
) -> Result<(), VerificationError> {
    settle_root(pending.0, evidence, max_deferred_elements)
}

// HELPER FUNCTIONS
// ================================================================================================

fn settle_root(
    deferred_root: DeferredRoot,
    evidence: &DeferredStateWire,
    max_deferred_elements: usize,
) -> Result<(), VerificationError> {
    let state = DeferredState::from_wire(
        Arc::new(miden_precompiles::registry()),
        evidence,
        max_deferred_elements,
    )?;
    if state.root() != deferred_root {
        return Err(VerificationError::DeferredRootMismatch);
    }
    Ok(())
}

fn verify_stark(
    claim: ExecutionClaim,
    final_deferred_root: Word,
    hash_fn: HashFunction,
    proof_bytes: Vec<u8>,
) -> Result<(), VerificationError> {
    let (program_info, stack_inputs, stack_outputs) = claim.into_parts();
    let program_hash = *program_info.program_hash();

    let pub_inputs =
        PublicInputs::new(program_info, stack_inputs, stack_outputs, final_deferred_root);
    let (public_values, kernel_felts) = pub_inputs.to_air_inputs();

    let params = config::pcs_params();
    match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::blake3_256_config(params);
            verify_stark_proof(&config, &public_values, &kernel_felts, &proof_bytes)
        },
        HashFunction::Rpo256 => {
            let config = config::rpo_config(params);
            verify_stark_proof(&config, &public_values, &kernel_felts, &proof_bytes)
        },
        HashFunction::Rpx256 => {
            let config = config::rpx_config(params);
            verify_stark_proof(&config, &public_values, &kernel_felts, &proof_bytes)
        },
        HashFunction::Poseidon2 => {
            let config = config::poseidon2_config(params);
            verify_stark_proof(&config, &public_values, &kernel_felts, &proof_bytes)
        },
        HashFunction::Keccak => {
            let config = config::keccak_config(params);
            verify_stark_proof(&config, &public_values, &kernel_felts, &proof_bytes)
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
    #[error("proof carries no settlement evidence; use verify_unsettled")]
    MissingSettlementEvidence,
    #[error("settlement evidence does not discharge the proof's deferred root")]
    DeferredRootMismatch,
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

/// Verifies a multi-AIR STARK proof for the Miden VM statement.
///
/// Pre-seeds the challenger with the protocol parameters, public values, and statement aux inputs,
/// then delegates to the lifted multi-AIR verifier.
fn verify_stark_proof<SC>(
    config: &SC,
    public_values: &[Felt],
    kernel_felts: &[Felt],
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

    // `air_inputs` are the fixed public values; `aux_inputs` are the kernel-procedure
    // digests. The lifted verifier absorbs both into Fiat-Shamir internally, and derives
    // the multi-AIR ordering deterministically from the proof's per-AIR trace heights.
    let statement = Statement::<Felt, QuadFelt, _>::new(
        MidenMultiAir::new(),
        public_values.to_vec(),
        kernel_felts.to_vec(),
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

    use super::*;

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
