//! Test-side adapter over the production recursive-verifier advice builder
//! (`miden_verifier::recursive`).
//!
//! The production builder produces the advice-stack stream, Merkle store, and advice map; the
//! test harness additionally needs the claim commitment on the operand stack and the proof stream
//! as `u64`s for `build_test!`. This module bundles those into [`VerifierData`] so the
//! recursive-verification tests drive the real MASM verifier over production-built advice.

use alloc::vec::Vec;

pub use miden_core::program::proof_request_key;
use miden_core::{Felt, Word, program::ExecutionClaim, proof::ExecutionProof};
pub use miden_verifier::recursive::RecursiveVerifierInputsError;

use crate::crypto::MerkleStore;

/// The advice inputs plus test operand-stack layout for one recursive verification.
///
/// `claim_advice` is retained for tests in which a consumer derives the commitment in-VM. The
/// verifier itself loads the authenticated claim preimage from the advice map.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifierData {
    /// Canonical claim encoding used by tests that derive the commitment in-VM.
    pub claim_advice: Vec<u64>,
    /// Advice-stack values for a direct verifier call. Empty when the proof is request-addressed.
    pub proof_stream: Vec<u64>,
    pub store: MerkleStore,
    pub advice_map: Vec<(Word, Vec<Felt>)>,
    /// Commitment to the execution claim (the content address the proof is registered under).
    pub claim_commitment: Word,
}

impl VerifierData {
    /// Operand stack for `verify_vm_proof`: `[CLAIM_COMMITMENT]`.
    pub fn initial_stack(&self) -> [u64; 4] {
        self.claim_commitment.into_elements().map(|felt| felt.as_canonical_u64())
    }

    /// The proof stream consumed by a direct verifier invocation.
    pub fn advice_stack(&self) -> &[u64] {
        &self.proof_stream
    }
}

/// Builds [`VerifierData`] for a proof of the given claim via the production advice builder.
pub fn generate_advice_inputs(
    proof: &ExecutionProof,
    claim: &ExecutionClaim,
) -> Result<VerifierData, RecursiveVerifierInputsError> {
    let inputs = miden_verifier::recursive::RecursiveVerifierInputs::new(proof, claim)?;
    Ok(verifier_data(inputs, claim))
}

/// Builds [`VerifierData`] with the proof registered under the verifier and claim commitments.
pub fn generate_request_inputs(
    verifier_root: Word,
    proof: &ExecutionProof,
    claim: &ExecutionClaim,
) -> Result<VerifierData, RecursiveVerifierInputsError> {
    let inputs = miden_verifier::recursive::RecursiveVerifierInputs::for_request(
        verifier_root,
        proof,
        claim,
    )?;
    Ok(verifier_data(inputs, claim))
}

fn verifier_data(
    inputs: miden_verifier::recursive::RecursiveVerifierInputs,
    claim: &ExecutionClaim,
) -> VerifierData {
    let (advice, claim_commitment) = inputs.into_parts();
    let (proof_stream, advice_map, store) = advice.into_parts();

    // The consumer's claim: the canonical 40-felt encoding. In a real protocol consumer these
    // fields are derived/held; here the test supplies the proof's own claim.
    let claim_advice: Vec<u64> = claim.to_elements().iter().map(Felt::as_canonical_u64).collect();

    VerifierData {
        claim_advice,
        proof_stream: proof_stream.iter().map(Felt::as_canonical_u64).collect(),
        store,
        advice_map: advice_map.into_iter().map(|(key, value)| (key, value.to_vec())).collect(),
        claim_commitment,
    }
}
