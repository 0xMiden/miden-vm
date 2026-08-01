//! Test-side adapter over the production recursive-verifier advice builder
//! (`miden_verifier::recursive`).
//!
//! The production builder produces the advice-stack stream, Merkle store, and advice map; the
//! test harness additionally needs the operand-stack pointers for its fixed memory layout and the
//! stream as `u64`s for `build_test!`. This module bundles those into [`VerifierData`] so the
//! recursive-verification tests drive the real MASM verifier over production-built advice.

use alloc::vec::Vec;

pub use miden_core::program::request_key;
use miden_core::{Felt, Word, program::ExecutionClaim, proof::ExecutionProof};
pub use miden_verifier::recursive::RecursiveAdviceError;

use crate::crypto::MerkleStore;

/// The advice inputs plus test operand-stack layout for one recursive verification.
///
/// `claim_advice` (the consumer's claim: the canonical 40-felt encoding) and `proof_stream`
/// (the proof as the verifier consumes it) are kept separate because they feed different
/// channels: a directly staged run concatenates them on the advice stack; a request-fetched run
/// keeps the claim on the advice stack and registers the proof in the advice map instead.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifierData {
    /// Operand stack for `verify_vm_proof`: `[claim_ptr]`.
    pub initial_stack: Vec<u64>,
    /// The consumer's claim, copied into VM memory before verification: the canonical 40-felt
    /// encoding `P | K | I | O`.
    pub claim_advice: Vec<u64>,
    /// The proof stream consumed by `verify_vm_proof` (production advice-builder
    /// output).
    pub proof_stream: Vec<u64>,
    pub store: MerkleStore,
    pub advice_map: Vec<(Word, Vec<Felt>)>,
    /// Commitment to the execution claim (the content address the proof is registered under).
    pub claim_commitment: Word,
}

impl VerifierData {
    /// The full advice stack for a directly staged run: the consumer's claim followed by the
    /// proof stream, in consumption order — the prologue copies the claim into memory, then
    /// `verify_vm_proof` consumes the proof.
    pub fn advice_stack(&self) -> Vec<u64> {
        [self.claim_advice.as_slice(), self.proof_stream.as_slice()].concat()
    }
}

// Caller-owned claim region in the test staging prologue.
const CLAIM_PTR: u64 = 4096;

/// Builds [`VerifierData`] for a proof of the given claim via the production advice builder.
pub fn generate_advice_inputs(
    proof: &ExecutionProof,
    claim: &ExecutionClaim,
) -> Result<VerifierData, RecursiveAdviceError> {
    let inputs = miden_verifier::recursive::advice_inputs(proof, claim)?;

    // The consumer's claim: the canonical 40-felt encoding. In a real protocol consumer these
    // fields are derived/held; here the test supplies the proof's own claim.
    let claim_advice: Vec<u64> = claim.to_elements().iter().map(Felt::as_canonical_u64).collect();

    Ok(VerifierData {
        initial_stack: alloc::vec![CLAIM_PTR],
        claim_advice,
        proof_stream: inputs.advice_stack.iter().map(Felt::as_canonical_u64).collect(),
        store: inputs.store,
        advice_map: inputs.advice_map,
        claim_commitment: inputs.claim_commitment,
    })
}
