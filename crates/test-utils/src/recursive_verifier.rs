//! Test-side adapter over the production recursive-verifier advice builder
//! (`miden_verifier::recursive`).
//!
//! The production builder produces the advice-stack stream, Merkle store, and advice map; the
//! test harness additionally needs the operand-stack pointers for its fixed memory layout and the
//! stream as `u64`s for `build_test!`. This module bundles those into [`VerifierData`] so the
//! recursive-verification tests drive the real MASM verifier over production-built advice.

use alloc::vec::Vec;

use miden_core::{Felt, Word, program::ExecutionClaim, proof::ExecutionProof};
pub use miden_core::program::request_key;
pub use miden_verifier::recursive::RecursiveAdviceError;

use crate::crypto::MerkleStore;

/// The advice inputs plus test operand-stack layout for one recursive verification.
///
/// `claim_advice` (the consumer's claim: kernel witness, program digest, stack i/o) and
/// `proof_stream` (the proof as the verifier consumes it) are kept separate to reflect that the
/// claim is the consumer's and the proof is fetched: a directly staged run concatenates them on
/// the advice stack; a run through `verify_vm_proof_from_claim` stages the claim and registers
/// the proof in the advice map.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifierData {
    /// Operand stack for `verify_vm_proof`: `[claim_ptr, kernel_ptr, num_kernel_digests]`.
    pub initial_stack: Vec<u64>,
    /// The consumer's claim, copied into VM memory before verification: kernel digests (4 each),
    /// then program digest (4), then stack inputs + outputs (32).
    pub claim_advice: Vec<u64>,
    /// The proof stream consumed by `verify_vm_proof` (production advice-builder output).
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

// Caller-owned memory regions in the test staging prologue: kernel digests at KERNEL_PTR, the
// claim region at CLAIM_PTR.
const KERNEL_PTR: u64 = 0;
const CLAIM_PTR: u64 = 4096;

/// Builds [`VerifierData`] for a proof of the given claim via the production advice builder.
pub fn generate_advice_inputs(
    proof: &ExecutionProof,
    claim: &ExecutionClaim,
) -> Result<VerifierData, RecursiveAdviceError> {
    let kernel_digests = claim.program_info().kernel_procedures();
    let num_kernel_digests = kernel_digests.len() as u64;
    let inputs = miden_verifier::recursive::advice_inputs(proof, claim)?;

    // The consumer's claim: kernel witness, then program digest, then stack i/o. In a real
    // protocol consumer these are derived/held; here the test supplies the proof's own claim.
    let mut claim_advice: Vec<u64> = Vec::new();
    for digest in kernel_digests {
        claim_advice.extend(digest.as_elements().iter().map(Felt::as_canonical_u64));
    }
    claim_advice.extend(
        claim.program_info().program_hash().as_elements().iter().map(Felt::as_canonical_u64),
    );
    claim_advice.extend(claim.stack_inputs().as_ref().iter().map(Felt::as_canonical_u64));
    claim_advice.extend(claim.stack_outputs().as_ref().iter().map(Felt::as_canonical_u64));

    Ok(VerifierData {
        initial_stack: alloc::vec![CLAIM_PTR, KERNEL_PTR, num_kernel_digests],
        claim_advice,
        proof_stream: inputs.advice_stack.iter().map(Felt::as_canonical_u64).collect(),
        store: inputs.store,
        advice_map: inputs.advice_map,
        claim_commitment: inputs.claim_commitment,
    })
}
