//! Advice provision and tests for the STARK-based signature verifier.

extern crate alloc;

use alloc::vec::Vec;

use miden_core::{Felt, Word};
use miden_signature::{Goldilocks, VerifyError, e2_105_w8};
use miden_utils_testing::crypto::MerkleStore;

mod bench;
pub mod circuit_gen;
mod conversions;
mod fixtures;
pub mod integration;
pub mod transcript;

// ── Types ──

/// All data needed to run the MASM signature verifier.
#[derive(Debug, Clone)]
pub struct SigVerifierData {
    pub initial_stack: Vec<u64>,
    pub advice_stack: Vec<u64>,
    pub store: MerkleStore,
    pub advice_map: Vec<(Word, Vec<Felt>)>,
}

// ── Public API ──

/// Test message helper: four base-field elements derived from a tag.
pub fn test_message(tag: u64) -> [Felt; 4] {
    [
        Felt::new_unchecked(tag),
        Felt::new_unchecked(tag.wrapping_add(1)),
        Felt::new_unchecked(tag.wrapping_add(2)),
        Felt::new_unchecked(tag.wrapping_add(3)),
    ]
}

/// Convert a 4-felt message into Goldilocks elements for miden-signature APIs.
pub fn message_to_goldilocks(msg: [Felt; 4]) -> [Goldilocks; 4] {
    msg.map(|f| f.into())
}

/// Derive a deterministic keygen seed from an arbitrary label.
///
/// This is test-only and not meant to be cryptographic; it just needs to be
/// stable and distinct across labels.
pub fn seed_from_label(label: &[u8]) -> [Goldilocks; 4] {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut out = [Goldilocks::new(0); 4];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut h = FNV_OFFSET ^ (i as u64);
        for &b in label {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        *slot = Goldilocks::new(h);
    }
    out
}

/// Convert the instance seed into Goldilocks elements for miden-signature APIs.
pub fn instance_seed_goldilocks() -> [Goldilocks; 4] {
    message_to_goldilocks(transcript::compute_instance_seed())
}

// Signature helpers using 4-felt messages.

pub fn sign_sig_w8(sk: &e2_105_w8::SecretKey, msg: [Felt; 4]) -> Vec<u8> {
    e2_105_w8::sign(sk, message_to_goldilocks(msg))
}

pub fn verify_sig_w8(
    pk: &e2_105_w8::PublicKey,
    msg: [Felt; 4],
    signature: &[u8],
) -> Result<(), VerifyError> {
    e2_105_w8::verify(pk, message_to_goldilocks(msg), signature)
}
