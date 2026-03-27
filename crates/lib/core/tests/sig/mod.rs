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
mod p3_poseidon2;
pub mod rpo_air;
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
        Felt::new(tag),
        Felt::new(tag.wrapping_add(1)),
        Felt::new(tag.wrapping_add(2)),
        Felt::new(tag.wrapping_add(3)),
    ]
}

/// Convert a 4-felt message into Goldilocks elements for miden-signature APIs.
pub fn message_to_goldilocks(msg: [Felt; 4]) -> [Goldilocks; 4] {
    debug_assert_eq!(core::mem::size_of::<Felt>(), core::mem::size_of::<Goldilocks>());
    unsafe { core::mem::transmute(msg) }
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

/// Build advice inputs from deserialized signature proof components.
///
/// The advice stack is packed in MASM consumption order:
///   witness_com(4) | ali_nonce(1) | quotient_com(4) | ood_nonce(1) |
///   deep_alpha_nd(2) |
///   OOD_data(96, naturally rate-aligned) | prox_nonce(1) |
///   DEEP_coeffs(256, padded-desc + rate-aligned) | query_nonce(1)
///
/// OOD data is laid out in point-major order (z-row then gz-row), with each
/// group independently zero-padded to a multiple of 8:
/// witness_z(16) + quotient_z(32) + witness_gz(16) + quotient_gz(32) = 96.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn build_sig_advice(
    pk: [u64; 4],
    msg: [u64; 4],
    witness_commitment: [u64; 4],
    quotient_commitment: [u64; 4],
    ali_nonce: u64,
    ood_nonce: u64,
    deep_alpha_nd: [u64; 2],
    prox_nonce: u64,
    query_nonce: u64,
    witness_z: &[[u64; 2]],
    witness_gz: &[[u64; 2]],
    quotient_z: &[[u64; 2]],
    quotient_gz: &[[u64; 2]],
    deep_coeffs: &[[u64; 2]],
) -> SigVerifierData {
    assert_eq!(witness_z.len(), 8);
    assert_eq!(witness_gz.len(), 8);
    assert_eq!(quotient_z.len(), 16);
    assert_eq!(quotient_gz.len(), 16);

    // ── Operand stack: [pk, msg] ──
    let mut initial_stack = Vec::with_capacity(8);
    initial_stack.extend_from_slice(&pk);
    initial_stack.extend_from_slice(&msg);

    // ── Advice stack (MASM consumption order) ──
    let mut adv = Vec::new();

    // Phase 1
    adv.extend_from_slice(&witness_commitment);
    adv.push(ali_nonce);

    // Phase 2
    adv.extend_from_slice(&quotient_commitment);
    adv.push(ood_nonce);
    // Push alpha1 first, then alpha0 so adv_push.2 materializes [alpha0, alpha1].
    adv.push(deep_alpha_nd[1]);
    adv.push(deep_alpha_nd[0]);

    // Phase 3: OOD evaluations — each group independently padded to multiple of 8 felts
    for group in [witness_z, quotient_z, witness_gz, quotient_gz] {
        let mut felts: Vec<u64> = Vec::new();
        for ef in group {
            felts.extend_from_slice(ef);
        }
        // Pad to next multiple of 8
        let padded_len = felts.len().next_multiple_of(8);
        felts.resize(padded_len, 0);
        adv.extend_from_slice(&felts);
    }

    adv.push(prox_nonce);

    // Phase 4: DEEP coefficients in transcript/eval order:
    // [0, ..., 0, c_{m-1}, ..., c_0], padded to next power-of-two.
    let padded_len = deep_coeffs.len().next_power_of_two();
    for _ in 0..(padded_len - deep_coeffs.len()) {
        adv.extend_from_slice(&[0, 0]);
    }
    for ef in deep_coeffs.iter().rev() {
        adv.extend_from_slice(ef);
    }

    adv.push(query_nonce);

    SigVerifierData {
        initial_stack,
        advice_stack: adv,
        store: MerkleStore::new(),
        advice_map: Vec::new(),
    }
}
