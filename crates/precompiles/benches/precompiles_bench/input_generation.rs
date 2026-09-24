use miden_core::{
    Felt, Word,
    advice::{AdviceInputs, AdviceStack},
    utils::bytes_to_packed_u32_elements,
};
use miden_core_lib::dsa::{ecdsa_k256_keccak, ecdsa_p256_sha256, eddsa_25519_sha512};
use miden_crypto::dsa::{
    ecdsa_k256_keccak::SigningKey, eddsa_25519_sha512::SigningKey as Ed25519Key,
};
use p256::ecdsa::SigningKey as P256SigningKey;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{Rng, SeedableRng},
};

pub const DEFAULT_KECCAKS: usize = 100;
pub const DEFAULT_ECDSAS: usize = 4;
pub const DEFAULT_EDDSAS: usize = 4;
pub const DEFAULT_ECDSA_P256S: usize = 4;
pub const DEFAULT_SHA256_64B: usize = 8;
pub const DEFAULT_SHA256_1KIB: usize = 4;

/// Bytes per fixed-size SHA-256 benchmark message.
const SHA256_64B_LEN: usize = 64;
const SHA256_1KIB_LEN: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecompileWorkload {
    pub keccaks: usize,
    pub ecdsas: usize,
    pub eddsas: usize,
    pub ecdsa_p256s: usize,
    pub sha256_64b: usize,
    pub sha256_1kib: usize,
}

impl Default for PrecompileWorkload {
    fn default() -> Self {
        Self {
            keccaks: DEFAULT_KECCAKS,
            ecdsas: DEFAULT_ECDSAS,
            eddsas: DEFAULT_EDDSAS,
            ecdsa_p256s: DEFAULT_ECDSA_P256S,
            sha256_64b: DEFAULT_SHA256_64B,
            sha256_1kib: DEFAULT_SHA256_1KIB,
        }
    }
}

pub(crate) fn generate_advice_inputs(workload: PrecompileWorkload) -> AdviceInputs {
    let mut advice_stack = AdviceStack::new();
    let mut rng = ChaCha20Rng::from_seed([0xd3; 32]);

    for i in 0..workload.ecdsas {
        let sk = SigningKey::with_rng(&mut rng);
        let pk = sk.public_key();
        let message = signature_message(i as u64);
        let signature = sk.sign(message);
        assert!(
            pk.verify(message, &signature),
            "generated ECDSA fixture must verify before passing it to MASM",
        );

        advice_stack.append_word(message);
        advice_stack.append_word(ecdsa_k256_keccak::public_key_commitment(&pk));
        advice_stack.append_for_adv_pipe(&ecdsa_k256_keccak::encode_signature(&pk, &signature));
    }

    for i in 0..workload.eddsas {
        let sk = Ed25519Key::with_rng(&mut rng);
        let pk = sk.public_key();
        let message = signature_message(i as u64);
        let signature = sk.sign(message);
        assert!(
            pk.verify(message, &signature),
            "generated Ed25519 fixture must verify before passing it to MASM",
        );

        advice_stack.append_word(message);
        advice_stack.append_word(eddsa_25519_sha512::public_key_commitment(&pk));
        advice_stack.append_for_adv_pipe(&eddsa_25519_sha512::encode_signature(&pk, &signature));
    }

    for i in 0..workload.ecdsa_p256s {
        let sk = p256_signing_key(&mut rng);
        let pk = sk.verifying_key();
        let message = signature_message(i as u64);
        advice_stack.append_word(message);
        advice_stack.append_word(ecdsa_p256_sha256::public_key_commitment(pk));
        advice_stack.append_for_adv_pipe(&ecdsa_p256_sha256::sign(&sk, message));
    }

    for i in 0..workload.sha256_64b {
        let message = sha256_message(SHA256_64B_LEN, i as u64);
        advice_stack.append_for_adv_pipe(&bytes_to_packed_u32_elements(&message));
    }

    for i in 0..workload.sha256_1kib {
        let message = sha256_message(SHA256_1KIB_LEN, i as u64);
        advice_stack.append_for_adv_pipe(&bytes_to_packed_u32_elements(&message));
    }

    // Each fixture contains message/commitment words followed by the scheme's native PK/SIG
    // witness. Both witness lengths are multiples of 8, so adv_pipe requires no padding.
    let felts_per_ecdsa = 8 + 32;
    let felts_per_eddsa = 8 + 24;
    let felts_per_ecdsa_p256 = 8 + 32;
    let felts_per_sha256_64b = SHA256_64B_LEN / 4;
    let felts_per_sha256_1kib = SHA256_1KIB_LEN / 4;
    assert_eq!(
        advice_stack.len(),
        workload.ecdsas * felts_per_ecdsa
            + workload.eddsas * felts_per_eddsa
            + workload.ecdsa_p256s * felts_per_ecdsa_p256
            + workload.sha256_64b * felts_per_sha256_64b
            + workload.sha256_1kib * felts_per_sha256_1kib,
        "unexpected signature advice length",
    );
    AdviceInputs::default().with_stack(advice_stack)
}

fn signature_message(index: u64) -> Word {
    Word::new([
        Felt::new_unchecked(0x0001_0203_0405_0607 + index),
        Felt::new_unchecked(0x0809_0a0b_0c0d_0e0f + index * 3),
        Felt::new_unchecked(0x1011_1213_1415_1617 + index * 5),
        Felt::new_unchecked(0x1819_1a1b_1c1d_1e1f + index * 7),
    ])
}

/// Derives a distinct deterministic P-256 secret key from the shared benchmark RNG.
fn p256_signing_key(rng: &mut ChaCha20Rng) -> P256SigningKey {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    P256SigningKey::from_slice(&bytes).expect("random bytes should be a valid P-256 secret key")
}

/// Deterministic pseudo-random message bytes of `len_bytes`, distinct per `index`.
fn sha256_message(len_bytes: usize, index: u64) -> Vec<u8> {
    assert!(len_bytes >= size_of::<u64>());
    let mut message = vec![0; len_bytes];
    ChaCha20Rng::seed_from_u64(index).fill_bytes(&mut message);
    // Preserve every index bit so the deferred-claim cache cannot collapse scaling workloads.
    message[..size_of::<u64>()].copy_from_slice(&index.to_le_bytes());
    message
}

#[cfg(test)]
mod tests {
    #[test]
    fn default_workload_has_valid_advice() {
        super::generate_advice_inputs(super::PrecompileWorkload::default());
    }

    #[test]
    fn sha256_scaling_inputs_do_not_repeat_after_256_claims() {
        use std::collections::HashSet;

        use super::*;

        for len in [SHA256_64B_LEN, SHA256_1KIB_LEN] {
            let mut messages = HashSet::new();
            for index in (0..1024).chain([1 << 32, 1 << 48, u64::MAX]) {
                let message = sha256_message(len, index);
                assert_eq!(message.len(), len);
                assert_eq!(message, sha256_message(len, index), "fixtures must be reproducible");
                assert!(messages.insert(message), "claim {index} repeats at length {len}");
            }
        }
    }
}
