//! Tests for the ECDSA secp256k1 / Keccak256 precompile MASM wrappers.
//!
//! ECDSA verification is performed entirely inside the `EcdsaK256KeccakPrecompile` schema's
//! `reduce` (no host-side event handler). The MASM wrappers register the chunk node, evaluate
//! the predicate (which traps on signature failure), and fold the chunk digest into the
//! precompile transcript.

use miden_core::{
    Felt, Word,
    crypto::hash::Poseidon2,
    serde::{Deserializable, Serializable},
    utils::bytes_to_packed_u32_elements,
};
use miden_core_lib::dsa::ecdsa_k256_keccak::sign as ecdsa_sign;
use miden_crypto::dsa::ecdsa_k256_keccak::SigningKey as SecretKey;
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler, EventName},
};
use rand::{SeedableRng, rngs::StdRng};

use crate::helpers::masm_store_felts;

// TEST CONSTANTS
// ================================================================================================

const BUF_ADDR: u32 = 128;

// VERIFY_PREHASH — single-buffer API
// ================================================================================================

/// Pack a (pk, digest, sig) triple into the schema's word-aligned 40-felt layout (160 bytes).
fn pack_ecdsa_buffer(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> Vec<Felt> {
    assert_eq!(pk.len(), 33);
    assert_eq!(sig.len(), 65);
    let mut buf = vec![0u8; 160];
    buf[0..33].copy_from_slice(pk);
    // bytes[33..48] pad
    buf[48..80].copy_from_slice(digest);
    buf[80..145].copy_from_slice(sig);
    // bytes[145..160] pad
    bytes_to_packed_u32_elements(&buf)
}

#[test]
fn test_ecdsa_verify_prehash_valid_signature_succeeds() {
    let mut rng = StdRng::seed_from_u64(42);
    let sk = SecretKey::with_rng(&mut rng);
    let pk_bytes = sk.public_key().to_bytes();
    let digest = [1u8; 32];
    let sig_bytes = sk.sign_prehash(digest).to_bytes();
    let buf_felts = pack_ecdsa_buffer(&pk_bytes, &digest, &sig_bytes);

    let memory_stores = masm_store_felts(&buf_felts, BUF_ADDR);
    let source = format!(
        r#"
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}
                push.{BUF_ADDR}
                exec.ecdsa_k256_keccak::verify_prehash
                exec.sys::truncate_stack
            end
        "#,
    );
    build_debug_test!(source, &[]).expect_stack(&[]);
}

#[test]
fn test_ecdsa_verify_prehash_invalid_signature_traps() {
    // Sign with key A but pack key B's pk — signature won't verify.
    let mut rng1 = StdRng::seed_from_u64(42);
    let sk_a = SecretKey::with_rng(&mut rng1);
    let mut rng2 = StdRng::seed_from_u64(123);
    let sk_b = SecretKey::with_rng(&mut rng2);
    let pk_bytes = sk_b.public_key().to_bytes();
    let digest = [1u8; 32];
    let sig_bytes = sk_a.sign_prehash(digest).to_bytes();
    let buf_felts = pack_ecdsa_buffer(&pk_bytes, &digest, &sig_bytes);

    let memory_stores = masm_store_felts(&buf_felts, BUF_ADDR);
    let source = format!(
        r#"
            use miden::core::crypto::dsa::ecdsa_k256_keccak

            begin
                {memory_stores}
                push.{BUF_ADDR}
                exec.ecdsa_k256_keccak::verify_prehash
            end
        "#,
    );
    let result = build_debug_test!(source, &[]).execute();
    assert!(result.is_err(), "invalid signature must trap execution");
}

// VERIFY — high-level wrapper that hashes the message via Keccak256
// ================================================================================================

const EVENT_ECDSA_SIG_TO_STACK: EventName = EventName::new("test::ecdsa::sig_to_stack");

struct EcdsaSignatureHandler {
    secret_key_bytes: Vec<u8>,
}

impl EcdsaSignatureHandler {
    fn new(secret_key: &SecretKey) -> Self {
        Self { secret_key_bytes: secret_key.to_bytes() }
    }
}

impl EventHandler for EcdsaSignatureHandler {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        // [event_id, pk_commitment(1-4), message(5-8), ...]
        let provided_pk_commitment = process.get_stack_word(1);
        let secret_key =
            SecretKey::read_from_bytes(&self.secret_key_bytes).expect("invalid test secret key");
        let pk = secret_key.public_key();
        let pk_commitment = {
            let pk_felts = bytes_to_packed_u32_elements(&pk.to_bytes());
            Poseidon2::hash_elements(&pk_felts)
        };
        assert_eq!(provided_pk_commitment, pk_commitment, "public key commitment mismatch",);

        let message = process.get_stack_word(5);
        let calldata = ecdsa_sign(&secret_key, message);
        Ok(vec![AdviceMutation::extend_stack(calldata)])
    }
}

#[test]
fn test_ecdsa_verify_end_to_end() {
    let mut rng = StdRng::seed_from_u64(19260817);
    let secret_key = SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();
    let message = Word::new([
        Felt::new_unchecked(11),
        Felt::new_unchecked(22),
        Felt::new_unchecked(33),
        Felt::new_unchecked(44),
    ]);

    let pk_commitment = {
        let pk_felts = bytes_to_packed_u32_elements(&public_key.to_bytes());
        Poseidon2::hash_elements(&pk_felts)
    };

    let source = format!(
        r#"
            use miden::core::crypto::dsa::ecdsa_k256_keccak

            begin
                push.{message}
                push.{pk_commitment}
                emit.event("{EVENT_ECDSA_SIG_TO_STACK}")
                exec.ecdsa_k256_keccak::verify
            end
        "#,
    );

    let test = build_debug_test!(&source)
        .with_event_handler(EVENT_ECDSA_SIG_TO_STACK, EcdsaSignatureHandler::new(&secret_key));
    test.expect_stack(&[]);
}
