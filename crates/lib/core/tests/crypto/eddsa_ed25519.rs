//! Tests for the EdDSA Ed25519 / SHA-512 precompile MASM wrappers.
//!
//! After the LegacyPrecompile migration, EdDSA verification runs entirely inside the schema's
//! `reduce` (no host-side event handler). The MASM wrappers register the chunk node, evaluate
//! the predicate (which traps on signature failure), and fold the chunk digest into the
//! precompile transcript.

use miden_core::{
    Felt, Word,
    crypto::hash::Poseidon2,
    serde::{Deserializable, Serializable},
    utils::bytes_to_packed_u32_elements,
};
use miden_core_lib::dsa::eddsa_ed25519::sign as eddsa_sign;
use miden_crypto::dsa::eddsa_25519_sha512::SigningKey as SecretKey;
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

/// Pack a (pk, k_digest, sig) triple into the schema's 40-felt chunk buffer (no padding —
/// 32 + 64 + 64 = 160 bytes naturally word-aligned at every boundary).
fn pack_eddsa_buffer(pk: &[u8], k_digest: &[u8; 64], sig: &[u8]) -> Vec<Felt> {
    assert_eq!(pk.len(), 32);
    assert_eq!(sig.len(), 64);
    let mut buf = vec![0u8; 160];
    buf[0..32].copy_from_slice(pk);
    buf[32..96].copy_from_slice(k_digest);
    buf[96..160].copy_from_slice(sig);
    bytes_to_packed_u32_elements(&buf)
}

fn eddsa_valid_triple(message: Word) -> (Vec<u8>, [u8; 64], Vec<u8>) {
    let mut rng = StdRng::seed_from_u64(42);
    let sk = SecretKey::with_rng(&mut rng);
    let pk = sk.public_key();
    let sig = sk.sign(message);
    let k_digest = pk.compute_challenge_k(message, &sig);
    (pk.to_bytes().to_vec(), k_digest, sig.to_bytes())
}

#[test]
fn test_eddsa_verify_prehash_valid_signature_succeeds() {
    let message = Word::new([Felt::new_unchecked(1); 4]);
    let (pk, k_digest, sig) = eddsa_valid_triple(message);
    let buf_felts = pack_eddsa_buffer(&pk, &k_digest, &sig);

    let memory_stores = masm_store_felts(&buf_felts, BUF_ADDR);
    let source = format!(
        r#"
            use miden::core::crypto::dsa::eddsa_ed25519
            use miden::core::sys

            begin
                {memory_stores}
                push.{BUF_ADDR}
                exec.eddsa_ed25519::verify_prehash
                exec.sys::truncate_stack
            end
        "#,
    );
    build_debug_test!(source, &[]).expect_stack(&[]);
}

#[test]
fn test_eddsa_verify_prehash_invalid_signature_traps() {
    let message = Word::new([Felt::new_unchecked(1); 4]);
    let (pk, k_digest, mut sig) = eddsa_valid_triple(message);
    sig[0] ^= 0xff; // tamper

    let buf_felts = pack_eddsa_buffer(&pk, &k_digest, &sig);
    let memory_stores = masm_store_felts(&buf_felts, BUF_ADDR);
    let source = format!(
        r#"
            use miden::core::crypto::dsa::eddsa_ed25519

            begin
                {memory_stores}
                push.{BUF_ADDR}
                exec.eddsa_ed25519::verify_prehash
            end
        "#,
    );
    let result = build_debug_test!(source, &[]).execute();
    assert!(result.is_err(), "tampered signature must trap execution");
}

// VERIFY — high-level wrapper that recomputes k_digest via SHA-512
// ================================================================================================

const EVENT_EDDSA_SIG_TO_STACK: EventName = EventName::new("test::eddsa::sig_to_stack");

struct EddsaSignatureHandler {
    secret_key_bytes: Vec<u8>,
}

impl EddsaSignatureHandler {
    fn new(secret_key: &SecretKey) -> Self {
        Self { secret_key_bytes: secret_key.to_bytes().to_vec() }
    }
}

impl EventHandler for EddsaSignatureHandler {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let provided_pk_commitment = process.get_stack_word(1);
        let secret_key =
            SecretKey::read_from_bytes(&self.secret_key_bytes).expect("invalid test secret key");
        let pk = secret_key.public_key();
        let pk_commitment = {
            let pk_felts = bytes_to_packed_u32_elements(&pk.to_bytes());
            Poseidon2::hash_elements(&pk_felts)
        };
        assert_eq!(
            provided_pk_commitment, pk_commitment,
            "public key commitment mismatch",
        );

        let message = process.get_stack_word(5);
        let calldata = eddsa_sign(&secret_key, message);
        Ok(vec![AdviceMutation::extend_stack(calldata)])
    }
}

#[test]
fn test_eddsa_verify_end_to_end() {
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
            use miden::core::crypto::dsa::eddsa_ed25519

            begin
                push.{message}
                push.{pk_commitment}
                emit.event("{EVENT_EDDSA_SIG_TO_STACK}")
                exec.eddsa_ed25519::verify
            end
        "#,
    );

    let test = build_debug_test!(&source)
        .with_event_handler(EVENT_EDDSA_SIG_TO_STACK, EddsaSignatureHandler::new(&secret_key));
    test.expect_stack(&[]);
}
