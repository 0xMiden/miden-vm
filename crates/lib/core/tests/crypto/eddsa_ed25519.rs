//! Tests for EdDSA (Ed25519) precompile.
//!
//! Validates that:
//! - Prehash flow (k-digest provided by the caller) works via `verify_prehash` and
//!   `verify_prehash_impl`
//! - Full message flow recomputes k-digest via SHA2-512 and verifies signatures
//! - Deferred requests logged by the runtime match expected host-side requests

use core::convert::TryFrom;

use miden_core::{
    EventName, Felt, Word,
    field::{PrimeCharacteristicRing, PrimeField64},
    precompile::{PrecompileCommitment, PrecompileVerifier},
    utils::{Deserializable, Serializable, bytes_to_packed_u32_elements},
};
use miden_core_lib::{
    dsa::eddsa_ed25519::sign as eddsa_sign,
    handlers::eddsa_ed25519::{EddsaPrecompile, EddsaRequest},
};
use miden_crypto::{
    dsa::eddsa_25519_sha512::{PublicKey, SecretKey, Signature},
    hash::rpo::Rpo256,
};
use miden_processor::{AdviceMutation, EventError, EventHandler, ProcessorState};
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha512};

use crate::helpers::masm_store_felts;

// TEST CONSTANTS
// ================================================================================================

const PK_ADDR: u32 = 128;
const K_DIGEST_ADDR: u32 = 192;
const SIG_ADDR: u32 = 256;
const MSG_ADDR: u32 = 320;

#[test]
fn test_eddsa_verify_prehash_cases() {
    let valid = generate_valid_data();
    let valid_request = valid.request();
    let invalid = generate_invalid_signature_data();
    let invalid_request = invalid.request();

    let memory_stores = generate_memory_store_masm(&valid_request, &valid.message);
    let source = format!(
        "
            use miden::core::crypto::dsa::eddsa_ed25519
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{K_DIGEST_ADDR}.{PK_ADDR}
                exec.eddsa_ed25519::verify_prehash

                exec.sys::truncate_stack
            end
        ",
    );

    let test = build_debug_test!(source, &[]);
    let output = test.execute().unwrap();

    let result = output.stack_outputs().get_element(0).unwrap();
    assert_eq!(result, Felt::ONE, "verification result mismatch");

    let deferred = output.advice_provider().precompile_requests().to_vec();
    assert_eq!(deferred.len(), 1, "expected one deferred request");
    assert_eq!(deferred[0], valid_request.as_precompile_request());

    // Invalid signature case
    let memory_stores = generate_memory_store_masm(&invalid_request, &invalid.message);
    let source = format!(
        "
            use miden::core::crypto::dsa::eddsa_ed25519
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{K_DIGEST_ADDR}.{PK_ADDR}
                exec.eddsa_ed25519::verify_prehash

                exec.sys::truncate_stack
            end
        ",
    );

    let test = build_debug_test!(source, &[]);
    let output = test.execute().unwrap();

    let result = output.stack_outputs().get_element(0).unwrap();
    assert_eq!(result, Felt::ZERO, "verification result mismatch");

    let deferred = output.advice_provider().precompile_requests().to_vec();
    assert_eq!(deferred.len(), 1, "expected one deferred request");
    assert_eq!(deferred[0], invalid_request.as_precompile_request());
}

#[test]
fn test_eddsa_verify_prehash_impl_commitment() {
    let valid = generate_valid_data();
    let invalid = generate_invalid_signature_data();

    let test_cases = vec![
        (valid.request(), valid.message, true),
        (invalid.request(), invalid.message, false),
    ];

    for (request, message, expected_valid) in test_cases {
        let memory_stores = generate_memory_store_masm(&request, &message);
        let source = format!(
            "
            use miden::core::crypto::dsa::eddsa_ed25519
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{K_DIGEST_ADDR}.{PK_ADDR}
                exec.eddsa_ed25519::verify_prehash_impl

                exec.sys::truncate_stack
            end
        ",
        );

        let test = build_debug_test!(source, &[]);
        let output = test.execute().unwrap();
        let stack = output.stack_outputs();

        let commitment = stack.get_word(0).unwrap();
        let tag = stack.get_word(4).unwrap();
        let precompile_commitment = PrecompileCommitment::new(tag, commitment);

        let verifier_commitment =
            EddsaPrecompile.verify(&request.to_bytes()).expect("verifier should succeed");
        assert_eq!(precompile_commitment, verifier_commitment);

        // Verify result - TAG[1] is at position 5 (TAG is at positions 4-7)
        let result = stack.get_element(5).unwrap();
        assert_eq!(result, Felt::from_bool(expected_valid));

        let deferred = output.advice_provider().precompile_requests().to_vec();
        assert_eq!(deferred.len(), 1, "expected a single deferred request");
        assert_eq!(deferred[0], request.as_precompile_request());

        assert!(
            output.advice_provider().stack().is_empty(),
            "advice stack should be empty after verify_prehash_impl"
        );
    }
}

#[test]
fn test_eddsa_verify_with_message() {
    let message = Word::new([1, 2, 3, 4].map(Felt::new));

    let mut rng = StdRng::seed_from_u64(42);
    let secret_key = SecretKey::with_rng(&mut rng);

    // Compute public key commitment
    let pk_felts = bytes_to_packed_u32_elements(&secret_key.public_key().to_bytes());
    let pk_commitment = Rpo256::hash_elements(&pk_felts);

    let advice: Vec<_> =
        eddsa_sign(&secret_key, message).iter().map(Felt::as_canonical_u64).collect();

    // Use push.{word} syntax for correct LE stack layout
    let source = format!(
        "
            use miden::core::crypto::dsa::eddsa_ed25519
            use miden::core::sys

            begin
                push.{message}
                push.{pk_commitment}
                exec.eddsa_ed25519::verify

                exec.sys::truncate_stack
            end
        "
    );

    let test = build_debug_test!(&source, &[], &advice);

    let _ = test.execute().unwrap();
}

// TESTS HIGH-LEVEL WRAPPER
// ================================================================================================

const EVENT_EDDSA_SIG_TO_STACK: EventName = EventName::new("test::eddsa::sig_to_stack");

struct EddsaSignatureHandler {
    secret_key_bytes: Vec<u8>,
}

impl EddsaSignatureHandler {
    fn new(secret_key: &SecretKey) -> Self {
        Self {
            secret_key_bytes: secret_key.to_bytes().to_vec(),
        }
    }
}

impl EventHandler for EddsaSignatureHandler {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        // Stack layout: [event_id, pk_commitment(1-4), message(5-8), ...]
        // Position 0 has the event ID, so pk_commitment starts at position 1
        let provided_pk_rpo = process.get_stack_word(1);
        let secret_key =
            SecretKey::read_from_bytes(&self.secret_key_bytes).expect("invalid test secret key");
        let pk_commitment = {
            let pk = secret_key.public_key();
            let pk_felts = bytes_to_packed_u32_elements(&pk.to_bytes());
            Rpo256::hash_elements(&pk_felts)
        };
        assert_eq!(
            provided_pk_rpo, pk_commitment,
            "public key commitment mismatch: expected {:?}, got {:?}",
            pk_commitment, provided_pk_rpo
        );

        // Message starts at position 5 (after event_id + pk_commitment)
        let message = process.get_stack_word(5);
        let calldata = eddsa_sign(&secret_key, message);

        // Use extend_stack to make elements available in order: pk first, then sig
        Ok(vec![AdviceMutation::extend_stack(calldata)])
    }
}

#[test]
fn test_eddsa_verify_high_level_wrapper() {
    let mut rng = StdRng::seed_from_u64(19260817);
    let secret_key = SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();
    let message = Word::from([Felt::new(11), Felt::new(22), Felt::new(33), Felt::new(44)]);

    let pk_commitment = {
        let pk_felts = bytes_to_packed_u32_elements(&public_key.to_bytes());
        Rpo256::hash_elements(&pk_felts)
    };

    let source = format!(
        "
        use miden::core::crypto::dsa::eddsa_ed25519

        begin
            push.{message} push.{pk_commitment}
            emit.event(\"{EVENT_EDDSA_SIG_TO_STACK}\")
            exec.eddsa_ed25519::verify
        end
        ",
    );

    let mut test = build_debug_test!(&source);
    test.add_event_handler(EVENT_EDDSA_SIG_TO_STACK, EddsaSignatureHandler::new(&secret_key));

    test.expect_stack(&[]);
    test.execute().unwrap();
}

// TEST DATA GENERATION
// ================================================================================================

#[derive(Clone)]
struct EddsaTestData {
    pk: PublicKey,
    message: [u8; 32],
    sig: Signature,
}

impl EddsaTestData {
    fn request(&self) -> EddsaRequest {
        EddsaRequest::new(self.pk.clone(), self.digest(), self.sig.clone())
    }

    fn digest(&self) -> [u8; 64] {
        compute_k_digest_bytes(&self.pk, &self.message, &self.sig)
    }
}

fn generate_valid_data() -> EddsaTestData {
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key = SecretKey::with_rng(&mut rng);
    let pk = secret_key.public_key();
    let message = Word::new([1, 2, 3, 4].map(Felt::new));
    let sig = secret_key.sign(message);
    let message_bytes: Vec<_> = message
        .into_iter()
        .flat_map(|felt| felt.as_canonical_u64().to_le_bytes())
        .collect();

    EddsaTestData {
        pk,
        message: message_bytes.try_into().unwrap(),
        sig,
    }
}

fn generate_invalid_signature_data() -> EddsaTestData {
    let mut rng_pk = StdRng::seed_from_u64(42);
    let primary_sk = SecretKey::with_rng(&mut rng_pk);
    let pk = primary_sk.public_key();

    let mut rng_other = StdRng::seed_from_u64(999);
    let other_sk = SecretKey::with_rng(&mut rng_other);

    let message = [3u8; 32];
    let sig = other_sk.sign(Word::try_from(message).expect("valid message"));
    EddsaTestData { pk, message, sig }
}

fn compute_k_digest_bytes(pk: &PublicKey, message: &[u8; 32], sig: &Signature) -> [u8; 64] {
    let sig_bytes = sig.to_bytes();
    let r_bytes = &sig_bytes[..32];
    let pk_bytes = pk.to_bytes();

    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(pk_bytes);
    hasher.update(message);
    hasher.finalize().into()
}

// MASM GENERATION HELPERS
// ================================================================================================

fn generate_memory_store_masm(request: &EddsaRequest, message: &[u8; 32]) -> String {
    let pk_felts = bytes_to_packed_u32_elements(&request.pk().to_bytes());
    let k_digest_felts = bytes_to_packed_u32_elements(&request.k_digest().to_bytes());
    let sig_felts = bytes_to_packed_u32_elements(&request.sig().to_bytes());
    let msg_felts = bytes_to_packed_u32_elements(message);

    [
        masm_store_felts(&pk_felts, PK_ADDR),
        masm_store_felts(&k_digest_felts, K_DIGEST_ADDR),
        masm_store_felts(&sig_felts, SIG_ADDR),
        masm_store_felts(&msg_felts, MSG_ADDR),
    ]
    .join(" ")
}
