//! Tests for ECDSA secp256k1 precompile.
//!
//! Validates that:
//! - Raw event handlers correctly perform ECDSA verification and populate advice provider
//! - MASM wrapper correctly returns commitment, tag, and result on stack
//! - Both valid and invalid signatures are handled correctly

use miden_core::{
    EventName, Felt, Word,
    field::PrimeCharacteristicRing,
    precompile::{PrecompileCommitment, PrecompileVerifier},
    utils::{Deserializable, Serializable, bytes_to_packed_u32_elements},
};
use miden_core_lib::{
    dsa::ecdsa_k256_keccak::sign as ecdsa_sign,
    handlers::ecdsa::{EcdsaPrecompile, EcdsaRequest},
};
use miden_crypto::{dsa::ecdsa_k256_keccak::SecretKey, hash::rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, EventHandler, ProcessorState};
use rand::{SeedableRng, rngs::StdRng};

use crate::helpers::masm_store_felts;

// TEST CONSTANTS
// ================================================================================================

const PK_ADDR: u32 = 128;
const DIGEST_ADDR: u32 = 192;
const SIG_ADDR: u32 = 256;

// TESTS PRECOMPILE
// ================================================================================================

#[test]
fn test_ecdsa_verify_cases() {
    // One valid and one invalid (wrong key) request
    let test_cases = vec![
        (generate_valid_signature(), true),
        (generate_invalid_signature_wrong_key(), false),
    ];

    for (request, expected_valid) in test_cases {
        let memory_stores = generate_memory_store_masm(&request);

        let source = format!(
            "
                use miden::core::crypto::dsa::ecdsa_k256_keccak
                use miden::core::sys

                begin
                    # Store test data in memory
                    {memory_stores}

                    # Call verify: [ptr_pk, ptr_digest, ptr_sig]
                    push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                    exec.ecdsa_k256_keccak::verify_prehash
                    # => [result, ...]

                    exec.sys::truncate_stack
                end
            ",
        );

        let test = build_debug_test!(source, &[]);
        let output = test.execute().unwrap();

        // Assert result
        let result = output.stack_outputs().get_element(0).unwrap();
        assert_eq!(result, Felt::from_bool(expected_valid));

        // Verify the precompile request was logged with the right event ID
        let deferred = output.advice_provider().precompile_requests().to_vec();
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0], request.as_precompile_request());
    }
}

#[test]
fn test_ecdsa_verify_impl_commitment() {
    // One valid and one invalid (wrong key) request
    let test_cases = vec![
        (generate_valid_signature(), true),
        (generate_invalid_signature_wrong_key(), false),
    ];
    for (request, expected_valid) in test_cases {
        // Verify tag/commitment once on a valid request
        let memory_stores = generate_memory_store_masm(&request);

        let source = format!(
            "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                # Store test data in memory
                {memory_stores}

                # Call verify_impl: [ptr_pk, ptr_digest, ptr_sig]
                push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                exec.ecdsa_k256_keccak::verify_prehash_impl
                # => [COMM, TAG, result, ...]

                exec.sys::truncate_stack
            end
        ",
        );

        let test = build_debug_test!(source, &[]);
        let output = test.execute().unwrap();
        let stack = output.stack_outputs();

        // Verify stack layout: [COMM (0-3), TAG (4-7), result (at position 8), ...]
        // TAG = [event_id, result, 0, 0] where TAG[1]=result is at position 5
        // Use get_stack_word to match LE stack convention
        let commitment = stack.get_word(0).unwrap();
        let tag = stack.get_word(4).unwrap();
        // Commitment and tag must match verifier output
        let precompile_commitment = PrecompileCommitment::new(tag, commitment);
        let verifier_commitment =
            EcdsaPrecompile.verify(&request.to_bytes()).expect("verifier should succeed");
        assert_eq!(
            precompile_commitment, verifier_commitment,
            "commitment on stack should match verifier output"
        );

        // Verify result - TAG[1] is at position 5 (TAG is at positions 4-7)
        let result = stack.get_element(5).unwrap();
        assert_eq!(
            result,
            Felt::from_bool(expected_valid),
            "result does not match expected validity"
        );

        let deferred = output.advice_provider().precompile_requests().to_vec();
        assert_eq!(deferred.len(), 1, "expected a single deferred request");
        assert_eq!(deferred[0], request.as_precompile_request());

        let advice_stack = output.advice_provider().stack();
        assert!(advice_stack.is_empty(), "advice stack should be empty after verify_impl");
    }
}

// TESTS SIGN+VERIFY
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
        let calldata = ecdsa_sign(&secret_key, message);

        // Use extend_stack to make elements available in order: pk first, then sig
        Ok(vec![AdviceMutation::extend_stack(calldata)])
    }
}

#[test]
fn test_ecdsa_verify_bis_wrapper() {
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
        use miden::core::crypto::dsa::ecdsa_k256_keccak

        begin
            push.{message}
            push.{pk_commitment}
            emit.event(\"{EVENT_ECDSA_SIG_TO_STACK}\")
            exec.ecdsa_k256_keccak::verify
        end
        ",
    );

    let mut test = build_debug_test!(&source);
    test.add_event_handler(EVENT_ECDSA_SIG_TO_STACK, EcdsaSignatureHandler::new(&secret_key));

    test.expect_stack(&[]);
}

// TEST DATA GENERATION
// ================================================================================================

/// Generates a valid signature using deterministic seed
fn generate_valid_signature() -> EcdsaRequest {
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key = SecretKey::with_rng(&mut rng);
    let pk = secret_key.public_key();

    // Use a simple deterministic digest
    let digest = [1u8; 32];
    let sig = secret_key.sign_prehash(digest);

    EcdsaRequest::new(pk, digest, sig)
}

/// Generates an invalid signature by signing with a different key
fn generate_invalid_signature_wrong_key() -> EcdsaRequest {
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key1 = SecretKey::with_rng(&mut rng);
    let pk = secret_key1.public_key();

    // Create a different key for signing
    let mut rng2 = StdRng::seed_from_u64(123);
    let secret_key2 = SecretKey::with_rng(&mut rng2);

    let digest = [1u8; 32];
    let sig = secret_key2.sign_prehash(digest);

    EcdsaRequest::new(pk, digest, sig)
}

// MASM GENERATION HELPERS
// ================================================================================================

/// Generates MASM code to store test data (pk, digest, sig) into memory as packed u32 values.
///
/// Memory layout:
/// - Public key: PK_ADDR (33 bytes)
/// - Digest: DIGEST_ADDR (32 bytes)
/// - Signature: SIG_ADDR (66 bytes)
fn generate_memory_store_masm(request: &EcdsaRequest) -> String {
    let pk_words = bytes_to_packed_u32_elements(&request.pk().to_bytes());
    let digest_words = bytes_to_packed_u32_elements(request.digest());
    let sig_words = bytes_to_packed_u32_elements(&request.sig().to_bytes());

    [
        masm_store_felts(&pk_words, PK_ADDR),
        masm_store_felts(&digest_words, DIGEST_ADDR),
        masm_store_felts(&sig_words, SIG_ADDR),
    ]
    .join(" ")
}
