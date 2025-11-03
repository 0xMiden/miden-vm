//! Tests for ECDSA secp256k1 precompile.
//!
//! Validates that:
//! - Raw event handlers correctly perform ECDSA verification and populate advice provider
//! - MASM wrapper correctly returns commitment, tag, and result on stack
//! - Both valid and invalid signatures are handled correctly

use miden_core::{
    Felt, FieldElement,
    precompile::{PrecompileCommitment, PrecompileVerifier},
    utils::Serializable,
};
use miden_crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_stdlib::handlers::{
    bytes_to_packed_u32_felts,
    ecdsa::{EcdsaPrecompile, EcdsaRequest},
};
use rand::{SeedableRng, rngs::StdRng};

use crate::helpers::masm_store_felts;

// TEST CONSTANTS
// ================================================================================================

const PK_ADDR: u32 = 128;
const DIGEST_ADDR: u32 = 192;
const SIG_ADDR: u32 = 256;

// TESTS
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
                use.std::crypto::dsa::ecdsa::secp256k1
                use.std::sys

                begin
                    # Store test data in memory
                    {memory_stores}

                    # Call verify: [ptr_pk, ptr_digest, ptr_sig]
                    push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                    exec.secp256k1::verify
                    # => [result, ...]

                    exec.sys::truncate_stack
                end
            ",
        );

        let test = build_debug_test!(source, &[]);
        let output = test.execute().unwrap();

        // Assert result
        let result = output.stack_outputs().get_stack_item(0).unwrap();
        let expected = if expected_valid { Felt::ONE } else { Felt::ZERO };
        assert_eq!(result, expected);

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
            use.std::crypto::dsa::ecdsa::secp256k1
            use.std::sys

            begin
                # Store test data in memory
                {memory_stores}

                # Call verify_impl: [ptr_pk, ptr_digest, ptr_sig]
                push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                exec.secp256k1::verify_impl
                # => [COMM, TAG, result, ...]

                exec.sys::truncate_stack
            end
        ",
        );

        let test = build_debug_test!(source, &[]);
        let output = test.execute().unwrap();
        let stack = output.stack_outputs();

        // Verify stack layout: [COMM (0-3), TAG (4-7), result (at position 6 = TAG[1]), ...]
        let commitment = stack.get_stack_word_be(0).unwrap();
        let tag = stack.get_stack_word_be(4).unwrap();
        // Commitment and tag must match verifier output
        let precompile_commitment = PrecompileCommitment::new(tag, commitment);
        let verifier_commitment =
            EcdsaPrecompile.verify(&request.to_bytes()).expect("verifier should succeed");
        assert_eq!(
            precompile_commitment, verifier_commitment,
            "commitment on stack should match verifier output"
        );

        // Verify result
        let result = stack.get_stack_item(6).unwrap();
        assert_eq!(result, Felt::from(expected_valid), "result does not match expected validity");

        let deferred = output.advice_provider().precompile_requests().to_vec();
        assert_eq!(deferred.len(), 1, "expected a single deferred request");
        assert_eq!(deferred[0], request.as_precompile_request());

        let advice_stack = output.advice_provider().stack();
        assert!(advice_stack.is_empty(), "advice stack should be empty after verify_impl");
    }
}

// TEST DATA GENERATION
// ================================================================================================

/// Generates a valid signature using deterministic seed
fn generate_valid_signature() -> EcdsaRequest {
    let mut rng = StdRng::seed_from_u64(42);
    let mut secret_key = SecretKey::with_rng(&mut rng);
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
    let mut secret_key2 = SecretKey::with_rng(&mut rng2);

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
    let pk_words = bytes_to_packed_u32_felts(&request.pk().to_bytes());
    let digest_words = bytes_to_packed_u32_felts(request.digest());
    let sig_words = bytes_to_packed_u32_felts(&request.sig().to_bytes());

    [
        masm_store_felts(&pk_words, PK_ADDR),
        masm_store_felts(&digest_words, DIGEST_ADDR),
        masm_store_felts(&sig_words, SIG_ADDR),
    ]
    .join(" ")
}
