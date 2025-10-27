//! Tests for EdDSA (Ed25519) precompile.
//!
//! Validates that:
//! - Raw event handler verifies signatures using pre-computed k-digests
//! - MASM wrapper returns `[COMM, TAG, result]` and logs deferred requests
//! - Both valid and invalid signature scenarios behave as expected

use core::convert::TryFrom;

use miden_core::{
    Felt, FieldElement, Word,
    precompile::{PrecompileCommitment, PrecompileVerifier},
    utils::Serializable,
};
use miden_crypto::dsa::eddsa_25519::{PublicKey, SecretKey, Signature};
use miden_stdlib::handlers::eddsa25519::{EddsaPrecompile, EddsaRequest};
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha512};

use crate::helpers::masm_store_packed_bytes;

// TEST CONSTANTS
// ================================================================================================

const PK_ADDR: u32 = 128;
const K_DIGEST_ADDR: u32 = 192;
const SIG_ADDR: u32 = 256;

// TESTS
// ================================================================================================

#[test]
fn test_eddsa_verify_cases() {
    let test_cases = vec![
        (generate_valid_request(), true),
        (generate_invalid_request_wrong_digest(), false),
    ];

    for (request, expected_valid) in test_cases {
        let memory_stores = generate_memory_store_masm(&request);
        let source = format!(
            "
                use.std::crypto::dsa::eddsa::ed25519
                use.std::sys

                begin
                    {memory_stores}

                    push.{SIG_ADDR}.{K_DIGEST_ADDR}.{PK_ADDR}
                    exec.ed25519::verify

                    exec.sys::truncate_stack
                end
            ",
        );

        let test = build_debug_test!(source, &[]);
        let output = test.execute().unwrap();

        let result = output.stack_outputs().get_stack_item(0).unwrap();
        let expected = if expected_valid { Felt::ONE } else { Felt::ZERO };
        assert_eq!(result, expected, "verification result mismatch");

        let deferred = output.advice_provider().precompile_requests().to_vec();
        assert_eq!(deferred.len(), 1, "expected one deferred request");
        assert_eq!(deferred[0], request.as_precompile_request());
    }
}

#[test]
fn test_eddsa_verify_impl_commitment() {
    let test_cases = vec![
        (generate_valid_request(), true),
        (generate_invalid_request_wrong_digest(), false),
    ];

    for (request, expected_valid) in test_cases {
        let memory_stores = generate_memory_store_masm(&request);
        let source = format!(
            "
                use.std::crypto::dsa::eddsa::ed25519
                use.std::sys

                begin
                    {memory_stores}

                    push.{SIG_ADDR}.{K_DIGEST_ADDR}.{PK_ADDR}
                    exec.ed25519::verify_impl

                    exec.sys::truncate_stack
                end
            ",
        );

        let test = build_debug_test!(source, &[]);
        let output = test.execute().unwrap();
        let stack = output.stack_outputs();

        let commitment = stack.get_stack_word_be(0).unwrap();
        let tag = stack.get_stack_word_be(4).unwrap();
        let precompile_commitment = PrecompileCommitment::new(tag, commitment);

        let verifier_commitment =
            EddsaPrecompile.verify(&request.to_bytes()).expect("verifier should succeed");
        assert_eq!(precompile_commitment, verifier_commitment);

        let result = stack.get_stack_item(6).unwrap();
        assert_eq!(result, Felt::from(expected_valid));

        let deferred = output.advice_provider().precompile_requests().to_vec();
        assert_eq!(deferred.len(), 1, "expected one deferred request");
        assert_eq!(deferred[0], request.as_precompile_request());

        assert!(
            output.advice_provider().stack().is_empty(),
            "advice stack should be empty after verify_impl"
        );
    }
}

// TEST DATA GENERATION
// ================================================================================================

fn generate_valid_request() -> EddsaRequest {
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key = SecretKey::with_rng(&mut rng);
    let pk = secret_key.public_key();

    let message_bytes = [1u8; 32];
    let message = Word::try_from(message_bytes).expect("message bytes are valid word");
    let sig = secret_key.sign(message);
    let k_digest = compute_k_digest(&pk, message, &sig);

    EddsaRequest::new(pk, k_digest, sig)
}

fn generate_invalid_request_wrong_digest() -> EddsaRequest {
    let mut rng = StdRng::seed_from_u64(123);
    let secret_key = SecretKey::with_rng(&mut rng);
    let pk = secret_key.public_key();

    let message_bytes = [2u8; 32];
    let message = Word::try_from(message_bytes).expect("message bytes are valid word");
    let sig = secret_key.sign(message);

    // Compute correct digest then corrupt it to ensure verification fails.
    let mut k_digest = compute_k_digest(&pk, message, &sig);
    k_digest[0] ^= 0x01;

    EddsaRequest::new(pk, k_digest, sig)
}

fn compute_k_digest(pk: &PublicKey, message: Word, sig: &Signature) -> [u8; 64] {
    let sig_bytes = sig.to_bytes();
    let r_bytes = &sig_bytes[..32];
    let pk_bytes = pk.to_bytes();
    let message_bytes: [u8; 32] = message.into();

    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(pk_bytes);
    hasher.update(message_bytes);
    hasher.finalize().into()
}

// MASM GENERATION HELPERS
// ================================================================================================

fn generate_memory_store_masm(request: &EddsaRequest) -> String {
    [
        masm_store_packed_bytes(&request.pk().to_bytes(), PK_ADDR),
        masm_store_packed_bytes(request.k_digest(), K_DIGEST_ADDR),
        masm_store_packed_bytes(&request.sig().to_bytes(), SIG_ADDR),
    ]
    .join(" ")
}
