//! Tests for ECDSA secp256k1 precompile.
//!
//! Validates that:
//! - Raw event handlers correctly perform ECDSA verification and populate advice provider
//! - MASM wrapper correctly returns commitment, tag, and result on stack
//! - Both valid and invalid signatures are handled correctly
//! - Full prove/verify workflow succeeds

use std::sync::Arc;

use miden_air::ProvingOptions;
use miden_assembly::Assembler;
use miden_core::{
    Felt, FieldElement, ProgramInfo, Word,
    precompile::{
        PrecompileCommitment, PrecompileTranscript, PrecompileVerifier, PrecompileVerifierRegistry,
    },
    utils::Serializable,
};
use miden_crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_processor::{AdviceInputs, DefaultHost, Program, StackInputs};
use miden_stdlib::{
    StdLibrary,
    handlers::ecdsa::{ECDSA_VERIFY_EVENT_ID, EcdsaPrecompile, EcdsaRequest},
};
use rand::{SeedableRng, rngs::StdRng};
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
    // Verify tag/commitment once on a valid request
    let request = generate_valid_signature();
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
    let tag = Word::from([
        stack.get_stack_item(7).unwrap(),
        stack.get_stack_item(6).unwrap(),
        stack.get_stack_item(5).unwrap(),
        stack.get_stack_item(4).unwrap(),
    ]);

    // Verify result
    let result = stack.get_stack_item(6).unwrap();
    assert_eq!(result, Felt::ONE, "result does not match expected validity");

    // Verify tag format: [event_id, result, 0, 0]
    assert_eq!(tag[0], ECDSA_VERIFY_EVENT_ID.as_felt());
    assert_eq!(tag[1], Felt::ONE);
    assert_eq!(tag[2], Felt::ZERO);
    assert_eq!(tag[3], Felt::ZERO);

    // Commitment and tag must match verifier output
    let precompile_commitment = PrecompileCommitment::new(tag, commitment);
    let verifier_commitment =
        EcdsaPrecompile.verify(&request.to_bytes()).expect("verifier should succeed");

    assert_eq!(
        precompile_commitment, verifier_commitment,
        "commitment on stack should match verifier output"
    );
}

#[test]
fn test_ecdsa_prove_verify() {
    // Test full prove/verify workflow with a valid signature
    let request = generate_valid_signature();
    let memory_stores = generate_memory_store_masm(&request);

    assert!(request.result());

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

    // Compile program
    let program: Program = Assembler::default()
        .with_dynamic_library(StdLibrary::default())
        .expect("failed to load stdlib")
        .assemble_program(source)
        .expect("failed to compile test source");

    // Set up inputs
    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    let stdlib = StdLibrary::default();
    host.load_library(&stdlib).expect("failed to load stdlib");

    // Generate proof
    let options = ProvingOptions::with_96_bit_security(miden_air::HashFunction::Blake3_192);
    let (stack_outputs, proof) = miden_utils_testing::prove(
        &program,
        stack_inputs.clone(),
        advice_inputs,
        &mut host,
        options,
    )
    .expect("failed to generate proof");

    // Verify stack result indicates valid signature
    let result = stack_outputs.get_stack_item(0).unwrap();
    assert_eq!(result, Felt::ONE, "runtime result should be 1 for a valid signature");

    // Verify the logged precompile request contains the expected data
    let proof_requests = proof.precompile_requests();
    assert_eq!(proof_requests.len(), 1, "expected a single precompile request");
    let proof_request = &proof_requests[0];
    assert_eq!(
        proof_request.event_id(),
        ECDSA_VERIFY_EVENT_ID,
        "precompile request should use the ECDSA event ID"
    );
    let expected_request = request.as_precompile_request();
    assert_eq!(
        proof_request.calldata(),
        expected_request.calldata(),
        "logged calldata should match the original request"
    );

    // Build the expected precompile commitment from the logged data
    let precompile_commitment = EcdsaPrecompile
        .verify(proof_request.calldata())
        .expect("verifier should succeed");
    assert_eq!(
        precompile_commitment.tag(),
        Word::from([ECDSA_VERIFY_EVENT_ID.as_felt(), Felt::ONE, Felt::ZERO, Felt::ZERO]),
        "precompile tag should encode [event_id, result, 0, 0]",
    );

    // Set up precompile verifier registry
    let mut precompile_verifiers = PrecompileVerifierRegistry::new();
    precompile_verifiers.register(ECDSA_VERIFY_EVENT_ID, Arc::new(EcdsaPrecompile));

    // Compute expected deferred commitment
    let transcript = precompile_verifiers
        .requests_transcript(proof.precompile_requests())
        .expect("failed to compute deferred commitment");

    let mut expected_transcript = PrecompileTranscript::new();
    expected_transcript.record(precompile_commitment);
    assert_eq!(expected_transcript, transcript);

    // Verify the proof
    let program_info = ProgramInfo::from(program);
    let (_, transcript_digest) = miden_verifier::verify_with_precompiles(
        program_info,
        stack_inputs,
        stack_outputs,
        proof,
        &precompile_verifiers,
    )
    .expect("proof verification failed");

    assert_eq!(transcript.finalize(), transcript_digest, "verifier commitment should match");
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

/// Generates MASM code to store bytes as packed u32 values at the specified memory address.
///
/// Each 4 bytes are packed into a single u32 in little-endian format. Unused bytes in the
/// final u32 are zero-padded.
///
/// # Arguments
/// * `data` - The byte slice to store
/// * `base_addr` - Base memory address to start storing at
///
/// # Returns
/// MASM instruction string that stores all packed u32 values sequentially
fn generate_packed_store_masm(data: &[u8], base_addr: u32) -> String {
    data.chunks(4)
        .enumerate()
        .map(|(i, chunk)| {
            let mut array = [0u8; 4];
            array[..chunk.len()].copy_from_slice(chunk);
            let value = u32::from_le_bytes(array);
            format!("push.{value} push.{} mem_store", base_addr + i as u32)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generates MASM code to store test data (pk, digest, sig) into memory as packed u32 values.
///
/// Memory layout:
/// - Public key: PK_ADDR (33 bytes)
/// - Digest: DIGEST_ADDR (32 bytes)
/// - Signature: SIG_ADDR (66 bytes)
fn generate_memory_store_masm(request: &EcdsaRequest) -> String {
    [
        generate_packed_store_masm(&request.pk().to_bytes(), PK_ADDR),
        generate_packed_store_masm(request.digest(), DIGEST_ADDR),
        generate_packed_store_masm(&request.sig().to_bytes(), SIG_ADDR),
    ]
    .join(" ")
}
