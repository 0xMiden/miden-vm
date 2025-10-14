//! Tests for ECDSA secp256k1 precompile.
//!
//! Validates that the ECDSA signature verification precompile works correctly through
//! a complete prove/verify workflow.

use std::sync::Arc;

use miden_air::ProvingOptions;
use miden_assembly::Assembler;
use miden_core::{
    Felt, FieldElement, ProgramInfo, Word,
    precompile::{PrecompileCommitment, PrecompileVerifierRegistry},
};
use miden_crypto::{dsa::ecdsa_k256_keccak::SecretKey, hash::rpo::Rpo256, utils::Serializable};
use miden_processor::{AdviceInputs, DefaultHost, Program, StackInputs};
use miden_stdlib::{
    StdLibrary,
    handlers::ecdsa::{ECDSA_VERIFY_EVENT_ID, EcdsaPrecompile},
};
use rand::rng;

// Test constants
const PK_ADDR: u32 = 0;
const SIG_ADDR: u32 = 64;
const DIGEST_ADDR: u32 = 128;

#[test]
fn test_ecdsa_verify_prove_verify() {
    // Generate test data: use sign_prehash with a simple digest
    let mut rng = rng();
    let mut secret_key = SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Simple fixed 32-byte digest
    let digest = [1u8; 32];
    let signature = secret_key.sign_prehash(digest);

    // Serialize to bytes
    let mut pk_bytes = vec![];
    public_key.write_into(&mut pk_bytes);
    let mut sig_bytes = vec![];
    signature.write_into(&mut sig_bytes);

    // Generate MASM memory stores
    let mut stores = vec![];
    let digest_vec = digest.to_vec();
    for (addr, bytes) in [(PK_ADDR, &pk_bytes), (SIG_ADDR, &sig_bytes), (DIGEST_ADDR, &digest_vec)]
    {
        for (i, chunk) in bytes.chunks(4).enumerate() {
            let mut array = [0u8; 4];
            array[..chunk.len()].copy_from_slice(chunk);
            let value = u32::from_le_bytes(array);
            stores.push(format!("push.{value} push.{} mem_store", addr + i as u32));
        }
    }
    let memory_stores = stores.join(" ");

    // MASM program
    let source = format!(
        r#"
            use.std::crypto::dsa::ecdsa::secp256k1
            use.std::sys

            begin
                # Store test data in memory
                {memory_stores}

                # Call verify_impl: [ptr_pk, ptr_digest, ptr_sig]
                push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                exec.secp256k1::verify_impl
                # => [COMM, TAG, result]

                exec.sys::truncate_stack
            end
            "#,
    );

    // Compile and set up
    let program: Program = Assembler::default()
        .with_dynamic_library(StdLibrary::default())
        .expect("failed to load stdlib")
        .assemble_program(source)
        .expect("failed to compile test source");

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

    // Verify commitment on stack
    // Stack layout after verify_impl: [COMM (0-3), TAG (4-7), result would be at 8 but TAG is
    // reversed] Actual layout: [COMM[0-3], TAG[3], TAG[2], TAG[1], TAG[0], ...]
    let stack_commitment = stack_outputs.get_stack_word(0).unwrap();

    // TAG elements are in positions 4-7 but need to be read as [7, 6, 5, 4]
    let stack_tag = Word::from([
        stack_outputs.get_stack_item(7).unwrap(),
        stack_outputs.get_stack_item(6).unwrap(),
        stack_outputs.get_stack_item(5).unwrap(),
        stack_outputs.get_stack_item(4).unwrap(),
    ]);
    let precompile_commitment = PrecompileCommitment {
        tag: stack_tag,
        commitment: stack_commitment,
    };

    // Result is at position 6 (which is TAG[1])
    let result = stack_outputs.get_stack_item(6).unwrap();
    assert_eq!(result, Felt::ONE, "signature should be valid");

    // Verify tag format
    assert_eq!(
        stack_tag,
        Word::from([ECDSA_VERIFY_EVENT_ID.as_felt(), Felt::ONE, Felt::ZERO, Felt::ZERO])
    );

    // Verify precompile verifier produces same commitment
    let mut precompile_verifiers = PrecompileVerifierRegistry::new();
    precompile_verifiers.register(ECDSA_VERIFY_EVENT_ID, Arc::new(EcdsaPrecompile));
    let deferred_commitment = precompile_verifiers
        .deferred_requests_commitment(proof.precompile_requests())
        .expect("failed to verify");

    let deferred_commitment_expected = {
        let elements = [
            precompile_commitment.tag,
            precompile_commitment.commitment,
            Word::empty(),
            Word::empty(),
        ];
        Rpo256::hash_elements(Word::words_as_elements(&elements))
    };
    assert_eq!(deferred_commitment_expected, deferred_commitment);

    // Verify the proof
    let program_info = ProgramInfo::from(program);
    let (_, verifier_commitment) = miden_verifier::verify_with_precompiles(
        program_info,
        stack_inputs,
        stack_outputs,
        proof,
        &precompile_verifiers,
    )
    .expect("proof verification failed");

    assert_eq!(
        deferred_commitment_expected, verifier_commitment,
        "verifier commitment should match"
    );
}

#[test]
fn test_ecdsa_invalid_signature() {
    // Test with invalid signature
    let mut rng = rng();
    let mut secret_key = SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Simple fixed digest
    let digest = [1u8; 32];
    let signature = secret_key.sign_prehash(digest);

    // Serialize and corrupt signature
    let mut pk_bytes = vec![];
    public_key.write_into(&mut pk_bytes);
    let mut sig_bytes = vec![];
    signature.write_into(&mut sig_bytes);
    sig_bytes[0] ^= 0xff; // Corrupt first byte

    // Generate MASM
    let mut stores = vec![];
    let digest_vec = digest.to_vec();
    for (addr, bytes) in [(PK_ADDR, &pk_bytes), (SIG_ADDR, &sig_bytes), (DIGEST_ADDR, &digest_vec)]
    {
        for (i, chunk) in bytes.chunks(4).enumerate() {
            let mut array = [0u8; 4];
            array[..chunk.len()].copy_from_slice(chunk);
            stores.push(format!(
                "push.{} push.{} mem_store",
                u32::from_le_bytes(array),
                addr + i as u32
            ));
        }
    }

    let source = format!(
        r#"
            use.std::crypto::dsa::ecdsa::secp256k1
            begin
                {}
                push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                exec.secp256k1::verify
            end
            "#,
        stores.join(" ")
    );

    let test = build_debug_test!(source, &[]);
    test.expect_stack(&[0]); // Should return 0 (invalid)
}
