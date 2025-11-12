//! Tests for Keccak256 precompile event handlers.
//!
//! Verifies that:
//! - Raw event handlers correctly compute Keccak256 and populate advice provider
//! - MASM wrappers correctly return commitment and digest on stack
//! - Both memory and digest merge operations work correctly
//! - Various input sizes and edge cases are handled properly

use core::array;

use miden_core::{
    Felt,
    precompile::{PrecompileCommitment, PrecompileVerifier},
};
use miden_stdlib::handlers::keccak256::{
    KECCAK_HASH_MEMORY_EVENT_NAME, KeccakPrecompile, KeccakPreimage,
};

use crate::helpers::{masm_push_felts, masm_store_felts};

// Test constants
// ================================================================================================

const INPUT_MEMORY_ADDR: u32 = 128;

// TESTS
// ================================================================================================

#[test]
fn test_keccak_handlers() {
    // Test various input sizes including edge cases
    let hash_memory_inputs: Vec<Vec<u8>> = vec![
        // empty
        vec![],
        // representative small sizes and alignments
        vec![1],
        vec![1, 2, 3, 4],
        vec![1, 2, 3, 4, 5],
        // boundary and just-over-boundary
        (0..32).collect(),
        (0..33).collect(),
    ];

    for input in &hash_memory_inputs {
        test_keccak_handler(input);
        test_keccak_hash_memory_impl(input);
        test_keccak_hash_memory(input);
    }
}

fn test_keccak_handler(input_u8: &[u8]) {
    let len_bytes = input_u8.len();
    let preimage = KeccakPreimage::new(input_u8.to_vec());

    let input_felts = preimage.as_felts();
    let memory_stores_source = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

    let source = format!(
        r#"
            begin
                # Store packed u32 values in memory
                {memory_stores_source}

                # Push handler inputs
                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                # => [ptr, len_bytes, ...]

                emit.event("{KECCAK_HASH_MEMORY_EVENT_NAME}")
                drop drop
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);

    let output = test.execute().unwrap();

    let advice_stack = output.advice_provider().stack();
    assert_eq!(advice_stack, preimage.digest().as_ref());

    let deferred = output.advice_provider().precompile_requests().to_vec();
    assert_eq!(deferred.len(), 1, "advice deferred must contain one entry");
    let precompile_data = &deferred[0];

    // PrecompileData contains the raw input bytes directly
    assert_eq!(
        precompile_data.calldata(),
        preimage.as_ref(),
        "data in deferred storage does not match preimage"
    );
}

fn test_keccak_hash_memory_impl(input_u8: &[u8]) {
    let len_bytes = input_u8.len();
    let preimage = KeccakPreimage::new(input_u8.to_vec());

    let input_felts = preimage.as_felts();
    let memory_stores_source = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

    let source = format!(
        r#"
            use std::sys
            use std::crypto::hashes::keccak256

            begin
                # Store packed u32 values in memory
                {memory_stores_source}

                # Push wrapper inputs
                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                # => [ptr, len_bytes]

                exec.keccak256::hash_memory_impl
                # => [COMM, TAG, DIGEST_U32[8]]

                exec.sys::truncate_stack
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);

    let output = test.execute().unwrap();

    let stack = output.stack_outputs();
    let commitment = stack.get_stack_word_be(0).unwrap();
    let tag = stack.get_stack_word_be(4).unwrap();
    let precompile_commitment = PrecompileCommitment::new(tag, commitment);
    let verifier_commitment = KeccakPrecompile.verify(preimage.as_ref()).unwrap();
    assert_eq!(precompile_commitment, verifier_commitment);

    // Digest occupies the elements after COMM/TAG
    let digest: [Felt; 8] = array::from_fn(|i| stack.get_stack_item(8 + i).unwrap());
    assert_eq!(&digest, preimage.digest().as_ref(), "output digest does not match");

    let deferred = output.advice_provider().precompile_requests().to_vec();
    assert_eq!(deferred.len(), 1, "expected a single deferred request");
    assert_eq!(deferred[0].event_id(), KECCAK_HASH_MEMORY_EVENT_NAME.to_event_id());
    assert_eq!(deferred[0].calldata(), preimage.as_ref());
    assert_eq!(deferred[0], preimage.into());

    let advice_stack = output.advice_provider().stack();
    assert!(advice_stack.is_empty(), "advice stack should be empty after hash_memory_impl");
}

fn test_keccak_hash_memory(input_u8: &[u8]) {
    let len_bytes = input_u8.len();
    let preimage = KeccakPreimage::new(input_u8.to_vec());

    let input_felts = preimage.as_felts();
    let memory_stores_source = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

    let source = format!(
        r#"
            use std::sys
            use std::crypto::hashes::keccak256

            begin
                # Store packed u32 values in memory
                {memory_stores_source}

                # Push wrapper inputs
                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                # => [ptr, len_bytes]

                exec.keccak256::hash_memory
                # => [DIGEST_U32[8]]

                exec.sys::truncate_stack
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);
    let digest: Vec<u64> = preimage.digest().as_ref().iter().map(Felt::as_int).collect();
    test.expect_stack(&digest);
}

#[test]
fn test_keccak_hash_1to1() {
    let input_u8: Vec<u8> = (0..32).collect();
    let preimage = KeccakPreimage::new(input_u8);

    let input_felts = preimage.as_felts();
    let stack_stores_source = masm_push_felts(&input_felts);

    let source = format!(
        r#"
            use std::sys
            use std::crypto::hashes::keccak256

            begin
                # Push input to stack as words with temporary memory pointer
                {stack_stores_source}
                # => [INPUT_LO, INPUT_HI]

                exec.keccak256::hash_1to1
                # => [DIGEST_U32[8]]

                exec.sys::truncate_stack
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);
    let digest: Vec<u64> = preimage.digest().as_ref().iter().map(Felt::as_int).collect();
    test.expect_stack(&digest);
}

#[test]
fn test_keccak_hash_2to1() {
    let input_u8: Vec<u8> = (0..64).collect();
    let preimage = KeccakPreimage::new(input_u8);

    let input_felts = preimage.as_felts();
    let stack_stores_source = masm_push_felts(&input_felts);

    let source = format!(
        r#"
            use std::sys
            use std::crypto::hashes::keccak256

            begin
                # Push input to stack as words with temporary memory pointer
                {stack_stores_source}
                # => [INPUT_L_U32[8], INPUT_R_U32[8]]

                exec.keccak256::hash_2to1
                # => [DIGEST_U32[8]]

                exec.sys::truncate_stack
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);
    let digest: Vec<u64> = preimage.digest().as_ref().iter().map(Felt::as_int).collect();
    test.expect_stack(&digest);
}
