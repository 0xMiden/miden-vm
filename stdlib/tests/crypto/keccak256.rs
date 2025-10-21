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
    KECCAK_HASH_MEMORY_EVENT_ID, KECCAK_HASH_MEMORY_EVENT_NAME, KeccakPrecompile, KeccakPreimage,
};

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

    let memory_stores_source = generate_memory_store_masm(&preimage, INPUT_MEMORY_ADDR);

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

    let memory_stores_source = generate_memory_store_masm(&preimage, INPUT_MEMORY_ADDR);

    let source = format!(
        r#"
            use.std::sys
            use.std::crypto::hashes::keccak256

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
    assert_eq!(deferred[0].event_id(), KECCAK_HASH_MEMORY_EVENT_ID);
    assert_eq!(deferred[0].calldata(), preimage.as_ref());
    assert_eq!(deferred[0], preimage.into());

    let advice_stack = output.advice_provider().stack();
    assert!(advice_stack.is_empty(), "advice stack should be empty after hash_memory_impl");
}

fn test_keccak_hash_memory(input_u8: &[u8]) {
    let len_bytes = input_u8.len();
    let preimage = KeccakPreimage::new(input_u8.to_vec());

    let memory_stores_source = generate_memory_store_masm(&preimage, INPUT_MEMORY_ADDR);

    let source = format!(
        r#"
            use.std::sys
            use.std::crypto::hashes::keccak256

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

    let stack_stores_source = generate_stack_push_masm(&preimage);

    let source = format!(
        r#"
            use.std::sys
            use.std::crypto::hashes::keccak256

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

    let stack_stores_source = generate_stack_push_masm(&preimage);

    let source = format!(
        r#"
            use.std::sys
            use.std::crypto::hashes::keccak256

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

// MASM GENERATION HELPERS
// ================================================================================================

/// Generates MASM code to store packed u32 values into memory.
///
/// # Arguments
/// * `preimage` - The Keccak preimage containing the data to store
/// * `base_addr` - Base memory address to start storing at
///
/// # Returns
/// MASM instruction string that stores all packed u32 values sequentially
fn generate_memory_store_masm(preimage: &KeccakPreimage, base_addr: u32) -> String {
    preimage
        .as_felts()
        .into_iter()
        .enumerate()
        .map(|(i, value)| format!("push.{value} push.{} mem_store", base_addr + i as u32))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generates MASM code to push the input represented as u32 values to the stack.
///
/// # Arguments
/// * `preimage` - The Keccak preimage containing the data to push
///
/// # Returns
/// MASM instruction string that pushes all packed u32 values in reverse order
/// so that the first element ends up at the top of the stack
fn generate_stack_push_masm(preimage: &KeccakPreimage) -> String {
    // Push elements in reverse order so that the first element ends up at the top
    preimage
        .as_felts()
        .into_iter()
        .rev()
        .map(|value| format!("push.{value}"))
        .collect::<Vec<_>>()
        .join(" ")
}
