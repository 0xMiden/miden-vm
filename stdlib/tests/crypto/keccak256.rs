//! Tests for Keccak256 precompile event handlers.
//!
//! Verifies that:
//! - Raw event handlers correctly compute Keccak256 and populate advice provider
//! - MASM wrappers correctly return commitment and digest on stack
//! - Both memory and digest merge operations work correctly
//! - Various input sizes and edge cases are handled properly

use core::array;

use miden_core::Felt;
use miden_stdlib::handlers::keccak256::{
    KECCAK_HASH_MEMORY_EVENT_ID, KECCAK_HASH_MEMORY_EVENT_NAME, KeccakPreimage, keccak_verifier,
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
        //empty
        vec![],
        // different byte packing
        vec![1],
        vec![1, 2],
        vec![1, 2, 3],
        vec![1, 2, 3, 4],
        // longer inputs with non-aligned sizes
        (0..31).collect(),
        (0..32).collect(),
        (0..33).collect(),
        // large-ish inputs
        (0..64).collect(),
        (0..128).collect(),
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
    assert_eq!(advice_stack, preimage.digest().inner());

    let deferred = output.advice_provider().precompile_requests().clone().into_requests();
    assert_eq!(deferred.len(), 1, "advice deferred must contain one entry");
    let precompile_data = &deferred[0];
    assert_eq!(precompile_data.event_id, KECCAK_HASH_MEMORY_EVENT_ID, "event ID does not match");

    // PrecompileData contains the raw input bytes directly
    assert_eq!(
        precompile_data.data, preimage.0,
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
                # => [COMM, DIGEST_U32[8]]

                exec.sys::truncate_stack
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);

    let output = test.execute().unwrap();
    let stack = output.stack_outputs();
    let commitment = stack.get_stack_word(0).unwrap();
    assert_eq!(
        commitment,
        preimage.precompile_commitment(),
        "precompile_commitment does not match"
    );

    let digest: [Felt; 8] = array::from_fn(|i| stack.get_stack_item(4 + i).unwrap());
    assert_eq!(digest, preimage.digest().inner(), "output digest does not match");

    let commitment_verified = keccak_verifier(&preimage.0).unwrap();
    assert_eq!(
        commitment, commitment_verified,
        "commitment returned by verifier does not match the one on the stack"
    )
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
    let digest = preimage.digest().inner().map(|felt| felt.as_int());
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
    let digest = preimage.digest().inner().map(|felt| felt.as_int());
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
    let digest = preimage.digest().inner().map(|felt| felt.as_int());
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
