//! Tests for Keccak256 precompile event handlers.
//!
//! Verifies that:
//! - Raw event handlers correctly compute Keccak256 and populate advice provider
//! - Public MASM wrappers correctly return the digest and log deferred requests
//! - Private implementation helpers return the expected commitment and tag
//! - Both memory and digest merge operations work correctly
//! - Various input sizes and edge cases are handled properly

use core::array;

use miden_core::{
    Felt,
    precompile::{PrecompileCommitment, PrecompileVerifier},
};
use miden_core_lib::handlers::keccak256::{
    KECCAK_HASH_BYTES_EVENT_NAME, KeccakPrecompile, KeccakPreimage,
};
use miden_processor::ExecutionError;

use crate::helpers::{masm_push_felts, masm_store_felts};

// Test constants
// ================================================================================================

const INPUT_MEMORY_ADDR: u32 = 128;

// TESTS
// ================================================================================================

#[test]
fn test_keccak_handlers() {
    // Test various input sizes including edge cases
    let hash_bytes_inputs: Vec<Vec<u8>> = vec![
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

    for input in &hash_bytes_inputs {
        test_keccak_handler(input);
        test_keccak_hash_bytes_impl(input);
        test_keccak_hash_bytes(input);
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

                emit.event("{KECCAK_HASH_BYTES_EVENT_NAME}")
                drop drop
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);

    let (output, _) = test.execute_for_output().unwrap();

    let advice_stack = output.advice.stack();
    assert_eq!(advice_stack, preimage.digest().as_ref());

    let deferred = output.advice.precompile_requests().to_vec();
    assert_eq!(deferred.len(), 1, "advice deferred must contain one entry");
    let precompile_data = &deferred[0];

    // PrecompileData contains the raw input bytes directly
    assert_eq!(
        precompile_data.calldata(),
        preimage.as_ref(),
        "data in deferred storage does not match preimage"
    );
}

fn test_keccak_hash_bytes_impl(input_u8: &[u8]) {
    let len_bytes = input_u8.len();
    let preimage = KeccakPreimage::new(input_u8.to_vec());

    let input_felts = preimage.as_felts();
    let memory_stores_source = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

    let source = private_proc_harness(
        include_str!("../../asm/crypto/hashes/keccak256.masm"),
        format!(
            r#"
                # Store packed u32 values in memory
                {memory_stores_source}

                # Push wrapper inputs
                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                # => [ptr, len_bytes]

                exec.hash_bytes_impl
                # => [COMM, TAG, DIGEST_U32[8]]

                exec.sys::truncate_stack
            "#,
        ),
    );

    let test = build_debug_test!(source, &[]);

    let (output, _) = test.execute_for_output().unwrap();

    let stack = output.stack;
    let commitment = stack.get_word(0).unwrap();
    let tag = stack.get_word(4).unwrap();
    let precompile_commitment = PrecompileCommitment::new(tag, commitment);
    let verifier_commitment = KeccakPrecompile.verify(preimage.as_ref()).unwrap();
    assert_eq!(precompile_commitment, verifier_commitment);

    // Digest occupies the elements after COMM/TAG
    let digest: [Felt; 8] = array::from_fn(|i| stack.get_element(8 + i).unwrap());
    assert_eq!(&digest, preimage.digest().as_ref(), "output digest does not match");

    let deferred = output.advice.precompile_requests().to_vec();
    assert_eq!(deferred.len(), 1, "expected a single deferred request");
    assert_eq!(deferred[0].event_id(), KECCAK_HASH_BYTES_EVENT_NAME.to_event_id());
    assert_eq!(deferred[0].calldata(), preimage.as_ref());
    assert_eq!(deferred[0], preimage.into());

    let advice_stack = output.advice.stack();
    assert!(advice_stack.is_empty(), "advice stack should be empty after hash_bytes_impl");
}

fn test_keccak_hash_bytes(input_u8: &[u8]) {
    let len_bytes = input_u8.len();
    let preimage = KeccakPreimage::new(input_u8.to_vec());

    let input_felts = preimage.as_felts();
    let memory_stores_source = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

    let source = format!(
        r#"
            use miden::core::sys
            use miden::core::crypto::hashes::keccak256

            begin
                # Store packed u32 values in memory
                {memory_stores_source}

                # Push wrapper inputs
                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                # => [ptr, len_bytes]

                exec.keccak256::hash_bytes
                # => [DIGEST_U32[8]]

                exec.sys::truncate_stack
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);
    let digest: Vec<u64> = preimage.digest().as_ref().iter().map(Felt::as_canonical_u64).collect();
    test.expect_stack(&digest);
}

#[test]
fn test_keccak_hash() {
    let input_u8: Vec<u8> = (0..32).collect();
    let preimage = KeccakPreimage::new(input_u8);

    let input_felts = preimage.as_felts();
    let stack_stores_source = masm_push_felts(&input_felts);

    let source = format!(
        r#"
            use miden::core::sys
            use miden::core::crypto::hashes::keccak256

            begin
                # Push input to stack as words with temporary memory pointer
                {stack_stores_source}
                # => [INPUT_LO, INPUT_HI]

                exec.keccak256::hash
                # => [DIGEST_U32[8]]

                exec.sys::truncate_stack
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);
    let digest: Vec<u64> = preimage.digest().as_ref().iter().map(Felt::as_canonical_u64).collect();
    test.expect_stack(&digest);
}

#[test]
fn test_keccak_hash_documented_stack_contract() {
    let input_u8: Vec<u8> = (0..32).collect();
    let preimage = KeccakPreimage::new(input_u8);
    let sentinels = [0x101_u64, 0x202, 0x303, 0x404];

    let input_felts = preimage.as_felts();
    let stack_stores_source = masm_push_felts(&input_felts);

    let source = format!(
        r#"
            use miden::core::crypto::hashes::keccak256

            begin
                {stack_stores_source}
                exec.keccak256::hash
                dropw dropw
            end
            "#,
    );

    build_debug_test!(source, &sentinels).expect_stack(&sentinels);
}

#[test]
fn test_keccak_merge() {
    let input_u8: Vec<u8> = (0..64).collect();
    let preimage = KeccakPreimage::new(input_u8);

    let input_felts = preimage.as_felts();
    let stack_stores_source = masm_push_felts(&input_felts);

    let source = format!(
        r#"
            use miden::core::sys
            use miden::core::crypto::hashes::keccak256

            begin
                # Push input to stack as words with temporary memory pointer
                {stack_stores_source}
                # => [INPUT_L_U32[8], INPUT_R_U32[8]]

                exec.keccak256::merge
                # => [DIGEST_U32[8]]

                exec.sys::truncate_stack
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);
    let digest: Vec<u64> = preimage.digest().as_ref().iter().map(Felt::as_canonical_u64).collect();
    test.expect_stack(&digest);
}

/// Input at exactly `max_hash_len_bytes` must succeed.
#[test]
fn test_keccak_max_hash_len_at_boundary() {
    let max_len = 20;
    let input: Vec<u8> = (0..max_len as u8).collect();
    run_keccak_with_max_hash_len(&input, max_len as u64, max_len).unwrap();
}

/// Input one byte over `max_hash_len_bytes` must be rejected.
#[test]
fn test_keccak_max_hash_len_over_boundary() {
    let max_len = 20;
    let input: Vec<u8> = (0..=max_len as u8).collect();
    let err = run_keccak_with_max_hash_len(&input, (max_len + 1) as u64, max_len).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("exceeds maximum"), "expected limit error, got: {msg}");
}

#[test]
fn test_keccak_merge_documented_stack_contract() {
    let input_u8: Vec<u8> = (0..64).collect();
    let preimage = KeccakPreimage::new(input_u8);
    let sentinels = [0x707_u64, 0x808, 0x909, 0xa0a];

    let input_felts = preimage.as_felts();
    let stack_stores_source = masm_push_felts(&input_felts);

    let source = format!(
        r#"
            use miden::core::crypto::hashes::keccak256

            begin
                {stack_stores_source}
                exec.keccak256::merge
                dropw dropw
            end
            "#,
    );

    build_debug_test!(source, &sentinels).expect_stack(&sentinels);
}

// HELPERS
// ================================================================================================

/// Helper that compiles and runs a keccak256 event with a given `len_bytes` on the stack and a
/// custom `max_hash_len_bytes` execution option.
fn run_keccak_with_max_hash_len(
    input_u8: &[u8],
    len_bytes_on_stack: u64,
    max_hash_len_bytes: usize,
) -> Result<(), ExecutionError> {
    use miden_assembly::Assembler;
    use miden_processor::{
        DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
    };

    let preimage = KeccakPreimage::new(input_u8.to_vec());
    let input_felts = preimage.as_felts();
    let memory_stores = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

    let source = format!(
        r#"
        begin
            {memory_stores}
            push.{len_bytes_on_stack}.{INPUT_MEMORY_ADDR}
            emit.event("{KECCAK_HASH_BYTES_EVENT_NAME}")
            drop drop
        end
        "#,
    );

    let core_lib = miden_core_lib::CoreLibrary::default();
    let program = Assembler::default()
        .with_static_library(core_lib.library())
        .unwrap()
        .assemble_program(&source)
        .unwrap();

    let mut host = DefaultHost::default();
    host.load_library(core_lib.library().mast_forest()).unwrap();
    for (event_name, handler) in core_lib.handlers() {
        host.register_handler(event_name, handler).unwrap();
    }

    let options = ExecutionOptions::default().with_max_hash_len_bytes(max_hash_len_bytes);
    let processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .map_err(ExecutionError::advice_error_no_context)?;

    processor.execute_sync(&program, &mut host)?;
    Ok(())
}

fn private_proc_harness(module_source: &str, body: impl AsRef<str>) -> String {
    format!("{}\n\nbegin\n{}\nend", module_source.replace("pub proc", "proc"), body.as_ref())
}
