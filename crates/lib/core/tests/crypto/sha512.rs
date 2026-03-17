//! Tests for SHA512 precompile event handlers.
//!
//! Validates that:
//! - Raw event handlers correctly compute SHA512 and populate advice provider
//! - MASM wrapper returns commitment, tag, and digest on the stack
//! - Various input lengths (including empty) are handled correctly

use miden_core::{
    Felt,
    precompile::{PrecompileCommitment, PrecompileVerifier},
};
use miden_core_lib::handlers::sha512::{
    SHA512_HASH_BYTES_EVENT_NAME, Sha512Precompile, Sha512Preimage,
};
use miden_processor::ExecutionError;

use crate::helpers::masm_store_felts;

const INPUT_MEMORY_ADDR: u32 = 256;

#[test]
fn test_sha512_handlers() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![1, 2, 3, 4, 5],
        vec![],
        vec![42],
        (0..32).collect(),
        (0..48).collect(),
        (0..65).collect(),
    ];

    for input in &inputs {
        test_sha512_handler(input);
        test_sha512_hash_memory_impl(input);
        test_sha512_hash_memory(input);
    }
}

fn test_sha512_handler(bytes: &[u8]) {
    let len_bytes = bytes.len();
    let preimage = Sha512Preimage::new(bytes.to_vec());
    let input_felts = preimage.as_felts();
    let memory_stores = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

    let source = format!(
        r#"
            begin
                {memory_stores}

                push.{len_bytes}.{INPUT_MEMORY_ADDR}

                emit.event("{SHA512_HASH_BYTES_EVENT_NAME}")
                drop drop
            end
        "#
    );

    let test = build_debug_test!(source, &[]);
    let output = test.execute().unwrap();

    let advice_stack: Vec<_> = output.advice_provider().stack().to_vec();
    assert_eq!(advice_stack, preimage.digest().as_ref());

    let deferred = output.advice_provider().precompile_requests().to_vec();
    assert_eq!(deferred.len(), 1);
    let request = &deferred[0];
    assert_eq!(request.calldata(), preimage.as_ref());
}

fn test_sha512_hash_memory_impl(bytes: &[u8]) {
    let len_bytes = bytes.len();
    let preimage = Sha512Preimage::new(bytes.to_vec());
    let input_felts = preimage.as_felts();
    let memory_stores = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

    let source = format!(
        r#"
            use miden::core::sys
            use miden::core::crypto::hashes::sha512

            begin
                {memory_stores}

                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                exec.sha512::hash_bytes_impl

                exec.sys::truncate_stack
            end
        "#
    );

    let test = build_debug_test!(source, &[]);
    let output = test.execute().unwrap();
    let stack = output.stack_outputs();

    // we cannot check the digest since it overflows the stack.
    // we check it in test_sha512_hash_memory

    let deferred = output.advice_provider().precompile_requests().to_vec();
    assert_eq!(deferred.len(), 1);
    let request = &deferred[0];
    assert_eq!(request.event_id(), SHA512_HASH_BYTES_EVENT_NAME.to_event_id());
    assert_eq!(request.calldata(), preimage.as_ref());

    let preimage = Sha512Preimage::new(request.calldata().to_vec());

    let commitment = stack.get_word(0).unwrap();
    let tag = stack.get_word(4).unwrap();
    let precompile_commitment = PrecompileCommitment::new(tag, commitment);
    let verifier_commitment = Sha512Precompile.verify(preimage.as_ref()).unwrap();
    assert_eq!(precompile_commitment, verifier_commitment, "commitment mismatch");

    assert!(
        output.advice_provider().stack().is_empty(),
        "advice stack must be empty after hash_memory_impl"
    );
}

fn test_sha512_hash_memory(bytes: &[u8]) {
    let len_bytes = bytes.len();
    let preimage = Sha512Preimage::new(bytes.to_vec());
    let input_felts = preimage.as_felts();
    let memory_stores = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

    let source = format!(
        r#"
            use miden::core::sys
            use miden::core::crypto::hashes::sha512

            begin
                {memory_stores}

                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                exec.sha512::hash_bytes

                exec.sys::truncate_stack
            end
        "#
    );

    let test = build_debug_test!(source, &[]);
    let digest: Vec<u64> = preimage.digest().as_ref().iter().map(Felt::as_canonical_u64).collect();
    test.expect_stack(&digest);
}

/// Input at exactly `max_hash_len_bytes` must succeed.
#[test]
fn test_sha512_max_hash_len_at_boundary() {
    let max_len = 20;
    let input: Vec<u8> = (0..max_len as u8).collect();
    run_sha512_with_max_hash_len(&input, max_len as u64, max_len).unwrap();
}

/// Input one byte over `max_hash_len_bytes` must be rejected.
#[test]
fn test_sha512_max_hash_len_over_boundary() {
    let max_len = 20;
    let input: Vec<u8> = (0..=max_len as u8).collect();
    let err = run_sha512_with_max_hash_len(&input, (max_len + 1) as u64, max_len).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("exceeds maximum"), "expected limit error, got: {msg}");
}

#[test]
fn test_sha512_hash_bytes_documented_stack_contract() {
    let bytes = vec![1_u8, 2, 3, 4, 5];
    let len_bytes = bytes.len();
    let preimage = Sha512Preimage::new(bytes);
    let input_felts = preimage.as_felts();
    let memory_stores = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);
    let sentinels = [0x11_u64, 0x22, 0x33, 0x44];

    let source = format!(
        r#"
            use miden::core::crypto::hashes::sha512

            begin
                {memory_stores}

                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                exec.sha512::hash_bytes

                # drop the digest and ensure caller stack words are preserved
                dropw dropw dropw dropw
            end
        "#
    );

    build_debug_test!(source, &sentinels).expect_stack(&sentinels);
}

// HELPERS
// ================================================================================

/// Helper that compiles and runs a sha512 event with a given `len_bytes` on the stack and a
/// custom `max_hash_len_bytes` execution option.
fn run_sha512_with_max_hash_len(
    input_u8: &[u8],
    len_bytes_on_stack: u64,
    max_hash_len_bytes: usize,
) -> Result<(), ExecutionError> {
    use miden_assembly::Assembler;
    use miden_processor::{
        DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
    };

    let preimage = Sha512Preimage::new(input_u8.to_vec());
    let input_felts = preimage.as_felts();
    let memory_stores = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

    let source = format!(
        r#"
        begin
            {memory_stores}
            push.{len_bytes_on_stack}.{INPUT_MEMORY_ADDR}
            emit.event("{SHA512_HASH_BYTES_EVENT_NAME}")
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
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options);

    processor.execute(&program, &mut host)?;
    Ok(())
}
