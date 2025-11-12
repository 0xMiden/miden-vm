//! Tests for SHA2-512 precompile event handlers.
//!
//! Validates that:
//! - Raw event handlers correctly compute SHA2-512 and populate advice provider
//! - MASM wrapper returns commitment, tag, and digest on the stack
//! - Various input lengths (including empty) are handled correctly

use miden_core::{
    Felt,
    precompile::{PrecompileCommitment, PrecompileVerifier},
};
use miden_stdlib::handlers::sha2_512::{
    SHA2_512_HASH_MEMORY_EVENT_NAME, Sha512Precompile, Sha512Preimage,
};

use crate::helpers::masm_store_felts;

const INPUT_MEMORY_ADDR: u32 = 256;

#[test]
fn test_sha2_512_handlers() {
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

                emit.event("{SHA2_512_HASH_MEMORY_EVENT_NAME}")
                drop drop
            end
        "#
    );

    let test = build_debug_test!(source, &[]);
    let output = test.execute().unwrap();

    let advice_stack: Vec<_> = output.advice_provider().stack().iter().rev().copied().collect();
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
            use.std::sys
            use.std::crypto::hashes::sha2_512

            begin
                {memory_stores}

                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                exec.sha2_512::hash_memory_impl

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
    assert_eq!(request.event_id(), SHA2_512_HASH_MEMORY_EVENT_NAME.to_event_id());
    assert_eq!(request.calldata(), preimage.as_ref());

    let preimage = Sha512Preimage::new(request.calldata().to_vec());
    println!("input comm: {:?}", preimage.input_commitment());
    println!("digest comm: {:?}", preimage.digest().to_commitment());
    println!("digest: {:?}", preimage.digest());
    // preimage.input_commitment()

    let commitment = stack.get_stack_word_be(0).unwrap();
    let tag = stack.get_stack_word_be(4).unwrap();
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
            use.std::sys
            use.std::crypto::hashes::sha2_512

            begin
                {memory_stores}

                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                exec.sha2_512::hash_memory

                exec.sys::truncate_stack
            end
        "#
    );

    let test = build_debug_test!(source, &[]);
    let digest: Vec<u64> = preimage.digest().as_ref().iter().map(Felt::as_int).collect();
    test.expect_stack(&digest);
}
