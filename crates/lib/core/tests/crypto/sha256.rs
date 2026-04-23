use miden_air::Serializable;
use miden_crypto::hash::sha2::Sha256;
use miden_processor::{ExecutionError, operation::OperationError};
use miden_utils_testing::{
    Felt, IntoBytes, Test, group_slice_elements, push_inputs,
    rand::{rand_array, rand_value, rand_vector},
};

const NON_U32_WORD: u64 = u32::MAX as u64 + 2;
const INVALID_SHA256_MESSAGE_WORD: &str = "invalid sha256 message word";
const SHA256_HASH_SOURCE: &str = "
    use miden::core::crypto::hashes::sha256

    begin
        exec.sha256::hash
    end";
const SHA256_MERGE_SOURCE: &str = "
    use miden::core::crypto::hashes::sha256

    begin
        exec.sha256::merge
    end";

#[test]
fn sha256_hash_bytes() {
    let length_in_bytes = rand_value::<u64>() & 1023; // length: 0-1023
    let ibytes: Vec<u8> = rand_vector(length_in_bytes as usize);
    let ipadding: Vec<u8> = vec![0; (4 - (length_in_bytes as usize % 4)) % 4];

    // Note: We need .rev() here because push_inputs generates MASM push instructions.
    // MASM push puts each value on top, so pushing [a, b, c] results in stack [c, b, a].
    // To get word0 on top after all pushes (and after mem_store.1 pops length),
    // we need to push wordN-1 first, then ..., then word0, then length.
    let ifelts = [
        group_slice_elements::<u8, 4>(&[ibytes.clone(), ipadding].concat())
            .iter()
            .map(|&bytes| u32::from_be_bytes(bytes) as u64)
            .rev()
            .collect::<Vec<u64>>(),
        vec![length_in_bytes; 1],
    ]
    .concat();

    let source = format!(
        "
    use miden::core::crypto::hashes::sha256

    begin
        # push inputs on the stack
        {inputs}

        # mem.0 - input data address
        push.10000 mem_store.0

        # mem.1 - length in bytes
        mem_store.1

        # mem.2 - length in words
        mem_load.1 u32assert u32overflowing_add.15 assertz u32assert u32div.16 mem_store.2

        # Load input data into memory address 10000, 10004, ...
        mem_load.2 u32assert neq.0
        while.true
            mem_load.0 mem_storew_be dropw
            mem_load.0 u32assert u32overflowing_add.4 assertz mem_store.0
            mem_load.2 u32assert u32overflowing_sub.1 assertz dup mem_store.2 u32assert neq.0
        end

        # Compute hash of memory address 10000, 10004, ...
        mem_load.1
        push.10000
        exec.sha256::hash_bytes

        # truncate the stack
        swapdw dropw dropw
    end",
        inputs = push_inputs(&ifelts)
    );

    let obytes = Sha256::hash(&ibytes).to_bytes();
    let ofelts = group_slice_elements::<u8, 4>(&obytes)
        .iter()
        .map(|&bytes| u32::from_be_bytes(bytes) as u64)
        .collect::<Vec<u64>>();

    let test = build_test!(source, &[]);
    test.expect_stack(&ofelts);
}

#[test]
fn sha256_2_to_1_hash() {
    let input0 = rand_array::<Felt, 4>().into_bytes();
    let input1 = rand_array::<Felt, 4>().into_bytes();

    let mut ibytes = [0u8; 64];
    ibytes[..32].copy_from_slice(&input0);
    ibytes[32..].copy_from_slice(&input1);

    let ifelts: Vec<u64> = group_slice_elements::<u8, 4>(&ibytes)
        .iter()
        .map(|&bytes| u32::from_be_bytes(bytes) as u64)
        .collect();

    let obytes = Sha256::hash(&ibytes).to_bytes();
    let ofelts: Vec<u64> = group_slice_elements::<u8, 4>(&obytes)
        .iter()
        .map(|&bytes| u32::from_be_bytes(bytes) as u64)
        .collect();

    build_test!(SHA256_MERGE_SOURCE, &ifelts).expect_stack(&ofelts);
}

#[test]
fn sha256_1_to_1_hash() {
    let ibytes = rand_array::<Felt, 4>().into_bytes();
    let ifelts: Vec<u64> = group_slice_elements::<u8, 4>(&ibytes)
        .iter()
        .map(|&bytes| u32::from_be_bytes(bytes) as u64)
        .collect();

    let obytes = Sha256::hash(&ibytes).to_bytes();
    let ofelts: Vec<u64> = group_slice_elements::<u8, 4>(&obytes)
        .iter()
        .map(|&bytes| u32::from_be_bytes(bytes) as u64)
        .collect();

    build_test!(SHA256_HASH_SOURCE, &ifelts).expect_stack(&ofelts);
}

#[test]
fn sha256_hash_rejects_non_u32_message_word() {
    let mut input_words = vec![0; 8];
    input_words[1] = NON_U32_WORD;

    expect_non_u32_execution_error(build_test!(SHA256_HASH_SOURCE, &input_words));
}

#[test]
fn sha256_merge_rejects_non_u32_message_word() {
    let mut input_words = vec![0; 16];
    input_words[1] = NON_U32_WORD;

    expect_non_u32_execution_error(build_test!(SHA256_MERGE_SOURCE, &input_words));
}

#[test]
fn sha256_hash_bytes_rejects_non_u32_memory_word() {
    let source = format!(
        "
    use miden::core::crypto::hashes::sha256

    begin
        push.0.0.{NON_U32_WORD}.0 mem_storew_be.10000 dropw

        push.32.10000
        exec.sha256::hash_bytes
    end"
    );

    expect_non_u32_execution_error(build_test!(source, &[]));
}

fn expect_non_u32_execution_error(test: Test) {
    let err = test.execute().expect_err("expected non-u32 SHA256 input to fail");
    match err {
        ExecutionError::OperationError {
            err: OperationError::U32AssertionFailed { err_msg, invalid_values, .. },
            ..
        } => assert!(
            err_msg.as_deref() == Some(INVALID_SHA256_MESSAGE_WORD)
                && invalid_values.iter().any(|value| value.as_canonical_u64() == NON_U32_WORD),
            "expected SHA256 message word assertion for {NON_U32_WORD}, got message {err_msg:?} and values {invalid_values:?}"
        ),
        err => panic!("expected SHA256 message word assertion, got {err:?}"),
    }
}
