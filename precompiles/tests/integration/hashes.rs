use miden_core::{Felt, utils::bytes_to_packed_u32_elements};
use miden_crypto::hash::{keccak::Keccak256, sha2::Sha512};
use miden_processor::ExecutionError;

use crate::helpers::{
    IN_PTR, OUT_PTR, assert_deferred_state_round_trips, masm_push_u32x8, masm_store_felts,
    read_memory_felts, run_precompile_program, run_precompile_program_with_stack,
};

#[test]
fn keccak_fixed_size_hash_wrapper_writes_expected_digest() {
    let input: Vec<u8> = (0u8..32).collect();

    let keccak = run_fixed_hash("keccak256", &input).expect("keccak256::hash must execute");
    assert_eq!(keccak, pack_digest(&Keccak256::hash(&input)));
}

#[test]
fn sha512_fixed_size_hash_wrapper_writes_expected_digest() {
    let input: Vec<u8> = (0u8..32).collect();

    let sha512 = run_fixed_hash("sha512", &input).expect("sha512::hash must execute");
    assert_eq!(sha512, pack_digest(&Sha512::hash(&input)));
}

#[test]
fn keccak_hash_bytes_wrapper_handles_short_preimages() {
    let input = b"hash wrapper coverage";

    let keccak = run_hash_bytes("keccak256", input, 8).expect("keccak256::hash_bytes must execute");
    assert_eq!(keccak, pack_digest(&Keccak256::hash(input)));
}

#[test]
fn sha512_hash_bytes_wrapper_handles_short_preimages() {
    let input = b"hash wrapper coverage";

    let sha512 = run_hash_bytes("sha512", input, 16).expect("sha512::hash_bytes must execute");
    assert_eq!(sha512, pack_digest(&Sha512::hash(input)));
}

#[test]
fn keccak_merge_hashes_concatenated_inputs() {
    let left: Vec<u8> = (0u8..32).collect();
    let right: Vec<u8> = (32u8..64).collect();
    let mut preimage = left.clone();
    preimage.extend_from_slice(&right);

    let output = run_merge("keccak256", &left, &right, 8).expect("keccak256::merge must execute");
    assert_eq!(output, pack_digest(&Keccak256::hash(&preimage)));
}

fn run_fixed_hash(module: &str, input: &[u8]) -> Result<Vec<Felt>, ExecutionError> {
    assert_eq!(input.len(), 32, "fixed hash wrapper takes a 256-bit input");
    let mut stack = vec![Felt::from_u32(OUT_PTR)];
    stack.extend(bytes_to_packed_u32_elements(input));

    let source = format!("begin exec.::miden::precompiles::crypto::hashes::{module}::hash end",);
    let output = run_precompile_program_with_stack(&source, &stack)?;
    assert_deferred_state_round_trips(&output);
    Ok(read_memory_felts(&output, OUT_PTR, digest_len(module)))
}

fn run_hash_bytes(
    module: &str,
    input: &[u8],
    output_len: usize,
) -> Result<Vec<Felt>, ExecutionError> {
    let input_felts = bytes_to_packed_u32_elements(input);
    let stores = masm_store_felts(&input_felts, IN_PTR);
    let source = format!(
        r#"
        begin
            {stores}
            push.{len_bytes}
            push.{IN_PTR}
            push.{OUT_PTR}
            exec.::miden::precompiles::crypto::hashes::{module}::hash_bytes
        end
        "#,
        len_bytes = input.len(),
        module = module,
    );

    let output = run_precompile_program(&source)?;
    assert_deferred_state_round_trips(&output);
    Ok(read_memory_felts(&output, OUT_PTR, output_len))
}

fn run_merge(
    module: &str,
    left: &[u8],
    right: &[u8],
    output_len: usize,
) -> Result<Vec<Felt>, ExecutionError> {
    assert_eq!(left.len(), 32, "merge left input must be 256 bits");
    assert_eq!(right.len(), 32, "merge right input must be 256 bits");

    let left = masm_push_u32x8(u32_limbs(left));
    let right = masm_push_u32x8(u32_limbs(right));
    let source = format!(
        r#"
        begin
            {right}
            {left}
            push.{OUT_PTR}
            exec.::miden::precompiles::crypto::hashes::{module}::merge
        end
        "#,
    );
    let output = run_precompile_program(&source)?;
    assert_deferred_state_round_trips(&output);
    Ok(read_memory_felts(&output, OUT_PTR, output_len))
}

fn digest_len(module: &str) -> usize {
    match module {
        "keccak256" => 8,
        "sha512" => 16,
        _ => panic!("unsupported hash module {module}"),
    }
}

fn pack_digest(bytes: &[u8]) -> Vec<Felt> {
    bytes_to_packed_u32_elements(bytes)
}

fn u32_limbs(bytes: &[u8]) -> [u32; 8] {
    assert_eq!(bytes.len(), 32, "expected a 256-bit value");
    core::array::from_fn(|i| {
        let mut limb = [0u8; 4];
        limb.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        u32::from_le_bytes(limb)
    })
}
