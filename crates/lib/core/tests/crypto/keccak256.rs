//! Tests for the Keccak256 precompile MASM wrappers.
//!
//! The MASM wrappers in `crypto/hashes/keccak256.masm` drive the deferred-DAG sys events
//! directly, and the installed `Keccak256Precompile` schema's `reduce` runs `Keccak256::hash`
//! at evaluation time.
//!
//! These tests cover the public surface:
//! - `keccak256::hash_bytes` returns the correct digest for various input sizes (incl. empty,
//!   sub-word, multi-chunk).
//! - `keccak256::hash` / `keccak256::merge` operate on 256-bit / 512-bit inputs respectively.
//! - The documented stack contracts (caller frame below the digest is preserved).

use core::array;

use miden_core::{Felt, crypto::hash::Keccak256, utils::bytes_to_packed_u32_elements};

use crate::helpers::{masm_push_felts, masm_store_felts};

// Test constants
// ================================================================================================

const INPUT_MEMORY_ADDR: u32 = 128;

/// Compute Keccak256 of `input`, then unpack the 32-byte digest into 8 u32-packed-LE felts —
/// matching what the MASM wrapper leaves on the stack.
fn keccak_digest_felts(input: &[u8]) -> [Felt; 8] {
    let hash: [u8; 32] = Keccak256::hash(input).into();
    array::from_fn(|i| {
        let mut limb = [0u8; 4];
        limb.copy_from_slice(&hash[i * 4..(i + 1) * 4]);
        Felt::from_u32(u32::from_le_bytes(limb))
    })
}

// HASH_BYTES — variable-length API
// ================================================================================================

#[test]
fn test_keccak_hash_bytes_various_sizes() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![1],
        vec![1, 2, 3, 4],
        vec![1, 2, 3, 4, 5],
        (0..32).collect(),
        (0..33).collect(),
        (0..70).collect(),
    ];

    for input in &inputs {
        let len_bytes = input.len();
        let input_felts = bytes_to_packed_u32_elements(input);
        let memory_stores_source = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

        let source = format!(
            r#"
                use miden::core::sys
                use miden::core::crypto::hashes::keccak256

                begin
                    {memory_stores_source}

                    push.{len_bytes}.{INPUT_MEMORY_ADDR}
                    # => [ptr, len_bytes]

                    exec.keccak256::hash_bytes
                    # => [DIGEST_U32[8]]

                    exec.sys::truncate_stack
                end
                "#,
        );

        let test = build_debug_test!(source, &[]);
        let digest: Vec<u64> = keccak_digest_felts(input)
            .iter()
            .map(Felt::as_canonical_u64)
            .collect();
        test.expect_stack(&digest);
    }
}

// HASH — fixed 256-bit-input API
// ================================================================================================

#[test]
fn test_keccak_hash() {
    let input: Vec<u8> = (0..32).collect();
    let input_felts = bytes_to_packed_u32_elements(&input);
    let stack_stores_source = masm_push_felts(&input_felts);

    let source = format!(
        r#"
            use miden::core::sys
            use miden::core::crypto::hashes::keccak256

            begin
                {stack_stores_source}
                # => [INPUT_LO, INPUT_HI]

                exec.keccak256::hash
                # => [DIGEST_U32[8]]

                exec.sys::truncate_stack
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);
    let digest: Vec<u64> = keccak_digest_felts(&input).iter().map(Felt::as_canonical_u64).collect();
    test.expect_stack(&digest);
}

#[test]
fn test_keccak_hash_preserves_caller_stack() {
    // Sentinel values below the input on the stack must survive the wrapper unmolested. Catches
    // off-by-one stack-shuffle bugs in the helper choreography.
    let input: Vec<u8> = (0..32).collect();
    let sentinels = [0x101_u64, 0x202, 0x303, 0x404];

    let input_felts = bytes_to_packed_u32_elements(&input);
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

// MERGE — two-256-bit-input API
// ================================================================================================

#[test]
fn test_keccak_merge() {
    let input: Vec<u8> = (0..64).collect();
    let input_felts = bytes_to_packed_u32_elements(&input);
    let stack_stores_source = masm_push_felts(&input_felts);

    let source = format!(
        r#"
            use miden::core::sys
            use miden::core::crypto::hashes::keccak256

            begin
                {stack_stores_source}
                # => [INPUT_L_U32[8], INPUT_R_U32[8]]

                exec.keccak256::merge
                # => [DIGEST_U32[8]]

                exec.sys::truncate_stack
            end
            "#,
    );

    let test = build_debug_test!(source, &[]);
    let digest: Vec<u64> = keccak_digest_felts(&input).iter().map(Felt::as_canonical_u64).collect();
    test.expect_stack(&digest);
}

#[test]
fn test_keccak_merge_preserves_caller_stack() {
    let input: Vec<u8> = (0..64).collect();
    let sentinels = [0x707_u64, 0x808, 0x909, 0xa0a];

    let input_felts = bytes_to_packed_u32_elements(&input);
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
