//! Tests for the SHA-512 precompile MASM wrappers.
//!
//! `crypto/hashes/sha512.masm` drives the deferred-DAG sys events directly, and the installed
//! `Sha512Precompile` precompiles's `reduce` runs `Sha512::hash` at evaluation time.

use core::array;

use miden_core::{Felt, crypto::hash::Sha512, utils::bytes_to_packed_u32_elements};

use crate::helpers::masm_store_felts;

const INPUT_MEMORY_ADDR: u32 = 256;

fn sha512_digest_felts(input: &[u8]) -> [Felt; 16] {
    let hash: [u8; 64] = Sha512::hash(input).into();
    array::from_fn(|i| {
        let mut limb = [0u8; 4];
        limb.copy_from_slice(&hash[i * 4..(i + 1) * 4]);
        Felt::from_u32(u32::from_le_bytes(limb))
    })
}

#[test]
fn test_sha512_hash_bytes_various_sizes() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![42],
        vec![1, 2, 3, 4, 5],
        (0..32).collect(),
        (0..48).collect(),
        (0..65).collect(),
    ];

    for input in &inputs {
        let len_bytes = input.len();
        let input_felts = bytes_to_packed_u32_elements(input);
        let memory_stores_source = masm_store_felts(&input_felts, INPUT_MEMORY_ADDR);

        let source = format!(
            r#"
                use miden::core::sys
                use miden::core::crypto::hashes::sha512

                begin
                    {memory_stores_source}
                    push.{len_bytes}.{INPUT_MEMORY_ADDR}
                    exec.sha512::hash_bytes
                    # => [DIGEST_U32[16]]
                    exec.sys::truncate_stack
                end
                "#,
        );

        let test = build_debug_test!(source, &[]);
        let digest: Vec<u64> =
            sha512_digest_felts(input).iter().map(Felt::as_canonical_u64).collect();
        test.expect_stack(&digest);
    }
}
