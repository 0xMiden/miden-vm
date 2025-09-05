//! Tests for Keccak256 precompile event handlers.
//!
//! Verifies that:
//! - Raw event handlers correctly compute Keccak256 and populate advice provider
//! - MASM wrappers correctly return commitment and digest on stack
//! - Both memory and digest merge operations work correctly
//! - Various input sizes and edge cases are handled properly

use miden_core::{Felt, utils::string_to_event_id};
use miden_crypto::{
    Word,
    hash::{keccak::Keccak256, rpo::Rpo256},
};
use miden_processor::{AdviceMutation, EventError, EventHandler, ProcessState};
use miden_stdlib::handlers::keccak::{
    KECCAK_HASH_MEM_EVENT_ID, KECCAK_MERGE_STACK_EVENT_ID, KeccakFeltDigest,
};

// Test constants
// ================================================================================================

const INPUT_MEMORY_ADDR: u32 = 128;
const DEBUG_EVENT_ID: &str = "miden::debug";

/// Test helper for Keccak256 precompile operations.
///
/// Wraps a byte array and provides utilities for:
/// - Converting bytes to u32/felt representations
/// - Computing expected Keccak256 digests and commitments
/// - Generating MASM code for memory/stack operations
/// - Creating event handlers for test validation
#[derive(Debug, Eq, PartialEq)]
struct Preimage(Vec<u8>);

impl Preimage {
    /// Converts bytes to packed u32 values (4 bytes per u32, last chunk padded with zeros).
    fn as_packed_u32(&self) -> impl Iterator<Item = u32> {
        let pack_bytes = |bytes: &[u8]| -> u32 {
            let mut out = [0u8; 4];
            for (i, byte) in bytes.iter().enumerate() {
                out[i] = *byte;
            }
            u32::from_le_bytes(out)
        };

        self.0.chunks(4).map(pack_bytes)
    }

    /// Converts packed u32 values to field elements.
    fn as_felt(&self) -> impl Iterator<Item = Felt> {
        self.as_packed_u32().map(Felt::from)
    }

    /// Computes RPO(input_felts) for commitment calculation.
    fn input_commitment(&self) -> Word {
        let preimage_felt: Vec<Felt> = self.as_felt().collect();
        Rpo256::hash_elements(&preimage_felt)
    }

    /// Computes the expected Keccak256 digest.
    fn digest(&self) -> KeccakFeltDigest {
        let hash_u8 = Keccak256::hash(&self.0);
        KeccakFeltDigest::from_bytes(&hash_u8)
    }

    /// Computes the expected commitment: RPO(RPO(input) || RPO(hash)).
    fn calldata_commitment(&self) -> Word {
        Rpo256::merge(&[self.input_commitment(), self.digest().to_commitment()])
    }

    /// Generates MASM code to store packed u32 values into memory.
    fn masm_memory_store_source(&self) -> String {
        self.as_packed_u32()
            .enumerate()
            .map(|(i, value)| {
                format!("push.{} push.{} mem_store", value, INPUT_MEMORY_ADDR + i as u32)
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Generates MASM code to push two digests onto the stack for merge testing.
    /// Requires exactly 64 bytes: first 32 bytes = left digest, last 32 bytes = right digest.
    fn masm_stack_store_source(&self) -> String {
        assert_eq!(self.0.len(), 64, "merge requires exactly 64 bytes (two digests)");
        let (digest_l_lo, digest_l_hi) = KeccakFeltDigest::from_bytes(&self.0[0..32]).to_words();
        let (digest_r_lo, digest_r_hi) = KeccakFeltDigest::from_bytes(&self.0[32..64]).to_words();
        let words = [digest_l_lo, digest_l_hi, digest_r_lo, digest_r_hi];
        words
            .into_iter()
            .rev()
            .map(|word| format!("push.{:?}", word.as_ref()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Verifies that raw event handlers correctly populate advice provider.
    fn handler_test(self) -> impl EventHandler {
        move |process: &ProcessState| -> Result<Vec<AdviceMutation>, EventError> {
            let digest = self.digest();
            assert_eq!(
                &digest.to_stack(),
                process.advice_provider().stack(),
                "digest not found in advice stack"
            );

            let calldata_commitment = self.calldata_commitment();
            let witness = process.advice_provider().get_mapped_values(&calldata_commitment).expect(
                format!(
                    "witness was not found in advice map with key {calldata_commitment:?}\n\
                    advice provider:\n{:?}",
                    process.advice_provider(),
                )
                .as_str(),
            );
            let witness_expected: Vec<Felt> = {
                let len_bytes = self.0.len() as u64;

                [Felt::new(len_bytes)].into_iter().chain(self.as_felt()).collect()
            };
            assert_eq!(witness, witness_expected, "witness in advice map does not match preimage");

            Ok(vec![])
        }
    }

    /// Verifies that MASM wrappers correctly return commitment and digest on stack.
    fn wrapper_test(self) -> impl EventHandler {
        move |process: &ProcessState| -> Result<Vec<AdviceMutation>, EventError> {
            // Expected stack after wrapper: [event_id, commitment, digest_lo, digest_hi, ...]
            let calldata_commitment = process.get_stack_word(1);
            let digest_lo = process.get_stack_word(5);
            let digest_hi = process.get_stack_word(9);
            let digest = KeccakFeltDigest::from_words(digest_lo, digest_hi);

            // Verify the digest matches our reference computation
            assert_eq!(digest, self.digest(), "output digest does not match");

            // Verify the calldata commitment matches our reference computation
            assert_eq!(
                calldata_commitment,
                self.calldata_commitment(),
                "calldata_commitment does not match"
            );

            Ok(vec![])
        }
    }
}

// TESTS
// ================================================================================================

#[test]
fn test_keccak_handlers() {
    // Test various input sizes including edge cases
    let inputs: Vec<Vec<u8>> = vec![
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

    for input in &inputs {
        test_keccak_hash_mem_handler_with_input(input);
        test_keccak_hash_mem_wrapper_with_input(input);
    }

    let input_digests: Vec<u8> = (0..64).collect();
    test_keccak_merge_stack_handler_with_input(&input_digests);
    test_keccak_merge_stack_wrapper_with_input(&input_digests);
}

fn test_keccak_hash_mem_handler_with_input(input_u8: &[u8]) {
    let len_bytes = input_u8.len();
    let preimage = Preimage(input_u8.to_vec());

    let memory_stores_source = preimage.masm_memory_store_source();

    let source = format!(
        r#"
            begin
                # Store packed u32 values in memory
                {memory_stores_source}

                # Push handler inputs
                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                # => [ptr, len_bytes, ...]

                emit.event("{KECCAK_HASH_MEM_EVENT_ID}")
                drop drop

                emit.event("{DEBUG_EVENT_ID}")
            end
            "#,
    );

    let mut test = build_debug_test!(source, &[]);

    test.add_event_handler(string_to_event_id(DEBUG_EVENT_ID), preimage.handler_test());
    test.execute().unwrap();
}

fn test_keccak_hash_mem_wrapper_with_input(input_u8: &[u8]) {
    let len_bytes = input_u8.len();
    let preimage = Preimage(input_u8.to_vec());

    let memory_stores_source = preimage.masm_memory_store_source();

    let source = format!(
        r#"
            use.std::sys
            use.std::crypto::hashes::keccak_precompile

            begin
                # Store packed u32 values in memory
                {memory_stores_source}

                # Push wrapper inputs
                push.{len_bytes}.{INPUT_MEMORY_ADDR}
                # => [ptr, len_bytes, ...]

                exec.keccak_precompile::hash_mem
                # => [commitment, keccak_lo, keccak_hi, ...]

                emit.event("{DEBUG_EVENT_ID}")
                exec.sys::truncate_stack
            end
            "#,
    );

    let mut test = build_debug_test!(source, &[]);

    test.add_event_handler(string_to_event_id(DEBUG_EVENT_ID), preimage.wrapper_test());
    test.execute().unwrap();
}

fn test_keccak_merge_stack_handler_with_input(input_u8: &[u8]) {
    let preimage = Preimage(input_u8.to_vec());

    let stack_stores_source = preimage.masm_stack_store_source();

    let source = format!(
        r#"
            use.std::sys
            begin
                # Push two digests to stack
                {stack_stores_source}
                # => [digest_left_lo, digest_left_hi, digest_right_lo, digest_right_hi, ...]

                emit.event("{KECCAK_MERGE_STACK_EVENT_ID}")

                emit.event("{DEBUG_EVENT_ID}")
                exec.sys::truncate_stack
            end
            "#,
    );

    let mut test = build_debug_test!(source, &[]);

    test.add_event_handler(string_to_event_id(DEBUG_EVENT_ID), preimage.handler_test());
    test.execute().unwrap();
}

fn test_keccak_merge_stack_wrapper_with_input(input_u8: &[u8]) {
    let preimage = Preimage(input_u8.to_vec());

    let stack_stores_source = preimage.masm_stack_store_source();

    let source = format!(
        r#"
            use.std::sys
            use.std::crypto::hashes::keccak_precompile

            begin
                # Push two digests to stack
                {stack_stores_source}
                # => [digest_left_lo, digest_left_hi, digest_right_lo, digest_right_hi, ...]

                exec.keccak_precompile::merge_stack
                # => [commitment, keccak_lo, keccak_hi, ...]

                emit.event("{DEBUG_EVENT_ID}")

                exec.sys::truncate_stack
            end
            "#,
    );

    let mut test = build_debug_test!(source, &[]);

    test.add_event_handler(string_to_event_id(DEBUG_EVENT_ID), preimage.wrapper_test());
    test.execute().unwrap();
}
