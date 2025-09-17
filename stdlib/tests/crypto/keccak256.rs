//! Tests for Keccak256 precompile event handlers.
//!
//! Verifies that:
//! - Raw event handlers correctly compute Keccak256 and populate advice provider
//! - MASM wrappers correctly return commitment and digest on stack
//! - Both memory and digest merge operations work correctly
//! - Various input sizes and edge cases are handled properly

use core::array;

use miden_core::{EventId, Felt};
use miden_crypto::{
    Word,
    hash::{keccak::Keccak256, rpo::Rpo256},
};
use miden_processor::{AdviceMutation, EventError, EventHandler, ProcessState};
use miden_stdlib::handlers::keccak256::{KECCAK_HASH_MEMORY_EVENT_NAME, KeccakFeltDigest};

// Test constants
// ================================================================================================

const INPUT_MEMORY_ADDR: u32 = 128;
const DEBUG_EVENT_NAME: &str = "miden::debug";

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

                emit.event("{KECCAK_HASH_MEMORY_EVENT_NAME}")
                drop drop

                emit.event("{DEBUG_EVENT_NAME}")
            end
            "#,
    );

    let mut test = build_debug_test!(source, &[]);

    test.add_event_handler(EventId::from_name(DEBUG_EVENT_NAME), preimage.handler_test());
    test.execute().unwrap();
}

fn test_keccak_hash_memory_impl(input_u8: &[u8]) {
    let len_bytes = input_u8.len();
    let preimage = Preimage(input_u8.to_vec());

    let memory_stores_source = preimage.masm_memory_store_source();

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
    assert_eq!(commitment, preimage.calldata_commitment(), "calldata_commitment does not match");

    let digest: [Felt; 8] = array::from_fn(|i| stack.get_stack_item(4 + i).unwrap());
    assert_eq!(digest, preimage.digest().inner(), "output digest does not match");
}

fn test_keccak_hash_memory(input_u8: &[u8]) {
    let len_bytes = input_u8.len();
    let preimage = Preimage(input_u8.to_vec());

    let memory_stores_source = preimage.masm_memory_store_source();

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
    let preimage = Preimage(input_u8);

    let stack_stores_source = preimage.masm_stack_store_source();

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
    let preimage = Preimage(input_u8);

    let stack_stores_source = preimage.masm_stack_store_source();

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

// DEBUG HANDLER
// ================================================================================================

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

    /// Generates MASM code to push the input represented as u32 values to the stack
    fn masm_stack_store_source(&self) -> String {
        let input_u32: Vec<u32> = self.as_packed_u32().collect();
        // Push elements in reverse order so that the first element ends up at the top
        input_u32
            .into_iter()
            .rev()
            .map(|value| format!("push.{}", value))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Handler for verifying the correctness of the keccak handler.
    fn handler_test(self) -> impl EventHandler {
        move |process: &ProcessState| -> Result<Vec<AdviceMutation>, EventError> {
            let digest = self.digest();
            assert_eq!(
                &digest.inner(),
                process.advice_provider().stack(),
                "digest not found in advice stack"
            );

            let calldata_commitment = self.calldata_commitment();
            let witness = process
                .advice_provider()
                .get_mapped_values(&calldata_commitment)
                .expect("witness was not found in advice map with key {calldata_commitment:?}");
            let witness_expected: Vec<Felt> = {
                let len_bytes = self.0.len() as u64;

                [Felt::new(len_bytes)].into_iter().chain(self.as_felt()).collect()
            };
            assert_eq!(witness, witness_expected, "witness in advice map does not match preimage");

            Ok(vec![])
        }
    }
}
