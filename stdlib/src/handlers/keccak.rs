//! Keccak256 precompile event handlers for the Miden VM.
//!
//! Event handlers compute Keccak256 hashes and:
//! - Return the hash to the VM via the advice stack
//! - Store witness data (byte length + input felts) in the advice map for later proof generation
//!
//! The MASM wrappers return a commitment for future kernel tracking of deferred computations,
//! as well as the actual digest, encoded as two words.
//!
//! ## Key Concepts
//!
//! ### Digest Representation
//! A Keccak256 digest (256 bits) is represented as [`KeccakFeltDigest`]: 8 field elements,
//! each containing a u32 value in little-endian order. In the VM, digests are stored as
//! two words to enable efficient memory operations. Each word is encoded in little-endian order
//! (reversed in the VM stack).
//!
//! ### Byte Packing
//! Input bytes are packed into field elements as u32 values:
//! - Each field element holds 4 bytes (one u32) in little-endian format
//! - Number of field elements = ceil(len_bytes / 4)
//! - Unused bytes in the final u32 must be zero
//! - Byte length is stored in witness since packing loses this information

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{AdviceMap, Felt, FieldElement, Word, crypto::hash::Digest};
use miden_crypto::hash::{keccak::Keccak256, rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, ProcessState};

use crate::handlers::read_memory;

/// Event ID for memory-based Keccak256 computation
pub const KECCAK_HASH_MEM_EVENT_ID: &str = "miden_stdlib::hash::keccak::hash_mem";
/// Event ID for stack-based Keccak256 merge computation
pub const KECCAK_MERGE_STACK_EVENT_ID: &str = "miden_stdlib::hash::keccak::merge_stack";

/// Keccak256 event handler that reads data from memory.
///
/// - Input: Reads packed bytes from memory starting at word-aligned `ptr`
/// - Output: Returns hash via advice stack, stores witness in advice map
///
/// Stack: [event_id, ptr, len_bytes, ...]
/// Where ptr must be word-aligned (divisible by 4)
pub fn handle_keccak_hash_mem(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    // Stack: [event_id, ptr, len_bytes, ...]
    let ptr = process.get_stack_item(1).as_int();
    let len_bytes = process.get_stack_item(2).as_int();

    if len_bytes > u32::MAX as u64 {
        return Err(KeccakError::MemoryReadFailed { ptr, len: len_bytes }.into());
    }

    // Read packed u32 values from memory
    let len_u32 = len_bytes.div_ceil(4);
    let input_felt = read_memory(process, ptr, len_u32)
        .ok_or(KeccakError::MemoryReadFailed { ptr, len: len_bytes })?;

    compute_keccak_with_commitment(input_felt, len_bytes as usize)
}

/// Keccak256 event handler that merges two digests.
///
/// - Input: Reads two 256-bit digests from stack as four words
/// - Output: Returns Keccak256(left || right) via advice stack, stores witness in advice map
///
/// Stack: [event_id, digest_left_lo, digest_left_hi, digest_right_lo, digest_right_hi, ...]
pub fn handle_keccak_merge_stack(
    process: &ProcessState,
) -> Result<Vec<AdviceMutation>, EventError> {
    // Stack contains two KeccakFeltDigest values as four words
    let input: Vec<Felt> = [
        process.get_stack_word(1),  // digest_left_lo (word 1)
        process.get_stack_word(5),  // digest_left_hi (word 2)
        process.get_stack_word(9),  // digest_right_lo (word 3)
        process.get_stack_word(13), // digest_right_hi (word 4)
    ]
    .into_iter()
    .flatten()
    .collect();

    compute_keccak_with_commitment(input, 64)
}

/// Common helper that computes hash and returns it via advice mutations.
fn compute_keccak_with_commitment(
    mut input_felt: Vec<Felt>,
    len_bytes: usize,
) -> Result<Vec<AdviceMutation>, EventError> {
    let input_u8 = packed_felts_to_bytes(&input_felt, len_bytes)?;
    let hash_u8: [u8; 32] = Keccak256::hash(&input_u8).as_bytes();
    let digest = KeccakFeltDigest::from_bytes(&hash_u8);

    // Create commitment for deferred computation tracking
    let calldata_commitment =
        Rpo256::merge(&[Rpo256::hash_elements(&input_felt), digest.to_commitment()]);

    // Store witness: [len_bytes, ...input_felts]
    input_felt.insert(0, Felt::new(len_bytes as u64));
    let advice_map_entry = (calldata_commitment, input_felt);

    let advice_stack_extension = AdviceMutation::extend_stack(digest.to_stack());
    let advice_map_extension = AdviceMutation::extend_map(AdviceMap::from_iter([advice_map_entry]));

    Ok(vec![advice_stack_extension, advice_map_extension])
}

/// Converts packed field elements to bytes following the byte packing format (see module docs).
///
/// Validates input length, u32 bounds, and zero-padding requirements.
fn packed_felts_to_bytes(input_felt: &[Felt], len_bytes: usize) -> Result<Vec<u8>, KeccakError> {
    // Validate expected number of field elements
    let expected_len = len_bytes.div_ceil(4);
    if input_felt.len() != expected_len {
        return Err(KeccakError::InvalidInputLength {
            actual: input_felt.len(),
            expected: expected_len,
        });
    }

    // Allocate buffer with 4-byte alignment
    let mut bytes = vec![0u8; len_bytes.next_multiple_of(4)];

    // Unpack field elements to bytes (little-endian)
    for (index, (byte_chunk, felt)) in bytes.chunks_exact_mut(4).zip(input_felt.iter()).enumerate()
    {
        let value: u32 = felt
            .as_int()
            .try_into()
            .map_err(|_| KeccakError::InvalidFeltValue { value: felt.as_int(), index })?;
        byte_chunk.copy_from_slice(&value.to_le_bytes())
    }

    // Verify zero-padding in final u32
    for (index, &to_drop) in bytes[len_bytes..].iter().enumerate() {
        if to_drop != 0 {
            return Err(KeccakError::InvalidPadding { value: to_drop, index: len_bytes + index });
        }
    }

    bytes.truncate(len_bytes);
    Ok(bytes)
}

/// Keccak256 digest representation in the Miden VM (see module docs for layout details).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct KeccakFeltDigest([Felt; 8]);

impl KeccakFeltDigest {
    /// Creates a digest from a 32-byte Keccak256 hash output.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 32, "input must be 32 bytes");
        let packed: [u32; 8] = array::from_fn(|i| {
            let limbs = array::from_fn(|j| bytes[4 * i + j]);
            u32::from_le_bytes(limbs)
        });
        Self(packed.map(Felt::from))
    }

    /// Creates a digest from two VM words.
    pub fn from_words(lo: Word, hi: Word) -> Self {
        let mut out = [Felt::ZERO; 8];
        out[0..4].copy_from_slice(lo.as_slice());
        out[4..8].copy_from_slice(hi.as_slice());
        Self(out)
    }

    /// Creates an RPO hash commitment of the digest.
    pub fn to_commitment(&self) -> Word {
        Rpo256::hash_elements(&self.0)
    }

    /// Converts to stack order (LIFO): [0,1,2,3,4,5,6,7] → [3,2,1,0,7,6,5,4].
    pub fn to_stack(&self) -> [Felt; 8] {
        const fn reverse(limbs: &mut [Felt]) {
            limbs.swap(3, 0);
            limbs.swap(2, 1);
        }

        let mut out = self.0;
        reverse(&mut out[0..4]); // Reverse low word
        reverse(&mut out[4..8]); // Reverse high word
        out
    }

    /// Returns the internal field element representation.
    pub fn to_felts(&self) -> [Felt; 8] {
        self.0
    }

    /// Converts to two Miden words for memory operations.
    pub fn to_words(&self) -> (Word, Word) {
        let lo = Word::try_from(&self.0[0..4]).unwrap();
        let hi = Word::try_from(&self.0[4..8]).unwrap();
        (lo, hi)
    }
}

// KECCAK EVENT ERROR
// ================================================================================================

/// Error types that can occur during Keccak256 precompile operations.
#[derive(Debug, thiserror::Error)]
pub enum KeccakError {
    /// Memory read operation failed at the specified pointer and length.
    #[error("failed to read memory at ptr {ptr}, len {len}")]
    MemoryReadFailed { ptr: u64, len: u64 },

    /// Input length validation failed - wrong number of field elements provided.
    #[error("invalid input length: got {actual}, expected {expected}")]
    InvalidInputLength { actual: usize, expected: usize },

    /// Field element value exceeds u32::MAX and cannot be converted to u32.
    #[error("field element value {value} at index {index} exceeds u32::MAX")]
    InvalidFeltValue { value: u64, index: usize },

    /// Non-zero padding bytes found in unused portion of final u32.
    #[error("non-zero padding byte {value:#x} at position {index}")]
    InvalidPadding { value: u8, index: usize },
}
