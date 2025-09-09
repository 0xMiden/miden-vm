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
//! each containing a u32 value in little-endian order.
//!
//! #### Example Encoding
//! For a 32-byte digest, the encoding process is:
//! 1. **Bytes to u32s**: `[b0,b1,...,b31]` → `[h0,h1,h2,h3,h4,h5,h6,h7]` where each `hi` is a
//!    little-endian u32 (e.g., `h0 = u32::from_le_bytes([b0,b1,b2,b3])`)
//! 2. **Group into words**: `KECCAK_LO = [h0,h1,h2,h3]`, `KECCAK_HI = [h4,h5,h6,h7]`
//! 3. **Stack representation**: `[[h3,h2,h1,h0], [h7,h6,h5,h4]]` (each word reversed for LIFO)
//!
//! This representation allows direct memory writes without element reordering: when written to
//! memory using `mem_storew`, the bytes maintain correct little-endian order.
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

/// Event name for the Keccak256 handler.
pub const KECCAK_HASH_MEMORY_EVENT_NAME: &str = "miden_stdlib::hash::keccak::hash_memory";
/// Event ID for the Keccak256 handler, derived from
/// `string_to_event_id(KECCAK_HASH_MEMORY_EVENT_NAME)`.
pub const KECCAK_HASH_MEMORY_EVENT_ID: Felt = Felt::new(5005056617811169331);

/// Keccak256 event handler that reads data from memory.
///
/// - Input: Reads packed bytes from memory starting at word-aligned `ptr`
/// - Output: Returns hash via advice stack, stores witness in advice map
///
/// Stack: [event_id, ptr, len_bytes, ...]
/// Where ptr must be word-aligned (divisible by 4)
pub fn handle_keccak_hash_memory(
    process: &ProcessState,
) -> Result<Vec<AdviceMutation>, EventError> {
    // Stack: [event_id, ptr, len_bytes, ...]
    let ptr = process.get_stack_item(1).as_int();
    let len_bytes = process.get_stack_item(2).as_int();

    // Read packed u32 values from memory
    let witness_felt = read_witness(process, ptr, len_bytes)
        .ok_or(KeccakError::MemoryReadFailed { ptr, len: len_bytes })?;
    let input_felt = &witness_felt[1..];

    // Recover the input represented as bytes
    let input_u8 = packed_felts_to_bytes(input_felt, len_bytes as usize)?;
    let hash_u8: [u8; 32] = Keccak256::hash(&input_u8).as_bytes();
    let digest = KeccakFeltDigest::from_bytes(&hash_u8);

    // Create commitment for deferred computation tracking
    let calldata_commitment =
        Rpo256::merge(&[Rpo256::hash_elements(input_felt), digest.to_commitment()]);

    let advice_stack_extension = AdviceMutation::extend_stack(digest.to_stack());

    let advice_map_entry = (calldata_commitment, witness_felt);
    let advice_map_extension = AdviceMutation::extend_map(AdviceMap::from_iter([advice_map_entry]));

    Ok(vec![advice_stack_extension, advice_map_extension])
}

// HELPERS
// =================================================================================================

/// Constructs a witness vector for deferred Keccak computation proof.
///
/// Returns a vector containing `[len_bytes, input_u32[..]]` where:
/// - `len_bytes` is the input length in bytes
/// - `input_u32` is the array of u32 values read from memory of length `len_u32 = ⌈len_bytes/4⌉`
///
/// # Preconditions
/// - `ptr` must be word-aligned (multiple of 4)
/// - The memory range `[ptr, ptr + len_u32)` is valid
/// - All read values have been initialized
///
/// The function returns `None` if any of the above conditions are not satisfied.
fn read_witness(process: &ProcessState, ptr: u64, len_bytes: u64) -> Option<Vec<Felt>> {
    // Convert inputs to u32 and check for overflow + alignment.
    let start_addr: u32 = ptr.try_into().ok()?;
    if !start_addr.is_multiple_of(4) {
        return None;
    }

    // number of packed u32 values we will actually read
    let len_packed: u32 = len_bytes.div_ceil(4).try_into().ok()?;
    let end_addr = start_addr.checked_add(len_packed)?;

    // The witness is prepended with the length of the input in bytes, allowing the original
    // byte input to be recovered unambiguously.
    let mut witness = Vec::with_capacity(1 + len_packed as usize);
    witness.push(Felt::new(len_bytes));

    // Read each memory location in the range [start_addr, end_addr) and append to the witness.
    let ctx = process.ctx();
    for addr in start_addr..end_addr {
        let value = process.get_mem_value(ctx, addr)?;
        witness.push(value);
    }
    Some(witness)
}

/// Converts packed field elements to bytes following the byte packing format (see module docs).
///
/// Validates input length, u32 bounds, and zero-padding requirements.
fn packed_felts_to_bytes(input_felt: &[Felt], len_bytes: usize) -> Result<Vec<u8>, KeccakError> {
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

    /// Converts to stack order for VM operations.
    ///
    /// The digest `[h0,h1,h2,h3,h4,h5,h6,h7]` is reorganized as:
    /// - `KECCAK_LO`: `[h0,h1,h2,h3]` → `[h3,h2,h1,h0]` (reversed for stack)
    /// - `KECCAK_HI`: `[h4,h5,h6,h7]` → `[h7,h6,h5,h4]` (reversed for stack)
    ///
    /// Stack layout: `[[h3,h2,h1,h0], [h7,h6,h5,h4]]`
    ///
    /// This reversal per word (not the entire digest) ensures that `mem_storew`
    /// operations preserve correct little-endian byte order in memory.
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

#[cfg(test)]
mod tests {
    use miden_core::utils::string_to_event_id;

    use crate::handlers::keccak::{KECCAK_HASH_MEMORY_EVENT_ID, KECCAK_HASH_MEMORY_EVENT_NAME};

    #[test]
    fn test_event_id() {
        let expected_event_id = string_to_event_id(KECCAK_HASH_MEMORY_EVENT_NAME);
        assert_eq!(KECCAK_HASH_MEMORY_EVENT_ID, expected_event_id);
    }
}
