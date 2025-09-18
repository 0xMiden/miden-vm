//! Keccak256 precompile event handlers for the Miden VM.
//!
//! Event handlers compute Keccak256 hashes and provide them to the VM via the advice stack,
//! while storing witness data for later proof generation.
//!
//! ## Digest Representation
//! A Keccak256 digest (256 bits) is represented as 8 field elements `[h0, ..., h7]`,
//! each containing a u32 value where `hi = u32::from_le_bytes([b_{4i}, ..., b_{4i+3}])`.

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{
    EventId, Felt, Word,
    precompile::{PrecompileData, PrecompileError},
};
use miden_crypto::hash::{keccak::Keccak256, rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, ProcessState};

/// Qualified event name for the `hash_memory` event.
pub const KECCAK_HASH_MEMORY_EVENT_NAME: &str = "stdlib::hash::keccak256::hash_memory";
/// Constant Event ID for the `hash_memory` event, derived via
/// `EventId::from_name(SMT_PEEK_EVENT_NAME)`
pub const KECCAK_HASH_MEMORY_EVENT_ID: EventId = EventId::from_u64(5779517439479051634);

/// Keccak256 event handler that reads data from memory.
///
/// Computes Keccak256 hash of data stored in memory and provides the result via the advice stack.
/// Also stores witness data (byte length + input elements) in the advice map for later proof
/// generation.
///
/// ## Input Format
/// - **Memory Layout**: Input bytes are packed into field elements as u32 values:
///   - Each field element holds 4 bytes in little-endian format
///   - Number of field elements = `ceil(len_bytes / 4)`
///   - Unused bytes in the final u32 must be zero
///   - Memory layout from `ptr` to `ptr+len_u32` contains inputs from least to most significant
///     element
/// - **Stack**: `[event_id, ptr, len_bytes, ...]` where `ptr` must be word-aligned (divisible by 4)
///
/// ## Output Format
/// - **Advice Stack**: Extended with digest `[h_0, ..., h_7]` so the least significant u32 (h_0) is
///   at the top of the stack
/// - **Advice Map**: Contains precompile data with raw input bytes for proof generation
/// - **Commitment**: `Rpo256(Rpo256(input) || Rpo256(digest))` for kernel tracking of deferred
///   computations
pub fn handle_keccak_hash_memory(
    process: &ProcessState,
) -> Result<Vec<AdviceMutation>, EventError> {
    // Stack: [event_id, ptr, len_bytes, ...]
    let ptr = process.get_stack_item(1).as_int();
    let len_bytes = process.get_stack_item(2).as_int();

    // Read packed u32 values from memory
    let input_felt = read_witness(process, ptr, len_bytes)
        .ok_or(KeccakError::MemoryReadFailed { ptr, len: len_bytes })?;

    // Recover the input represented as bytes
    let preimage = KeccakPreimage::from_felts(&input_felt, len_bytes as usize)?;
    let digest = preimage.digest();

    // Extend the stack with the digest [h_0, ..., h_7] so it can be popped in the right order,
    // i.e. with h_0 at the top.
    let advice_stack_extension = AdviceMutation::extend_stack(digest.0);

    // Store the precompile data for later proof generation
    let deferred_extension =
        AdviceMutation::extend_precompile_requests(preimage.to_precompile_data());

    Ok(vec![advice_stack_extension, deferred_extension])
}

// KECCAK VERIFIER
// ================================================================================================

/// Verifier for Keccak256 precompile computations.
///
/// This verifier validates that Keccak256 hash computations were performed correctly
/// by recomputing the hash from the provided witness data and comparing the result.
pub fn keccak_verifier(input_u8: &[u8]) -> Result<Word, PrecompileError> {
    let preimage = KeccakPreimage::new(input_u8.to_vec());
    let commitment = preimage.precompile_commitment();
    Ok(commitment)
}

// KECCAK DIGEST
// ================================================================================================

/// Keccak256 digest representation in the Miden VM.
///
/// Represents a 256-bit Keccak digest as 8 field elements, each containing a u32 value
/// packed in little-endian order: `[d_0, ..., d_7]` where
/// `d_0 = u32::from_le_bytes([b_0, b_1, b_2, b_3])` and so on.
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

    /// Creates an commitment of the digest using Rpo256.
    ///
    /// When the digest is popped from the advice stack, it appears as
    /// `[d_0, ..., d_7]` on the operand stack. In masm, the `hmerge` operation computes
    /// `Rpo256([d_7, ..., d_0])`, so we reverse the order here to match that behavior.
    pub fn to_commitment(&self) -> Word {
        let mut rev = self.0;
        rev.reverse();
        Rpo256::hash_elements(&rev)
    }

    /// Returns this digest as an array of [`Felt`]s as `[d_0, ..., d_7]`.
    pub fn inner(&self) -> [Felt; 8] {
        self.0
    }
}

// KECCAK PREIMAGE
// ================================================================================================

/// Keccak256 preimage structure representing the raw input data to be hashed.
///
/// This structure encapsulates the raw bytes that will be passed to the Keccak256
/// hash function, providing utilities for:
/// - Converting between bytes and field element representations
/// - Computing the Keccak256 digest
/// - Generating precompile commitments for verification
/// - Handling the data packing format used by the VM
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeccakPreimage(pub Vec<u8>);

impl KeccakPreimage {
    /// Creates a new Keccak preimage from raw bytes.
    ///
    /// # Arguments
    /// * `data` - The raw bytes to be hashed
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Converts field elements to bytes using the VM's u32 packing format.
    ///
    /// This method validates that:
    /// - Each field element value fits in a u32 (≤ u32::MAX)
    /// - Zero-padding in the final u32 is correct (unused bytes must be 0)
    /// - The total byte length matches the expected input length
    ///
    /// # Arguments
    /// * `input_felt` - Field elements containing packed u32 values
    /// * `len_bytes` - The actual length of the input data in bytes
    ///
    /// # Returns
    /// A `KeccakPreimage` containing the unpacked bytes, or an error if validation fails.
    ///
    /// # Byte Packing Format
    /// Each field element contains 4 bytes in little-endian format:
    /// - `felt[i] = u32::from_le_bytes([b[4*i], b[4*i+1], b[4*i+2], b[4*i+3]])`
    /// - Unused bytes in the final u32 must be zero
    pub fn from_felts(input_felt: &[Felt], len_bytes: usize) -> Result<Self, KeccakError> {
        // Validate inputs
        let expected_felts = len_bytes.div_ceil(4);
        if input_felt.len() != expected_felts {
            return Err(KeccakError::InvalidInputLength {
                actual: input_felt.len(),
                expected: expected_felts,
            });
        }

        // Allocate buffer with 4-byte alignment
        let mut bytes = vec![0u8; len_bytes.next_multiple_of(4)];

        // Unpack field elements to bytes (little-endian)
        for (index, (byte_chunk, felt)) in bytes.chunks_exact_mut(4).zip(input_felt).enumerate() {
            let value: u32 = felt
                .as_int()
                .try_into()
                .map_err(|_| KeccakError::InvalidFeltValue { value: felt.as_int(), index })?;
            byte_chunk.copy_from_slice(&value.to_le_bytes())
        }

        // Verify zero-padding in final u32
        for (index, &to_drop) in bytes[len_bytes..].iter().enumerate() {
            if to_drop != 0 {
                return Err(KeccakError::InvalidPadding {
                    value: to_drop,
                    index: len_bytes + index,
                });
            }
        }

        bytes.truncate(len_bytes);
        Ok(Self(bytes))
    }

    /// Converts the preimage bytes to field elements using u32 packing.
    ///
    /// Each field element contains a u32 value representing 4 bytes in little-endian format.
    /// The last chunk is padded with zeros if the byte length is not a multiple of 4.
    ///
    /// This method is the inverse of `from_felts()` and produces the same format
    /// expected by the Keccak256 event handlers.
    pub fn as_felts(&self) -> Vec<Felt> {
        self.0
            .chunks(4)
            .map(|bytes| {
                // Pack up to 4 bytes into a u32 in little-endian format
                let mut packed = [0u8; 4];
                packed[..bytes.len()].copy_from_slice(bytes);
                Felt::from(u32::from_le_bytes(packed))
            })
            .collect()
    }

    /// Computes the RPO hash of the input data in field element format.
    ///
    /// This creates a cryptographic commitment to the input data that can be
    /// used for verification purposes. The input is first converted to field
    /// elements using the same packing format as the VM.
    pub fn input_commitment(&self) -> Word {
        Rpo256::hash_elements(&self.as_felts())
    }

    /// Computes the Keccak256 hash of the preimage bytes.
    ///
    /// Returns the digest formatted as 8 field elements, each containing a u32 value
    /// in little-endian byte order. This matches the format expected by the VM
    /// and can be directly used on the operand stack.
    pub fn digest(&self) -> KeccakFeltDigest {
        let hash_u8 = Keccak256::hash(&self.0);
        KeccakFeltDigest::from_bytes(&hash_u8)
    }

    /// Computes the precompile commitment: RPO(RPO(input) || RPO(hash)).
    ///
    /// This commitment is used by the precompile verification system to ensure
    /// that the hash computation was performed correctly. The double RPO structure
    /// allows the verifier to independently verify both the input data integrity
    /// and the correctness of the hash computation.
    pub fn precompile_commitment(&self) -> Word {
        Rpo256::merge(&[self.input_commitment(), self.digest().to_commitment()])
    }

    pub fn to_precompile_data(self) -> PrecompileData {
        PrecompileData::new(KECCAK_HASH_MEMORY_EVENT_ID, self.0)
    }
}

// HELPERS
// =================================================================================================

/// Reads field elements from memory for Keccak computation.
///
/// The memory layout from ptr to `ptr+len_u32` contains inputs from least to most significant
/// element.
///
/// Returns a vector containing `input_u32[..]` where:
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

    // Read each memory location in the range [start_addr, end_addr) and append to the witness.
    let ctx = process.ctx();
    (start_addr..end_addr).map(|addr| process.get_mem_value(ctx, addr)).collect()
}

// ERRORS
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
    use super::*;

    #[test]
    fn test_event_id() {
        let expected_event_id = EventId::from_name(KECCAK_HASH_MEMORY_EVENT_NAME);
        assert_eq!(KECCAK_HASH_MEMORY_EVENT_ID, expected_event_id);
    }
}
