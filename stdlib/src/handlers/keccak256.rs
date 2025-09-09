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

use miden_core::{AdviceMap, Felt, Word, crypto::hash::Digest};
use miden_crypto::hash::{keccak::Keccak256, rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, ProcessState};

/// Event name for the Keccak256 handler.
pub const KECCAK_HASH_MEMORY_EVENT_NAME: &str = "miden_stdlib::hash::keccak256::hash_memory";
/// Event ID for the Keccak256 handler, derived from
/// `string_to_event_id(KECCAK_HASH_MEMORY_EVENT_NAME)`.
pub const KECCAK_HASH_MEMORY_EVENT_ID: Felt = Felt::new(871406259734432837);

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
/// - **Advice Map**: Contains witness vector `[len_bytes, input_u32[..]]` for proof generation
/// - **Commitment**: `Rpo256(Rpo256(input) || Rpo256(digest))` for kernel tracking of deferred
///   computations
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

    // Extend the stack with the digest [h_0, ..., h_7] so it can be popped in the right order,
    // i.e. with h_0 at the top.
    let advice_stack_extension = AdviceMutation::extend_stack(digest.0);

    let advice_map_entry = (calldata_commitment, witness_felt);
    let advice_map_extension = AdviceMutation::extend_map(AdviceMap::from_iter([advice_map_entry]));

    Ok(vec![advice_stack_extension, advice_map_extension])
}

// HELPERS
// =================================================================================================

/// Constructs a witness vector for deferred Keccak computation proof.
///
/// The memory layout from ptr to `ptr+len_u32` contains inputs from least to most significant
/// element.
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

/// Converts packed field elements to bytes following the byte packing format expected by
/// [`handle_keccak_hash_memory`].
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

    use crate::handlers::keccak256::{KECCAK_HASH_MEMORY_EVENT_ID, KECCAK_HASH_MEMORY_EVENT_NAME};

    #[test]
    fn test_event_id() {
        let expected_event_id = string_to_event_id(KECCAK_HASH_MEMORY_EVENT_NAME);
        assert_eq!(KECCAK_HASH_MEMORY_EVENT_ID, expected_event_id);
    }
}
