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
    EventId, Felt, Word, ZERO,
    precompile::{PrecompileCommitment, PrecompileError, PrecompileRequest},
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
/// Also stores the preimage in byte form in the [`AdviceProvider`](miden_processor::AdviceProvider)
/// for deferred verification.
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
/// - **Precompile Requests**: Logs the preimage as a precompile request with tag `[event_id,
///   len_bytes, 0, 0]` in the [`AdviceProvider`](miden_processor::AdviceProvider).
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

    // Store the precompile data for deferred verification.
    let precompile_request_extension =
        AdviceMutation::extend_precompile_requests([preimage.to_precompile_request()]);

    Ok(vec![advice_stack_extension, precompile_request_extension])
}

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

// KECCAK VERIFIER
// ================================================================================================

/// Verifier for Keccak256 precompile computations.
///
/// This verifier validates that Keccak256 hash computations were performed correctly
/// by recomputing the hash from the provided witness data and generating the precompile
/// commitment.
pub fn keccak_verifier(input_u8: &[u8]) -> Result<PrecompileCommitment, PrecompileError> {
    let preimage = KeccakPreimage(input_u8.to_vec());
    Ok(preimage.precompile_commitment())
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
        Rpo256::hash_elements(&self.0)
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

    /// Computes the precompile commitment: `RPO(RPO(input) || RPO(keccak_hash))`, along with the
    /// tag for the computation.
    ///
    /// The tag format is `[event_id, len_bytes, 0, 0]` where `event_id` identifies the Keccak
    /// precompile and `len_bytes` is the original input length.
    ///
    /// This commitment is used by the precompile verification system to ensure
    /// that the hash computation was performed correctly.
    pub fn precompile_commitment(&self) -> PrecompileCommitment {
        let commitment = Rpo256::merge(&[self.input_commitment(), self.digest().to_commitment()]);
        let tag = self.precompile_tag();
        PrecompileCommitment { tag, commitment }
    }

    /// Returns the tag used to identify the commitment to the precompile. defined as
    /// `[KECCAK_HASH_MEMORY_EVENT_ID, preimage_u8.len(), 0, 0]`.
    fn precompile_tag(&self) -> Word {
        [
            KECCAK_HASH_MEMORY_EVENT_ID.as_felt(),
            Felt::new(self.0.len() as u64),
            ZERO,
            ZERO,
        ]
        .into()
    }

    /// Returns this preimage as [`PrecompileRequest`] from which the [`PrecompileCommitment`] can
    /// be recomputed.
    pub fn to_precompile_request(self) -> PrecompileRequest {
        PrecompileRequest {
            event_id: KECCAK_HASH_MEMORY_EVENT_ID,
            data: self.0,
        }
    }
}

impl AsRef<[Felt]> for KeccakFeltDigest {
    fn as_ref(&self) -> &[Felt] {
        &self.0
    }
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

    // KECCAK FELT DIGEST TESTS
    // ============================================================================================

    #[test]
    fn test_keccak_felt_digest_from_bytes() {
        // Test with a known 32-byte sequence
        let bytes: Vec<u8> = (1..=32).collect();
        let digest = KeccakFeltDigest::from_bytes(&bytes);

        // Verify each u32 is packed correctly in little-endian order
        // Each u32 is constructed from 4 consecutive bytes: byte[i] + byte[i+1]<<8 + byte[i+2]<<16
        // + byte[i+3]<<24
        let expected = [
            u32::from_le_bytes([1, 2, 3, 4]),
            u32::from_le_bytes([5, 6, 7, 8]),
            u32::from_le_bytes([9, 10, 11, 12]),
            u32::from_le_bytes([13, 14, 15, 16]),
            u32::from_le_bytes([17, 18, 19, 20]),
            u32::from_le_bytes([21, 22, 23, 24]),
            u32::from_le_bytes([25, 26, 27, 28]),
            u32::from_le_bytes([29, 30, 31, 32]),
        ]
        .map(Felt::from);

        assert_eq!(digest.0, expected);
    }

    // KECCAK PREIMAGE TESTS
    // ============================================================================================

    #[test]
    fn test_keccak_preimage_empty() {
        let preimage = KeccakPreimage(vec![]);

        // Empty input should produce empty felt vector
        assert_eq!(preimage.as_felts(), vec![]);

        // Test round-trip conversion
        let recovered = KeccakPreimage::from_felts(&[], 0).unwrap();
        assert_eq!(recovered.0, vec![]);

        // An empty preimage yields the empty word
        assert_eq!(preimage.input_commitment(), Word::empty())
    }

    #[test]
    fn test_keccak_preimage_single_byte() {
        let input = vec![0x42u8];
        let preimage = KeccakPreimage(input.clone());

        // Should pack into single felt with zero padding
        let felts = preimage.as_felts();
        assert_eq!(felts.len(), 1);
        assert_eq!(felts[0], Felt::from(0x42u32)); // Little-endian: [0x42, 0, 0, 0]

        // Test round-trip conversion
        let recovered = KeccakPreimage::from_felts(&felts, 1).unwrap();
        assert_eq!(recovered.0, input);
    }

    #[test]
    fn test_keccak_preimage_four_bytes() {
        let input = vec![0x01, 0x02, 0x03, 0x04];
        let preimage = KeccakPreimage(input.clone());

        // Should pack into single u32 in little-endian order
        let felts = preimage.as_felts();
        assert_eq!(felts.len(), 1);
        assert_eq!(felts[0], Felt::from(0x04030201u32));

        // Test round-trip conversion
        let recovered = KeccakPreimage::from_felts(&felts, 4).unwrap();
        assert_eq!(recovered.0, input);
    }

    #[test]
    fn test_keccak_preimage_five_bytes() {
        let input = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let preimage = KeccakPreimage(input.clone());

        // Should pack into two felts: first with 4 bytes, second with 1 byte + padding
        let felts = preimage.as_felts();
        assert_eq!(felts.len(), 2);
        assert_eq!(felts[0], Felt::from(0x04030201u32));
        assert_eq!(felts[1], Felt::from(0x05u32)); // [0x05, 0, 0, 0] in little-endian

        // Test round-trip conversion
        let recovered = KeccakPreimage::from_felts(&felts, 5).unwrap();
        assert_eq!(recovered.0, input);
    }

    #[test]
    fn test_keccak_preimage_32_bytes() {
        let input: Vec<u8> = (1..=32).collect();
        let preimage = KeccakPreimage(input.clone());

        // Should pack into 8 felts (32 bytes / 4 bytes per felt)
        let felts = preimage.as_felts();
        assert_eq!(felts.len(), 8);

        // Check first and last felt values
        assert_eq!(felts[0], Felt::from(u32::from_le_bytes([1, 2, 3, 4]))); // bytes [1,2,3,4]
        assert_eq!(felts[7], Felt::from(u32::from_le_bytes([29, 30, 31, 32]))); // bytes [29,30,31,32]

        // Test round-trip conversion
        let recovered = KeccakPreimage::from_felts(&felts, 32).unwrap();
        assert_eq!(recovered.0, input);
    }

    #[test]
    fn test_keccak_preimage_from_felts_comprehensive() {
        // Test sizes 4-7 with both valid (zero padding) and invalid (non-zero padding) cases
        for size in 4..=7 {
            // Create input data of the specified size
            let input: Vec<u8> = (0..size).map(|i| (i + 1) as u8).collect();
            let preimage = KeccakPreimage(input.clone());
            let felts = preimage.as_felts();

            // Test 1: Valid round-trip with proper zero padding
            let recovered = KeccakPreimage::from_felts(&felts, size).unwrap();
            assert_eq!(recovered.0, input, "Round-trip failed for size {}", size);

            // Test 2: Invalid padding - modify the felt to have non-zero padding bytes
            // Only test padding corruption for sizes that don't fill the complete felt (sizes 4-7
            // all require padding)
            let num_felts_needed = size.div_ceil(4);
            let bytes_in_last_felt = if size % 4 == 0 { 4 } else { size % 4 };

            if bytes_in_last_felt < 4 {
                let mut invalid_felts = felts.clone();
                let last_felt_idx = num_felts_needed - 1;
                let felt_value = invalid_felts[last_felt_idx].as_int() as u32;

                // Set the first padding byte to non-zero (0xFF)
                // Padding starts at byte position bytes_in_last_felt
                let corrupted_value = felt_value | (0xff << (bytes_in_last_felt * 8));
                invalid_felts[last_felt_idx] = Felt::from(corrupted_value);

                let result = KeccakPreimage::from_felts(&invalid_felts, size);
                assert!(
                    matches!(result, Err(KeccakError::InvalidPadding { value: 0xff, .. })),
                    "Expected padding error for size {}, got {:?}",
                    size,
                    result
                );
            }
        }

        // Test invalid input length errors
        let felts = vec![Felt::from(1u32), Felt::from(2u32)];

        // Test with wrong number of felts (need 3 felts for 9 bytes, but only have 2)
        let result = KeccakPreimage::from_felts(&felts, 9);
        assert!(matches!(
            result,
            Err(KeccakError::InvalidInputLength { actual: 2, expected: 3 })
        ));

        // Test felt value too large (exceeds u32::MAX)
        let large_felt = Felt::new(4294967296u64); // u32::MAX + 1
        let result = KeccakPreimage::from_felts(&[large_felt], 4);
        assert!(matches!(result, Err(KeccakError::InvalidFeltValue { .. })));
    }

    #[test]
    fn test_keccak_preimage_digest_consistency() {
        // Test that digest computation is consistent with direct Keccak256
        let input = b"hello world";
        let preimage = KeccakPreimage(input.to_vec());

        // Compute digest using preimage
        let preimage_digest = preimage.digest();

        // Compute digest directly using Keccak256
        let direct_hash = Keccak256::hash(input);
        let direct_digest = KeccakFeltDigest::from_bytes(&direct_hash);

        assert_eq!(preimage_digest, direct_digest);
    }

    #[test]
    fn test_keccak_preimage_commitments() {
        let input = b"test input for commitments";
        let preimage = KeccakPreimage(input.to_vec());

        // Test input commitment
        let felts = preimage.as_felts();
        let expected_input_commitment = Rpo256::hash_elements(&felts);
        assert_eq!(preimage.input_commitment(), expected_input_commitment);

        // Test digest commitment
        let digest = preimage.digest();
        let expected_digest_commitment = Rpo256::hash_elements(digest.as_ref());
        assert_eq!(digest.to_commitment(), expected_digest_commitment);

        // Test precompile commitment (double hash)
        let expected_precompile_commitment = PrecompileCommitment {
            tag: preimage.precompile_tag(),
            commitment: Rpo256::merge(&[preimage.input_commitment(), digest.to_commitment()]),
        };

        assert_eq!(preimage.precompile_commitment(), expected_precompile_commitment);
    }

    #[test]
    fn test_keccak_preimage_round_trip_various_sizes() {
        let test_sizes = [0, 1, 3, 4, 5, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128];

        for size in test_sizes {
            let input: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let preimage = KeccakPreimage(input.clone());

            // Convert to felts and back
            let felts = preimage.as_felts();
            let recovered = KeccakPreimage::from_felts(&felts, size).unwrap();

            assert_eq!(recovered.0, input, "Round-trip failed for size {}", size);
        }
    }

    #[test]
    fn test_keccak_verifier() {
        let input = b"test verifier input";
        let preimage = KeccakPreimage(input.to_vec());
        let expected_commitment = preimage.precompile_commitment();

        let commitment = keccak_verifier(input).unwrap();
        assert_eq!(commitment, expected_commitment);
    }
}
