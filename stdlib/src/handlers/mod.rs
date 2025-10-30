use alloc::vec::Vec;
use core::mem::size_of;

use miden_core::{Felt, WORD_SIZE};
use miden_processor::ProcessState;

/// Number of bytes packed into each u32 field element.
///
/// Used for converting between byte arrays and u32-packed field elements in memory.
pub(crate) const BYTES_PER_U32: usize = size_of::<u32>();

pub mod falcon_div;
pub mod keccak256;
pub mod smt_peek;
pub mod sorted_array;
pub mod u64_div;

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a u64 value into two u32 elements (high and low parts).
fn u64_to_u32_elements(value: u64) -> (Felt, Felt) {
    let hi = Felt::from((value >> 32) as u32);
    let lo = Felt::from(value as u32);
    (hi, lo)
}

/// Reads packed u32 values from memory and returns them as a byte vector.
///
/// This function reads field elements from memory where each element contains a u32 value
/// packed in little-endian byte order. It's commonly used for reading precompile inputs
/// (e.g., Keccak256, ECDSA) where data is stored as packed bytes in memory.
///
/// # Memory Layout
/// - Each field element stores 4 bytes in little-endian format: `felt[i] =
///   u32::from_le_bytes([byte[4*i], byte[4*i+1], byte[4*i+2], byte[4*i+3]])`
/// - The function reads `⌈len_bytes/4⌉` field elements from memory
/// - Memory addresses range from `start` to `start + ⌈len_bytes/4⌉` (exclusive)
///
/// # Arguments
/// - `process`: The process state containing memory to read from
/// - `start`: Starting memory address (must be word-aligned, i.e., divisible by 4)
/// - `len_bytes`: Number of bytes to read from memory
///
/// # Returns
/// A vector containing exactly `len_bytes` bytes read from memory.
///
/// # Errors
/// Returns an error if:
/// - `start` address is not word-aligned (not divisible by 4)
/// - Address arithmetic overflows (start + length exceeds u32::MAX)
/// - Any memory location in the range cannot be read (uninitialized or out of bounds)
/// - Any field element value exceeds u32::MAX
/// - Padding bytes in the final u32 are non-zero (when `len_bytes` is not a multiple of 4)
///
/// # Examples
/// ```ignore
/// // Read 5 bytes from address 0x100
/// // Memory layout: addr[0x100] = 0x04030201, addr[0x104] = 0x00000005
/// let bytes = read_memory_packed_u32(process, 0x100, 5)?;
/// // Returns: [0x01, 0x02, 0x03, 0x04, 0x05]
/// ```
pub(crate) fn read_memory_packed_u32(
    process: &ProcessState,
    start: u64,
    len_bytes: usize,
) -> Result<Vec<u8>, MemoryReadError> {
    // Validate word alignment
    if !start.is_multiple_of(WORD_SIZE as u64) {
        return Err(MemoryReadError::UnalignedAddress { address: start });
    }

    // Calculate number of field elements to read
    let len_felt = len_bytes.div_ceil(BYTES_PER_U32);
    let end = start
        .checked_add(len_felt as u64)
        .ok_or(MemoryReadError::AddressOverflow { start, len_bytes })?;

    // Convert to u32 addresses
    let start_u32 = start
        .try_into()
        .map_err(|_| MemoryReadError::AddressOverflow { start, len_bytes })?;
    let end_u32 = end
        .try_into()
        .map_err(|_| MemoryReadError::AddressOverflow { start, len_bytes })?;

    // Read field elements and unpack to bytes
    let len_padded = len_bytes
        .checked_next_multiple_of(BYTES_PER_U32)
        .ok_or(MemoryReadError::AddressOverflow { start, len_bytes })?;

    // Allocate buffer with 4-byte alignment
    let mut out = Vec::with_capacity(len_padded);

    let ctx = process.ctx();
    for address in start_u32..end_u32 {
        let felt = process
            .get_mem_value(ctx, address)
            .ok_or(MemoryReadError::MemoryAccessFailed { address })?;

        let value = felt.as_int();
        // Unpack field elements to bytes (little-endian)
        let packed: u32 =
            value.try_into().map_err(|_| MemoryReadError::InvalidValue { value, address })?;

        out.extend(packed.to_le_bytes());
    }

    // Validate zero-padding in the final u32
    for (offset, &byte) in out[len_bytes..].iter().enumerate() {
        if byte != 0 {
            return Err(MemoryReadError::InvalidPadding {
                value: byte,
                position: len_bytes + offset,
            });
        }
    }

    out.truncate(len_bytes);
    Ok(out)
}

/// Converts bytes to field elements using u32 packing in little-endian format.
///
/// Each field element contains a u32 value representing up to 4 bytes. If the byte length
/// is not a multiple of 4, the final field element is zero-padded.
///
/// This is commonly used by precompile handlers (Keccak256, ECDSA) to convert byte data
/// into field element commitments.
///
/// # Arguments
/// - `bytes`: The byte slice to convert
///
/// # Returns
/// A vector of field elements, each containing 4 bytes packed in little-endian order.
///
/// # Examples
/// ```ignore
/// let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];
/// let felts = bytes_to_felts(&bytes);
/// // Returns: [Felt(0x04030201), Felt(0x00000005)]
/// ```
pub fn bytes_to_packed_u32_felts(bytes: &[u8]) -> Vec<Felt> {
    bytes
        .chunks(BYTES_PER_U32)
        .map(|chunk| {
            // Pack up to 4 bytes into a u32 in little-endian format
            let mut packed = [0u8; BYTES_PER_U32];
            packed[..chunk.len()].copy_from_slice(chunk);
            Felt::from(u32::from_le_bytes(packed))
        })
        .collect()
}

// ERROR TYPES
// ================================================================================================

/// Error types that can occur during memory reading operations.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MemoryReadError {
    /// Address overflow during conversion or arithmetic.
    #[error("address overflow: start={start}, len_bytes={len_bytes}")]
    AddressOverflow { start: u64, len_bytes: usize },

    /// Address is not word-aligned (not divisible by 4).
    #[error("address {address} is not word-aligned (must be divisible by 4)")]
    UnalignedAddress { address: u64 },

    /// Failed to read from memory at the specified address.
    #[error("failed to read memory at address {address}")]
    MemoryAccessFailed { address: u32 },

    /// Field element value exceeds u32::MAX.
    #[error("field element value {value} at address {address} exceeds u32::MAX")]
    InvalidValue { value: u64, address: u32 },

    /// Non-zero padding byte found in unused portion.
    #[error("non-zero padding byte {value:#x} at byte position {position}")]
    InvalidPadding { value: u8, position: usize },
}
