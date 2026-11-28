//! Shared decoding of the packed-u32 message ABI used by hash precompiles.

use alloc::vec::Vec;
use core::mem::size_of;

use miden_core::{WORD_SIZE, utils::packed_u32_elements_to_bytes};
use miden_processor::ProcessorState;

use crate::handlers::read_uninitialized_memory_region;

const BYTES_PER_U32: usize = size_of::<u32>();

pub(super) fn read_memory_packed_u32(
    process: &ProcessorState<'_>,
    start: u64,
    len_bytes: usize,
) -> Result<Vec<u8>, PackedMemoryError> {
    if !start.is_multiple_of(WORD_SIZE as u64) {
        return Err(PackedMemoryError::UnalignedAddress { address: start });
    }

    let len_felts = len_bytes.div_ceil(BYTES_PER_U32);
    let len_felts_u64 = u64::try_from(len_felts)
        .map_err(|_| PackedMemoryError::AddressOverflow { start, len_bytes })?;
    let end = start
        .checked_add(len_felts_u64)
        .ok_or(PackedMemoryError::AddressOverflow { start, len_bytes })?;
    let start_u32 = u32::try_from(start)
        .map_err(|_| PackedMemoryError::AddressOverflow { start, len_bytes })?;
    u32::try_from(end).map_err(|_| PackedMemoryError::AddressOverflow { start, len_bytes })?;
    let len_padded = len_bytes
        .checked_next_multiple_of(BYTES_PER_U32)
        .ok_or(PackedMemoryError::AddressOverflow { start, len_bytes })?;

    let felts = read_uninitialized_memory_region(process, start, len_felts_u64)
        .ok_or(PackedMemoryError::MemoryAccessFailed { address: start_u32 })?;

    for (offset, felt) in felts.iter().enumerate() {
        let value = felt.as_canonical_u64();
        let address = start_u32 + offset as u32;
        u32::try_from(value).map_err(|_| PackedMemoryError::InvalidValue { value, address })?;
    }

    let mut out = packed_u32_elements_to_bytes(&felts);
    debug_assert_eq!(out.len(), len_padded);
    for (offset, &byte) in out[len_bytes..].iter().enumerate() {
        if byte != 0 {
            return Err(PackedMemoryError::InvalidPadding {
                value: byte,
                position: len_bytes + offset,
            });
        }
    }

    out.truncate(len_bytes);
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum PackedMemoryError {
    #[error(
        "address overflow while reading u32-packed memory: start={start}, len_bytes={len_bytes}"
    )]
    AddressOverflow { start: u64, len_bytes: usize },
    #[error("address {address} is not word-aligned (must be divisible by {})", WORD_SIZE)]
    UnalignedAddress { address: u64 },
    #[error("failed to read memory at address {address}")]
    MemoryAccessFailed { address: u32 },
    #[error("field element value {value} at address {address} exceeds u32::MAX")]
    InvalidValue { value: u64, address: u32 },
    #[error("non-zero padding byte {value:#x} at byte position {position}")]
    InvalidPadding { value: u8, position: usize },
}
