//! Host event handler for precompile-backed Keccak-256 wrapper advice.

use alloc::vec::Vec;
use core::mem::size_of;

use miden_core::{
    WORD_SIZE,
    events::EventName,
    utils::{bytes_to_packed_u32_elements, packed_u32_elements_to_bytes},
};
use miden_crypto::hash::keccak::Keccak256;
use miden_event_handler::{
    AdviceRecorder, EventContext, EventError, InvocationKind, MAX_KECCAK_INPUT_BYTES,
};

/// Event emitted by bundled `miden::precompiles::hashes::keccak256` wrappers to request a
/// Keccak-256 digest witness from the host.
pub const KECCAK256_DIGEST_EVENT_NAME: EventName =
    EventName::new("miden::precompiles::hashes::keccak256::digest");

const BYTES_PER_U32: usize = size_of::<u32>();
const KECCAK256_DIGEST_FELTS: usize = 8;

/// Reads the requested u32-packed memory preimage, computes Keccak-256, and pushes the digest limbs
/// onto the advice stack for the MASM wrapper to bind with deferred assertions.
/// Inputs larger than [`MAX_KECCAK_INPUT_BYTES`] are rejected before reading memory or allocating.
pub fn handle_keccak256_digest(
    context: EventContext<'_>,
    advice: &mut AdviceRecorder<'_>,
) -> Result<(), EventError> {
    context.kind().require(InvocationKind::Event)?;
    let ptr = context.stack_item(0).as_canonical_u64();
    let len_bytes = context.stack_item(1).as_canonical_u64();

    let max = MAX_KECCAK_INPUT_BYTES;
    if len_bytes > max as u64 {
        return Err(Keccak256DigestEventError::InputTooLong { len_bytes, max }.into());
    }
    let len_bytes = len_bytes as usize;

    let input = read_memory_packed_u32(context, ptr, len_bytes)?;
    let digest = <[u8; 32]>::from(Keccak256::hash(&input));
    let digest_felts = bytes_to_packed_u32_elements(&digest);
    if digest_felts.len() != KECCAK256_DIGEST_FELTS {
        return Err(Keccak256DigestEventError::InvalidDigestLength {
            len_bytes: digest.len(),
            expected_bytes: KECCAK256_DIGEST_FELTS * BYTES_PER_U32,
        }
        .into());
    }

    // Preserve the VM's sequential word/block consumption order.
    advice.prepend_stack(digest_felts);
    Ok(())
}

fn read_memory_packed_u32(
    context: EventContext<'_>,
    start: u64,
    len_bytes: usize,
) -> Result<Vec<u8>, Keccak256DigestEventError> {
    if !start.is_multiple_of(WORD_SIZE as u64) {
        return Err(Keccak256DigestEventError::UnalignedAddress { address: start });
    }

    let len_felts = len_bytes.div_ceil(BYTES_PER_U32);
    let len_felts_u64 = u64::try_from(len_felts)
        .map_err(|_| Keccak256DigestEventError::AddressOverflow { start, len_bytes })?;
    let end = start
        .checked_add(len_felts_u64)
        .ok_or(Keccak256DigestEventError::AddressOverflow { start, len_bytes })?;
    let start_u32 = u32::try_from(start)
        .map_err(|_| Keccak256DigestEventError::AddressOverflow { start, len_bytes })?;
    u32::try_from(end)
        .map_err(|_| Keccak256DigestEventError::AddressOverflow { start, len_bytes })?;
    let len_padded = len_bytes
        .checked_next_multiple_of(BYTES_PER_U32)
        .ok_or(Keccak256DigestEventError::AddressOverflow { start, len_bytes })?;

    let felts = context
        .memory_slice(start, len_felts_u64)
        .map_err(|_| Keccak256DigestEventError::MemoryAccessFailed { address: start_u32 })?;

    for (offset, felt) in felts.iter().enumerate() {
        let value = felt.as_canonical_u64();
        let address = start_u32 + offset as u32;
        u32::try_from(value)
            .map_err(|_| Keccak256DigestEventError::InvalidValue { value, address })?;
    }

    let mut out = packed_u32_elements_to_bytes(&felts);
    debug_assert_eq!(out.len(), len_padded);
    for (offset, &byte) in out[len_bytes..].iter().enumerate() {
        if byte != 0 {
            return Err(Keccak256DigestEventError::InvalidPadding {
                value: byte,
                position: len_bytes + offset,
            });
        }
    }

    out.truncate(len_bytes);
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum Keccak256DigestEventError {
    #[error("keccak256 input length {len_bytes} bytes exceeds maximum of {max} bytes")]
    InputTooLong { len_bytes: u64, max: usize },
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
    #[error(
        "keccak256 digest length {len_bytes} bytes did not match expected {expected_bytes} bytes"
    )]
    InvalidDigestLength { len_bytes: usize, expected_bytes: usize },
}
