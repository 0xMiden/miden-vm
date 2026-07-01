//! Host event handlers for hash wrapper advice.

use alloc::{sync::Arc, vec, vec::Vec};
use core::{error::Error, fmt, marker::PhantomData, mem::size_of};

use miden_core::{WORD_SIZE, events::EventName, utils::bytes_to_packed_u32_elements};
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler},
};

use super::{HashFunction, keccak256::Keccak256Hash};

pub(crate) const KECCAK256_DIGEST_EVENT_NAME: EventName =
    EventName::new("miden::precompiles::crypto::hashes::keccak256::digest");

const BYTES_PER_U32: usize = size_of::<u32>();

pub(crate) fn keccak256_digest_event_handler() -> (EventName, Arc<dyn EventHandler>) {
    (
        KECCAK256_DIGEST_EVENT_NAME,
        Arc::new(HashDigestHandler::<Keccak256Hash>::default()),
    )
}

struct HashDigestHandler<H>(PhantomData<H>);

impl<H> Default for HashDigestHandler<H> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<H: HashFunction> EventHandler for HashDigestHandler<H> {
    fn on_event(&self, process: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        let ptr = process.get_stack_item(1).as_canonical_u64();
        let len_bytes = process.get_stack_item(2).as_canonical_u64();

        let max = process.execution_options().max_hash_len_bytes();
        if len_bytes > max as u64 {
            return Err(HashDigestEventError::InputTooLong { hash: H::NAME, len_bytes, max }.into());
        }
        let len_bytes = usize::try_from(len_bytes)
            .map_err(|_| HashDigestEventError::InputLengthTooLarge { hash: H::NAME, len_bytes })?;

        let input = read_memory_packed_u32(process, ptr, len_bytes)?;
        let digest = H::hash(&input);
        let digest_felts = bytes_to_packed_u32_elements(&digest);
        if digest_felts.len() != H::DIGEST_FELTS {
            return Err(HashDigestEventError::InvalidDigestLength {
                hash: H::NAME,
                len_bytes: digest.len(),
                expected_bytes: H::DIGEST_FELTS * BYTES_PER_U32,
            }
            .into());
        }

        Ok(vec![AdviceMutation::extend_stack(digest_felts)])
    }
}

fn read_memory_packed_u32(
    process: &ProcessorState<'_>,
    start: u64,
    len_bytes: usize,
) -> Result<Vec<u8>, HashDigestEventError> {
    if !start.is_multiple_of(WORD_SIZE as u64) {
        return Err(HashDigestEventError::UnalignedAddress { address: start });
    }

    let len_felts = len_bytes.div_ceil(BYTES_PER_U32);
    let end = start
        .checked_add(len_felts as u64)
        .ok_or(HashDigestEventError::AddressOverflow { start, len_bytes })?;
    let start_u32 = u32::try_from(start)
        .map_err(|_| HashDigestEventError::AddressOverflow { start, len_bytes })?;
    let end_u32 = u32::try_from(end)
        .map_err(|_| HashDigestEventError::AddressOverflow { start, len_bytes })?;
    let len_padded = len_bytes
        .checked_next_multiple_of(BYTES_PER_U32)
        .ok_or(HashDigestEventError::AddressOverflow { start, len_bytes })?;

    let ctx = process.ctx();
    let mut out = Vec::with_capacity(len_padded);
    for address in start_u32..end_u32 {
        let felt = process
            .get_mem_value(ctx, address)
            .ok_or(HashDigestEventError::MemoryAccessFailed { address })?;
        let value = felt.as_canonical_u64();
        let packed = u32::try_from(value)
            .map_err(|_| HashDigestEventError::InvalidValue { value, address })?;
        out.extend_from_slice(&packed.to_le_bytes());
    }

    for (offset, &byte) in out[len_bytes..].iter().enumerate() {
        if byte != 0 {
            return Err(HashDigestEventError::InvalidPadding {
                value: byte,
                position: len_bytes + offset,
            });
        }
    }

    out.truncate(len_bytes);
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashDigestEventError {
    InputTooLong {
        hash: &'static str,
        len_bytes: u64,
        max: usize,
    },
    InputLengthTooLarge {
        hash: &'static str,
        len_bytes: u64,
    },
    AddressOverflow {
        start: u64,
        len_bytes: usize,
    },
    UnalignedAddress {
        address: u64,
    },
    MemoryAccessFailed {
        address: u32,
    },
    InvalidValue {
        value: u64,
        address: u32,
    },
    InvalidPadding {
        value: u8,
        position: usize,
    },
    InvalidDigestLength {
        hash: &'static str,
        len_bytes: usize,
        expected_bytes: usize,
    },
}

impl fmt::Display for HashDigestEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { hash, len_bytes, max } => {
                write!(f, "{hash} input length {len_bytes} bytes exceeds maximum of {max} bytes")
            },
            Self::InputLengthTooLarge { hash, len_bytes } => {
                write!(f, "{hash} input length {len_bytes} exceeds addressable range")
            },
            Self::AddressOverflow { start, len_bytes } => write!(
                f,
                "address overflow while reading u32-packed memory: start={start}, len_bytes={len_bytes}"
            ),
            Self::UnalignedAddress { address } => {
                write!(
                    f,
                    "address {address} is not word-aligned (must be divisible by {WORD_SIZE})"
                )
            },
            Self::MemoryAccessFailed { address } => {
                write!(f, "failed to read memory at address {address}")
            },
            Self::InvalidValue { value, address } => {
                write!(f, "field element value {value} at address {address} exceeds u32::MAX")
            },
            Self::InvalidPadding { value, position } => {
                write!(f, "non-zero padding byte {value:#x} at byte position {position}")
            },
            Self::InvalidDigestLength { hash, len_bytes, expected_bytes } => write!(
                f,
                "{hash} digest length {len_bytes} bytes did not match expected {expected_bytes} bytes"
            ),
        }
    }
}

impl Error for HashDigestEventError {}
