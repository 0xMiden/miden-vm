//! Shared chunk-to-byte codec for precompiles.

use alloc::vec::Vec;
use core::num::NonZeroU32;

use miden_core::{Felt, deferred::PrecompileError};

/// Bytes packed per 8-felt chunk. Each felt carries a little-endian u32 limb.
pub const BYTES_PER_CHUNK: u32 = 32;

/// Number of 8-felt chunks needed to encode `n_bytes` of u32-packed input.
///
/// Empty input still uses one chunk because deferred data payloads are non-empty.
pub fn n_chunks(n_bytes: u32) -> NonZeroU32 {
    NonZeroU32::new(n_bytes.div_ceil(BYTES_PER_CHUNK).max(1)).expect("clamped to at least 1")
}

/// Unpacks u32-packed chunks into `n_bytes` bytes, rejecting non-u32 felts and non-zero padding.
pub fn chunks_to_bytes(chunks: &[[Felt; 8]], n_bytes: usize) -> Result<Vec<u8>, PrecompileError> {
    let chunk_bytes = BYTES_PER_CHUNK as usize;
    if n_bytes > chunks.len() * chunk_bytes {
        return Err(PrecompileError::InvalidNode);
    }

    let mut bytes = Vec::with_capacity(chunks.len() * chunk_bytes);
    for chunk in chunks {
        for felt in chunk {
            let limb =
                u32::try_from(felt.as_canonical_u64()).map_err(|_| PrecompileError::InvalidNode)?;
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }

    if bytes[n_bytes..].iter().any(|&byte| byte != 0) {
        return Err(PrecompileError::InvalidNode);
    }
    bytes.truncate(n_bytes);
    Ok(bytes)
}
