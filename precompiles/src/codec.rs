//! Shared chunk ↔ byte codec for the core precompiles. Each precompile's `evaluate` consumes its
//! chunk body as a flat byte buffer; the framework guarantees the chunk count via `decode`,
//! and this codec strips the trailing zero pad back down to the declared `n_bytes` after
//! validating that the discarded pad bytes are zero.

use alloc::vec::Vec;
use core::num::NonZeroU32;

use miden_core::{Felt, deferred::PrecompileError};

/// Bytes packed per 8-felt chunk: each felt carries a u32 (4 bytes) little-endian limb.
pub const BYTES_PER_CHUNK: u32 = 32;

/// Number of 8-felt chunks needed to encode `n_bytes` of u32-packed input.
///
/// Empty input still needs one chunk: the framework bans empty chunk bodies
/// ([`NodeType::Chunks`](miden_core::deferred::NodeType) holds a [`NonZeroU32`]), so a 0-byte hash
/// preimage is encoded as a single zero chunk. The count is therefore clamped to at least 1.
pub fn n_chunks(n_bytes: u32) -> NonZeroU32 {
    NonZeroU32::new(n_bytes.div_ceil(BYTES_PER_CHUNK).max(1)).expect("clamped to at least 1")
}

/// Unpack a slice of u32-packed-LE chunks back to a `n_bytes`-length byte vector, returning
/// `PrecompileError::InvalidNode` if any felt holds a value larger than `u32::MAX`.
///
/// The caller-supplied `n_bytes` may be shorter than `chunks.len() * BYTES_PER_CHUNK as usize`;
/// the trailing bytes are zero-pad and are stripped from the output after validating they are
/// zero.
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
    if bytes[n_bytes..].iter().any(|&b| b != 0) {
        return Err(PrecompileError::InvalidNode);
    }
    bytes.truncate(n_bytes);
    Ok(bytes)
}
