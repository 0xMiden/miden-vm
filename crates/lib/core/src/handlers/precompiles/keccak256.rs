//! Host event handler for precompile-backed Keccak-256 wrapper advice.

use alloc::{vec, vec::Vec};
use core::mem::size_of;

use miden_core::{events::EventName, utils::bytes_to_packed_u32_elements};
use miden_crypto::hash::keccak::Keccak256;
use miden_processor::{
    ProcessorState,
    advice::{AdviceMutation, AdviceStack},
    event::EventError,
};

use super::packed_memory::read_memory_packed_u32;

/// Event emitted by bundled `miden::precompiles::hashes::keccak256` wrappers to request a
/// Keccak-256 digest witness from the host.
pub const KECCAK256_DIGEST_EVENT_NAME: EventName =
    EventName::new("miden::precompiles::hashes::keccak256::digest");

const BYTES_PER_U32: usize = size_of::<u32>();
const KECCAK256_DIGEST_FELTS: usize = 8;

/// Reads the requested u32-packed memory preimage, computes Keccak-256, and pushes the digest limbs
/// onto the advice stack for the MASM wrapper to bind with deferred assertions.
pub fn handle_keccak256_digest(
    process: &ProcessorState<'_>,
) -> Result<Vec<AdviceMutation>, EventError> {
    let ptr = process.get_stack_item(1).as_canonical_u64();
    let len_bytes = process.get_stack_item(2).as_canonical_u64();

    let max = process.execution_options().max_hash_len_bytes();
    if len_bytes > max as u64 {
        return Err(Keccak256DigestEventError::InputTooLong { len_bytes, max }.into());
    }
    let len_bytes = usize::try_from(len_bytes)
        .map_err(|_| Keccak256DigestEventError::InputLengthTooLarge { len_bytes })?;

    let input = read_memory_packed_u32(process, ptr, len_bytes)?;
    let digest = <[u8; 32]>::from(Keccak256::hash(&input));
    let digest_felts = bytes_to_packed_u32_elements(&digest);
    if digest_felts.len() != KECCAK256_DIGEST_FELTS {
        return Err(Keccak256DigestEventError::InvalidDigestLength {
            len_bytes: digest.len(),
            expected_bytes: KECCAK256_DIGEST_FELTS * BYTES_PER_U32,
        }
        .into());
    }

    let mut advice_stack = AdviceStack::new();
    // MASM consumes the digest with two `adv_pushw` calls, low word first and high word second.
    advice_stack.append_for_adv_pipe(&digest_felts);
    Ok(vec![AdviceMutation::extend_advice_stack(advice_stack)])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum Keccak256DigestEventError {
    #[error("keccak256 input length {len_bytes} bytes exceeds maximum of {max} bytes")]
    InputTooLong { len_bytes: u64, max: usize },
    #[error("keccak256 input length {len_bytes} exceeds addressable range")]
    InputLengthTooLarge { len_bytes: u64 },
    #[error(
        "keccak256 digest length {len_bytes} bytes did not match expected {expected_bytes} bytes"
    )]
    InvalidDigestLength { len_bytes: usize, expected_bytes: usize },
}
