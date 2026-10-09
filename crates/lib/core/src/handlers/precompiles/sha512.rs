//! Host advice for the precompile-backed SHA-512 memory wrapper.

use alloc::{vec, vec::Vec};

use miden_core::{events::EventName, utils::bytes_to_packed_u32_elements};
use miden_crypto::hash::sha2::Sha512;
use miden_processor::{
    ProcessorState,
    advice::{AdviceMutation, AdviceStack},
    event::EventError,
};

use super::packed_memory::read_memory_packed_u32;

/// Requests a SHA-512 digest witness for packed-u32 message memory.
pub const SHA512_DIGEST_EVENT_NAME: EventName =
    EventName::new("miden::precompiles::hashes::sha512::digest");

/// Supplies all sixteen digest limbs. The MASM wrapper binds them with a deferred assertion.
pub fn handle_sha512_digest(
    process: &ProcessorState<'_>,
) -> Result<Vec<AdviceMutation>, EventError> {
    let ptr = process.get_stack_item(1).as_canonical_u64();
    let len_bytes = process.get_stack_item(2).as_canonical_u64();
    let max = process.execution_options().max_hash_len_bytes();
    if len_bytes > max as u64 {
        return Err(Sha512DigestEventError::InputTooLong { len_bytes, max }.into());
    }
    let len_bytes = usize::try_from(len_bytes)
        .map_err(|_| Sha512DigestEventError::InputLengthTooLarge { len_bytes })?;
    let input = read_memory_packed_u32(process, ptr, len_bytes)?;
    let digest = Sha512::hash(&input);
    let mut advice = AdviceStack::new();
    advice.append_for_adv_pipe(&bytes_to_packed_u32_elements(&digest));
    Ok(vec![AdviceMutation::extend_advice_stack(advice)])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum Sha512DigestEventError {
    #[error("sha512 input length {len_bytes} bytes exceeds maximum of {max} bytes")]
    InputTooLong { len_bytes: u64, max: usize },
    #[error("sha512 input length {len_bytes} exceeds addressable range")]
    InputLengthTooLarge { len_bytes: u64 },
}
