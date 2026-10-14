//! Host advice for the precompile-backed SHA-512 memory wrapper.

use miden_core::{events::EventName, utils::bytes_to_packed_u32_elements};
use miden_crypto::hash::sha2::Sha512;
use miden_event_handler::{
    AdviceRecorder, EventContext, EventError, InvocationKind, MAX_SHA2_INPUT_BYTES,
};

use super::packed_memory::read_memory_packed_u32;

/// Requests a SHA-512 digest witness for packed-u32 message memory.
pub const SHA512_DIGEST_EVENT_NAME: EventName =
    EventName::new("miden::precompiles::hashes::sha512::digest");

/// Inputs larger than [`MAX_SHA2_INPUT_BYTES`] are rejected before reading memory or allocating.
/// Supplies all sixteen digest limbs. The MASM wrapper binds them with a deferred assertion.
pub fn handle_sha512_digest(
    context: EventContext<'_>,
    advice: &mut AdviceRecorder<'_>,
) -> Result<(), EventError> {
    context.kind().require(InvocationKind::Event)?;
    let ptr = context.stack_item(0).as_canonical_u64();
    let len_bytes = context.stack_item(1).as_canonical_u64();
    let max = MAX_SHA2_INPUT_BYTES;
    if len_bytes > max as u64 {
        return Err(Sha512DigestEventError::InputTooLong { len_bytes, max }.into());
    }
    let len_bytes = len_bytes as usize;
    let input = read_memory_packed_u32(context, ptr, len_bytes)?;
    let digest = Sha512::hash(&input);
    advice.prepend_stack(bytes_to_packed_u32_elements(&digest));
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum Sha512DigestEventError {
    #[error("sha512 input length {len_bytes} bytes exceeds maximum of {max} bytes")]
    InputTooLong { len_bytes: u64, max: usize },
}
