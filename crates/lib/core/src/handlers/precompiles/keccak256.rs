//! Host event handler for precompile-backed Keccak-256 wrapper advice.

use core::mem::size_of;

use miden_core::{events::EventName, utils::bytes_to_packed_u32_elements};
use miden_crypto::hash::keccak::Keccak256;
use miden_event_handler::{
    AdviceRecorder, EventContext, EventError, InvocationKind, MAX_KECCAK_INPUT_BYTES,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum Keccak256DigestEventError {
    #[error("keccak256 input length {len_bytes} bytes exceeds maximum of {max} bytes")]
    InputTooLong { len_bytes: u64, max: usize },
    #[error(
        "keccak256 digest length {len_bytes} bytes did not match expected {expected_bytes} bytes"
    )]
    InvalidDigestLength { len_bytes: usize, expected_bytes: usize },
}
