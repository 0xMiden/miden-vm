//! Advice for the proof-bound compressed Ed25519 point loader.

use miden_core::{Felt, events::EventName};
use miden_event_handler::{AdviceRecorder, EventContext, EventError, InvocationKind};
use miden_precompiles::ed25519_decompress_x;

use super::packed_memory::read_memory_packed_u32;

const COMPRESSED_POINT_BYTES: usize = 32;

/// Requests the Edwards x-coordinate of the compressed point at the given memory address.
pub const ED25519_DECOMPRESS_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::dsa::eddsa_25519_sha512::decompress");

/// Supplies a coordinate witness. The MASM loader proves parity, canonicality, and curve
/// membership.
///
/// Advice is arranged for `repeat.8 adv_push end` to leave x's eight u32 limbs on the operand
/// stack in little-endian order, with the least-significant limb on top.
pub fn handle_ed25519_decompress(
    context: EventContext<'_>,
    advice: &mut AdviceRecorder<'_>,
) -> Result<(), EventError> {
    context.kind().require(InvocationKind::Event)?;
    let ptr = context.stack_item(0).as_canonical_u64();
    let encoded = read_memory_packed_u32(context, ptr, COMPRESSED_POINT_BYTES)?;
    let x = ed25519_decompress_x(encoded.try_into().expect("exactly 32 point bytes"))?;
    advice.prepend_stack(x.map(Felt::from_u32).into_iter().rev());
    Ok(())
}
