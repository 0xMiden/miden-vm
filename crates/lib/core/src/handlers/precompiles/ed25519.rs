//! Advice for the proof-bound compressed Ed25519 point loader.

use alloc::{vec, vec::Vec};

use miden_core::{Felt, events::EventName};
use miden_precompiles::ed25519_decompress_x;
use miden_processor::{
    ProcessorState,
    advice::{AdviceMutation, AdviceStack},
    event::EventError,
};

use super::packed_memory::read_memory_packed_u32;

/// Requests the Edwards x-coordinate of the compressed point at the given memory address.
pub const ED25519_DECOMPRESS_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::dsa::eddsa_25519_sha512::decompress");

/// Supplies a coordinate witness. The MASM loader proves parity, canonicality, and curve
/// membership.
///
/// Advice is arranged for `repeat.8 adv_push end` to leave x's eight u32 limbs on the operand
/// stack in little-endian order, with the least-significant limb on top.
pub fn handle_ed25519_decompress(
    process: &ProcessorState<'_>,
) -> Result<Vec<AdviceMutation>, EventError> {
    let ptr = process.get_stack_item(1).as_canonical_u64();
    let encoded = read_memory_packed_u32(process, ptr, 32)?;
    let x = ed25519_decompress_x(encoded.try_into().expect("exactly 32 point bytes"))?;
    let mut advice = AdviceStack::new();
    advice.append_for_adv_push(&x.map(Felt::from_u32));
    Ok(vec![AdviceMutation::extend_advice_stack(advice)])
}
