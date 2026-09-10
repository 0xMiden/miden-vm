use miden_core::Felt;

pub mod aead_decrypt;
use alloc::vec::Vec;

pub mod debug;
pub mod ecdsa_k256_keccak;
pub mod falcon_div;
pub mod precompiles;
pub mod readonly;
pub mod smt_peek;
pub mod sorted_array;
pub mod u128_div;
pub mod u256_div;
pub mod u64_div;

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a u64 value into two u32 elements (high and low parts).
fn u64_to_u32_elements(value: u64) -> (Felt, Felt) {
    let hi = Felt::from_u32((value >> 32) as u32);
    let lo = Felt::from_u32(value as u32);
    (hi, lo)
}

/// Preserves legacy library-list shapes while the authoritative handlers use the portable trait.
pub(super) fn legacy_handlers(
    handlers: Vec<(
        miden_core::events::EventName,
        miden_processor::event::registration::EventHandler,
    )>,
) -> Vec<(
    miden_core::events::EventName,
    alloc::sync::Arc<dyn miden_processor::event::EventHandler>,
)> {
    handlers
        .into_iter()
        .map(|(name, handler)| (name, miden_processor::event::legacy_handler(handler)))
        .collect()
}
