// RE-EXPORTS
// ================================================================================================
pub use miden_core::utils::*;
use miden_core::{Felt, PrimeCharacteristicRing};

// HELPER FUNCTIONS
// ================================================================================================

/// Splits an element into two field elements containing 32-bit integer values
#[inline(always)]
pub(crate) fn split_element(value: Felt) -> (Felt, Felt) {
    let value = value.as_int();
    let lo = (value as u32) as u64;
    let hi = value >> 32;
    (Felt::from_u64(hi), Felt::from_u64(lo))
}

/// Splits an element into two 16 bit integer limbs. It assumes that the field element contains a
/// valid 32-bit integer value.
pub(crate) fn split_element_u32_into_u16(value: Felt) -> (Felt, Felt) {
    let (hi, lo) = split_u32_into_u16(value.as_int());
    (Felt::from_u64(hi as u64), Felt::from_u64(lo as u64))
}

/// Splits a u64 integer assumed to contain a 32-bit value into two u16 integers.
///
/// # Errors
/// Fails in debug mode if the provided value is not a 32-bit value.
pub(crate) fn split_u32_into_u16(value: u64) -> (u16, u16) {
    const U32MAX: u64 = u32::MAX as u64;
    debug_assert!(value <= U32MAX, "not a 32-bit value");

    let lo = value as u16;
    let hi = (value >> 16) as u16;

    (hi, lo)
}
