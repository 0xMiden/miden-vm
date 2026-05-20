//! secp256k1 base- and scalar-field specialisations of the SZ-based u256 modmul. The
//! polynomial identity, divmod, carry recurrence, and Fiat-Shamir derivation all live in
//! [`crate::handlers::u256_modmul`]; this file just provides the per-curve event names and
//! routes to the shared handler with the appropriate prime.

use alloc::vec::Vec;

use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventName},
};

use crate::handlers::{
    secp256k1_constants::{
        SECP256K1_BASE_PRIME_U16, SECP256K1_BASE_PRIME_U32, SECP256K1_SCALAR_PRIME_U16,
        SECP256K1_SCALAR_PRIME_U32,
    },
    u256_modmul,
};

pub const U256_MODMUL_K1_BASE_EVENT_NAME: EventName =
    EventName::new("miden::core::math::u256::u256_modmul_k1_base");

pub const U256_MODMUL_K1_SCALAR_EVENT_NAME: EventName =
    EventName::new("miden::core::math::u256::u256_modmul_k1_scalar");

pub fn handle_u256_modmul_k1_base(
    process: &ProcessorState,
) -> Result<Vec<AdviceMutation>, EventError> {
    u256_modmul::handle_modmul(process, &SECP256K1_BASE_PRIME_U16, &SECP256K1_BASE_PRIME_U32)
}

pub fn handle_u256_modmul_k1_scalar(
    process: &ProcessorState,
) -> Result<Vec<AdviceMutation>, EventError> {
    u256_modmul::handle_modmul(process, &SECP256K1_SCALAR_PRIME_U16, &SECP256K1_SCALAR_PRIME_U32)
}
