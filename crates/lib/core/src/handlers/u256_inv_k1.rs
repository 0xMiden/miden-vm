//! secp256k1 base- and scalar-field specialisations of the u256 hint-and-verify modular
//! inverse. The witness math lives in [`crate::handlers::u256_inv`]; this file just provides
//! the per-curve event names and routes to the shared handler with the appropriate prime.

use alloc::vec::Vec;

use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventName},
};

use crate::handlers::{
    secp256k1_constants::{SECP256K1_BASE_PRIME_U32, SECP256K1_SCALAR_PRIME_U32},
    u256_inv,
};

pub const U256_INV_K1_BASE_EVENT_NAME: EventName =
    EventName::new("miden::core::math::u256::u256_inv_k1_base");

pub const U256_INV_K1_SCALAR_EVENT_NAME: EventName =
    EventName::new("miden::core::math::u256::u256_inv_k1_scalar");

pub fn handle_u256_inv_k1_base(
    process: &ProcessorState,
) -> Result<Vec<AdviceMutation>, EventError> {
    u256_inv::handle_inv(process, &SECP256K1_BASE_PRIME_U32)
}

pub fn handle_u256_inv_k1_scalar(
    process: &ProcessorState,
) -> Result<Vec<AdviceMutation>, EventError> {
    u256_inv::handle_inv(process, &SECP256K1_SCALAR_PRIME_U32)
}
