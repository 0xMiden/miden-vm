//! U128_DIV system event handler for the Miden VM.
//!
//! This handler implements the U128_DIV operation that pushes the result of [u128] division
//! (both the quotient and the remainder) onto the advice stack.

use alloc::{vec, vec::Vec};

use miden_core::Felt;
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventName},
};

/// Event name for the u128_div operation.
pub const U128_DIV_EVENT_NAME: EventName = EventName::new("miden::core::math::u128::u128_div");

/// U128_DIV system event handler.
///
/// Pushes the result of [u128] division (both the quotient and the remainder) onto the advice
/// stack.
///
/// Inputs:
///   Operand stack: [event_id, b0, b1, b2, b3, a0, a1, a2, a3, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [r0, r1, r2, r3, q0, q1, q2, q3, ...]
///
/// Where (b0..b3) and (a0..a3) are the 32-bit limbs of the divisor and dividend respectively,
/// with b0/a0 being the least significant limb.
///
/// After two `padw adv_loadw` in MASM:
///   First:  loads [r0, r1, r2, r3] onto operand stack
///   Second: loads [q0, q1, q2, q3] onto operand stack
///
/// # Errors
/// Returns an error if the divisor is ZERO or any limb is not a valid u32.
pub fn handle_u128_div(process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
    let divisor = read_u128_from_stack(process, 1, "divisor")?;

    if divisor == 0 {
        return Err(U128DivError::DivideByZero.into());
    }

    let dividend = read_u128_from_stack(process, 5, "dividend")?;

    let quotient = dividend / divisor;
    let remainder = dividend - quotient * divisor;

    let (q0, q1, q2, q3) = u128_to_u32_felts(quotient);
    let (r0, r1, r2, r3) = u128_to_u32_felts(remainder);

    let mutation = AdviceMutation::extend_stack([r0, r1, r2, r3, q0, q1, q2, q3]);
    Ok(vec![mutation])
}

/// Reads a u128 value from 4 consecutive stack positions starting at `start`.
fn read_u128_from_stack(
    process: &ProcessorState,
    start: usize,
    name: &'static str,
) -> Result<u128, EventError> {
    let mut value: u128 = 0;
    for i in (0..4).rev() {
        let limb = process.get_stack_item(start + i).as_canonical_u64();
        if limb > u32::MAX as u64 {
            return Err(U128DivError::NotU32Value {
                value: limb,
                position: name,
                limb_index: i,
            }
            .into());
        }
        value = (value << 32) | limb as u128;
    }
    Ok(value)
}

/// Splits a u128 into 4 Felt values representing u32 limbs, least significant first.
fn u128_to_u32_felts(value: u128) -> (Felt, Felt, Felt, Felt) {
    let limb0 = Felt::from_u32(value as u32);
    let limb1 = Felt::from_u32((value >> 32) as u32);
    let limb2 = Felt::from_u32((value >> 64) as u32);
    let limb3 = Felt::from_u32((value >> 96) as u32);
    (limb0, limb1, limb2, limb3)
}

// ERROR TYPES
// ================================================================================================

/// Error types that can occur during U128_DIV operations.
#[derive(Debug, thiserror::Error)]
pub enum U128DivError {
    /// Division by zero error.
    #[error("division by zero")]
    DivideByZero,

    /// Value is not a valid u32.
    #[error("value {value} at {position} limb {limb_index} is not a valid u32")]
    NotU32Value {
        value: u64,
        position: &'static str,
        limb_index: usize,
    },
}
