//! U64_DIV system event handler for the Miden VM.
//!
//! This handler implements the U64_DIV operation that pushes the result of [u64] division
//! (both the quotient and the remainder) onto the advice stack.

use alloc::{vec, vec::Vec};

use miden_core::EventName;
use miden_processor::{AdviceMutation, EventError, ProcessState};

use crate::handlers::u64_to_u32_elements;

/// Event name for the u64_div operation.
pub const U64_DIV_EVENT_NAME: EventName = EventName::new("stdlib::math::u64::u64_div");

/// U64_DIV system event handler.
///
/// Pushes the result of [u64] division (both the quotient and the remainder) onto the advice
/// stack.
///
/// Inputs:
///   Operand stack: [event_id, b1, b0, a1, a0, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [q0, q1, r0, r1, ...]
///
/// Where (a0, a1) and (b0, b1) are the 32-bit limbs of the dividend and the divisor
/// respectively (with a0 representing the 32 lest significant bits and a1 representing the
/// 32 most significant bits). Similarly, (q0, q1) and (r0, r1) represent the quotient and
/// the remainder respectively.
///
/// # Errors
/// Returns an error if the divisor is ZERO.
pub fn handle_u64_div(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    let divisor = {
        let divisor_hi = process.get_stack_item(1).as_int();
        let divisor_lo = process.get_stack_item(2).as_int();

        // Ensure the divisor is a pair of u32 values
        if divisor_hi > u32::MAX.into() {
            return Err(U64DivError::NotU32Value {
                value: divisor_hi,
                position: "divisor_hi",
            }
            .into());
        }
        if divisor_lo > u32::MAX.into() {
            return Err(U64DivError::NotU32Value {
                value: divisor_lo,
                position: "divisor_lo",
            }
            .into());
        }

        let divisor = (divisor_hi << 32) + divisor_lo;

        if divisor == 0 {
            return Err(U64DivError::DivideByZero.into());
        }

        divisor
    };

    let dividend = {
        let dividend_hi = process.get_stack_item(3).as_int();
        let dividend_lo = process.get_stack_item(4).as_int();

        // Ensure the dividend is a pair of u32 values
        if dividend_hi > u32::MAX.into() {
            return Err(U64DivError::NotU32Value {
                value: dividend_hi,
                position: "dividend_hi",
            }
            .into());
        }
        if dividend_lo > u32::MAX.into() {
            return Err(U64DivError::NotU32Value {
                value: dividend_lo,
                position: "dividend_lo",
            }
            .into());
        }

        (dividend_hi << 32) + dividend_lo
    };

    let quotient = dividend / divisor;
    let remainder = dividend - quotient * divisor;

    let (q_hi, q_lo) = u64_to_u32_elements(quotient);
    let (r_hi, r_lo) = u64_to_u32_elements(remainder);

    // Create mutations to extend the advice stack with the result.
    // The values are pushed in reverse order to match the processor's behavior:
    // r_hi, r_lo, q_hi, q_lo
    let mutation = AdviceMutation::extend_stack([r_hi, r_lo, q_hi, q_lo]);
    Ok(vec![mutation])
}

// ERROR TYPES
// ================================================================================================

/// Error types that can occur during U64_DIV operations.
#[derive(Debug, thiserror::Error)]
pub enum U64DivError {
    /// Division by zero error.
    #[error("division by zero")]
    DivideByZero,

    /// Value is not a valid u32.
    #[error("value {value} at {position} is not a valid u32")]
    NotU32Value { value: u64, position: &'static str },
}
