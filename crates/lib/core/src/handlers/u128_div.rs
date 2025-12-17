//! U128_DIV system event handler for the Miden VM.
//!
//! This handler implements the U128_DIV operation that pushes the result of [u128] division
//! (both the quotient and the remainder) onto the advice stack.

use alloc::{vec, vec::Vec};

use miden_core::EventName;
use miden_processor::{AdviceMutation, EventError, ProcessState};

use crate::handlers::u128_to_u32_elements;

/// Event name for the u128_div operation.
pub const U128_DIV_EVENT_NAME: EventName = EventName::new("miden::core::math::u128::u128_div");

/// U128_DIV system event handler.
///
/// Pushes the result of [u128] division (both the quotient and the remainder) onto the advice
/// stack.
///
/// Inputs:
///   Operand stack: [event_id, b3, b2, b1, b0, a3, a2, a1, a0, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [q0, q1, q2, q3, r0, r1, r2, r3...]
///
/// Where (a0, a1, a2, a3) and (b0, b1, b2, b3) are the 32-bit limbs of the dividend and the
/// divisor respectively (with a0 representing the 32 least significant bits and a3 representing
/// the 32 most significant bits). Similarly, (q0, q1, q2, q3) and (r0, r1, r2, r3) represent the
/// quotient and the remainder respectively.
///
/// # Errors
/// Returns an error if the divisor is ZERO.
pub fn handle_u128_div(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    let ensure_u32 = |item, item_str| {
        if item > u32::MAX.into() {
            Err(U128DivError::NotU32Value { value: item, position: item_str })
        } else {
            Ok(())
        }
    };

    let divisor = {
        let divisor_hh = process.get_stack_item(1).as_int();
        let divisor_hm = process.get_stack_item(2).as_int();
        let divisor_lm = process.get_stack_item(3).as_int();
        let divisor_ll = process.get_stack_item(4).as_int();

        // Ensure the divisor is a set of u32 values.
        ensure_u32(divisor_hh, "divisor_hh")?;
        ensure_u32(divisor_hm, "divisor_hm")?;
        ensure_u32(divisor_lm, "divisor_lm")?;
        ensure_u32(divisor_ll, "divisor_ll")?;

        let divisor = ((divisor_hh as u128) << 96)
            | ((divisor_hm as u128) << 64)
            | ((divisor_lm as u128) << 32)
            | divisor_ll as u128;

        if divisor == 0 {
            return Err(U128DivError::DivideByZero.into());
        }

        divisor
    };

    let dividend = {
        let dividend_hh = process.get_stack_item(5).as_int();
        let dividend_hm = process.get_stack_item(6).as_int();
        let dividend_lm = process.get_stack_item(7).as_int();
        let dividend_ll = process.get_stack_item(8).as_int();

        // Ensure the dividend is a set of u32 values.
        ensure_u32(dividend_hh, "dividend_hh")?;
        ensure_u32(dividend_hm, "dividend_hm")?;
        ensure_u32(dividend_lm, "dividend_lm")?;
        ensure_u32(dividend_ll, "dividend_ll")?;

        ((dividend_hh as u128) << 96)
            | ((dividend_hm as u128) << 64)
            | ((dividend_lm as u128) << 32)
            | dividend_ll as u128
    };

    let quotient = dividend / divisor;
    let remainder = dividend - quotient * divisor;

    let (q_hh, q_hm, q_lm, q_ll) = u128_to_u32_elements(quotient);
    let (r_hh, r_hm, r_lm, r_ll) = u128_to_u32_elements(remainder);

    // Create mutations to extend the advice stack with the result.
    // The values are pushed in reverse order to match the processor's behavior:
    // r_hi, r_lo, q_hi, q_lo
    let mutation = AdviceMutation::extend_stack([r_hh, r_hm, r_lm, r_ll, q_hh, q_hm, q_lm, q_ll]);
    Ok(vec![mutation])
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
    #[error("value {value} at {position} is not a valid u32")]
    NotU32Value { value: u64, position: &'static str },
}
