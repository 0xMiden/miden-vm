//! U64_DIV system event handler for the Miden VM.
//!
//! This handler implements the U64_DIV operation that pushes the result of [u64] division
//! (both the quotient and the remainder) onto the advice stack.

use alloc::{vec, vec::Vec};

use miden_core::{EventName, field::PrimeField64};
use miden_processor::{AdviceMutation, EventError, ProcessState};

use crate::handlers::u64_to_u32_elements;

/// Event name for the u64_div operation.
pub const U64_DIV_EVENT_NAME: EventName = EventName::new("miden::core::math::u64::u64_div");

/// U64_DIV system event handler.
///
/// Pushes the result of [u64] division (both the quotient and the remainder) onto the advice
/// stack.
///
/// Inputs:
///   Operand stack: [event_id, b_lo, b_hi, a_lo, a_hi, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [q_lo, q_hi, r_lo, r_hi, ...]
///
/// Where (a_lo, a_hi) and (b_lo, b_hi) are the 32-bit limbs of the dividend and the divisor
/// respectively (with lo representing the 32 least significant bits and hi representing the
/// 32 most significant bits). Similarly, (q_lo, q_hi) and (r_lo, r_hi) represent the quotient
/// and the remainder respectively.
///
/// # Errors
/// Returns an error if the divisor is ZERO.
pub fn handle_u64_div(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    // Read divisor from positions 1 (lo) and 2 (hi) - b is on top of stack
    let divisor = {
        let divisor_lo = process.get_stack_item(1).as_canonical_u64();
        let divisor_hi = process.get_stack_item(2).as_canonical_u64();

        // Ensure the divisor is a pair of u32 values
        if divisor_lo > u32::MAX.into() {
            return Err(U64DivError::NotU32Value {
                value: divisor_lo,
                position: "divisor_lo",
            }
            .into());
        }
        if divisor_hi > u32::MAX.into() {
            return Err(U64DivError::NotU32Value {
                value: divisor_hi,
                position: "divisor_hi",
            }
            .into());
        }

        let divisor = (divisor_hi << 32) + divisor_lo;

        if divisor == 0 {
            return Err(U64DivError::DivideByZero.into());
        }

        divisor
    };

    // Read dividend from positions 3 (lo) and 4 (hi) - a is below b
    let dividend = {
        let dividend_lo = process.get_stack_item(3).as_canonical_u64();
        let dividend_hi = process.get_stack_item(4).as_canonical_u64();

        // Ensure the dividend is a pair of u32 values
        if dividend_lo > u32::MAX.into() {
            return Err(U64DivError::NotU32Value {
                value: dividend_lo,
                position: "dividend_lo",
            }
            .into());
        }
        if dividend_hi > u32::MAX.into() {
            return Err(U64DivError::NotU32Value {
                value: dividend_hi,
                position: "dividend_hi",
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
    // extend_stack([a,b,c,d]) puts 'a' on top due to reverse iteration + push_front
    // So [q_hi, q_lo, r_hi, r_lo] puts q_hi on top
    // After adv_push.2: pops q_hi then q_lo → operand stack [q_lo, q_hi, ...] (LE)
    // After adv_push.2: pops r_hi then r_lo → operand stack [r_lo, r_hi, ...] (LE)
    let mutation = AdviceMutation::extend_stack([q_hi, q_lo, r_hi, r_lo]);
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
