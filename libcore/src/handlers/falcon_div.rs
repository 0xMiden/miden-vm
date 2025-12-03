//! FALCON_DIV system event handler for the Miden VM.
//!
//! This handler implements the FALCON_DIV operation that pushes the result of dividing
//! a [u64] by the Falcon prime (M = 12289) onto the advice stack.

use alloc::{vec, vec::Vec};

use miden_core::{EventName, ZERO};
use miden_processor::{AdviceMutation, EventError, ProcessState};

use crate::handlers::u64_to_u32_elements;

/// Falcon signature prime.
const M: u64 = 12289;

/// Event name for the falcon_div operation.
pub const FALCON_DIV_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::dsa::falcon512rpo::falcon_div");

/// FALCON_DIV system event handler.
///
/// Pushes the result of divison (both the quotient and the remainder) of a [u64] by the Falcon
/// prime (M = 12289) onto the advice stack.
///
/// Inputs:
///   Operand stack: [event_id, a1, a0, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [q1, q0, r, ...]
///
/// where (a0, a1) are the 32-bit limbs of the dividend (with a0 representing the 32 least
/// significant bits and a1 representing the 32 most significant bits).
/// Similarly, (q0, q1) represent the quotient and r the remainder.
///
/// # Errors
/// - Returns an error if the divisor is ZERO.
/// - Returns an error if either a0 or a1 is not a u32.
pub fn handle_falcon_div(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    let dividend_hi = process.get_stack_item(1).as_int();
    let dividend_lo = process.get_stack_item(2).as_int();

    if dividend_lo > u32::MAX.into() {
        return Err(FalconDivError::InputNotU32 {
            value: dividend_lo,
            position: "dividend_lo",
        }
        .into());
    }
    if dividend_hi > u32::MAX.into() {
        return Err(FalconDivError::InputNotU32 {
            value: dividend_hi,
            position: "dividend_hi",
        }
        .into());
    }

    let dividend = (dividend_hi << 32) + dividend_lo;

    let (quotient, remainder) = (dividend / M, dividend % M);

    let (q_hi, q_lo) = u64_to_u32_elements(quotient);
    let (r_hi, r_lo) = u64_to_u32_elements(remainder);

    // Assertion from the original code: r_hi should always be zero for Falcon modulus
    assert_eq!(r_hi, ZERO);

    // Create mutations to extend the advice stack with the result.
    // The values are pushed in the order: r_lo, q_lo, q_hi
    let mutation = AdviceMutation::extend_stack([r_lo, q_lo, q_hi]);
    Ok(vec![mutation])
}

// ERROR TYPES
// ================================================================================================

/// Error types that can occur during FALCON_DIV operations.
#[derive(Debug, thiserror::Error)]
pub enum FalconDivError {
    /// Input value is not a valid u32.
    #[error("input value {value} at {position} is not a valid u32")]
    InputNotU32 { value: u64, position: &'static str },
}
