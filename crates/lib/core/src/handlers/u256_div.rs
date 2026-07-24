//! U256_DIV system event handler for the Miden VM.
//!
//! This handler implements the U256_DIV operation that pushes the result of u256 division
//! (both the quotient and the remainder) onto the advice stack.

use alloc::{vec, vec::Vec};

use miden_core::{Felt, Word};
use miden_processor::{
    ProcessorState,
    advice::{AdviceMutation, AdviceStack},
    event::{EventError, EventName},
};

/// Event name for the u256_div operation.
pub const U256_DIV_EVENT_NAME: EventName = EventName::new("miden::core::math::u256::u256_div");

/// U256_DIV system event handler.
///
/// Pushes the result of u256 division (both the quotient and the remainder) onto the advice
/// stack.
///
/// Inputs:
///   Operand stack: [event_id, b0..b7, a0..a7, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [r4..r7, r0..r3, q4..q7, q0..q3, ...]
///
/// Where (b0..b7) and (a0..a7) are the 32-bit limbs of the divisor and dividend respectively,
/// with b0/a0 being the least significant limb.
///
/// After four `padw adv_loadw` in MASM:
///   First:  loads [r4, r5, r6, r7] onto operand stack
///   Second: loads [r0, r1, r2, r3] onto operand stack
///   Third:  loads [q4, q5, q6, q7] onto operand stack
///   Fourth: loads [q0, q1, q2, q3] onto operand stack
///
/// # Errors
/// Returns an error if the divisor is ZERO or any limb is not a valid u32.
pub fn handle_u256_div(process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
    let divisor = read_u256_from_stack(process, 1, "divisor")?;

    if divisor == (0, 0) {
        return Err(U256DivError::DivideByZero.into());
    }

    let dividend = read_u256_from_stack(process, 9, "dividend")?;

    let (quotient, remainder) = u256_divmod(dividend, divisor);

    let q_felts = u256_to_u32_felts(quotient);
    let r_felts = u256_to_u32_felts(remainder);

    let mut advice_stack = AdviceStack::new();
    // MASM uses four `padw adv_loadw` instructions. Each load places the next lower word on top,
    // so q0..q3 must be consumed last to finish above q4..q7, r0..r3, and r4..r7.
    advice_stack
        .push_word(Word::new([r_felts[4], r_felts[5], r_felts[6], r_felts[7]]))
        .push_word(Word::new([r_felts[0], r_felts[1], r_felts[2], r_felts[3]]))
        .push_word(Word::new([q_felts[4], q_felts[5], q_felts[6], q_felts[7]]))
        .push_word(Word::new([q_felts[0], q_felts[1], q_felts[2], q_felts[3]]));

    Ok(vec![AdviceMutation::extend_advice_stack(advice_stack)])
}

/// Reads a u256 value from 8 consecutive stack positions starting at `start`.
///
/// Returned as a `(lo, hi)` pair of u128s.
fn read_u256_from_stack(
    process: &ProcessorState,
    start: usize,
    name: &'static str,
) -> Result<(u128, u128), EventError> {
    let mut lo: u128 = 0;
    let mut hi: u128 = 0;
    for i in (0..8).rev() {
        let limb = process.get_stack_item(start + i).as_canonical_u64();
        if limb > u32::MAX as u64 {
            return Err(U256DivError::NotU32Value {
                value: limb,
                position: name,
                limb_index: i,
            }
            .into());
        }
        if i < 4 {
            lo = (lo << 32) | limb as u128;
        } else {
            hi = (hi << 32) | limb as u128;
        }
    }
    Ok((lo, hi))
}

/// Splits a u256 (as `(lo, hi)`) into 8 Felt values representing u32 limbs, least significant
/// first.
fn u256_to_u32_felts(value: (u128, u128)) -> [Felt; 8] {
    let (lo, hi) = value;
    [
        Felt::from_u32(lo as u32),
        Felt::from_u32((lo >> 32) as u32),
        Felt::from_u32((lo >> 64) as u32),
        Felt::from_u32((lo >> 96) as u32),
        Felt::from_u32(hi as u32),
        Felt::from_u32((hi >> 32) as u32),
        Felt::from_u32((hi >> 64) as u32),
        Felt::from_u32((hi >> 96) as u32),
    ]
}

/// Computes `(a / b, a % b)` for u256 values represented as `(lo, hi)` pairs.
///
/// Bit-by-bit long division. The divisor is assumed to be nonzero (the caller checks this).
fn u256_divmod(a: (u128, u128), b: (u128, u128)) -> ((u128, u128), (u128, u128)) {
    let (mut q_lo, mut q_hi) = (0u128, 0u128);
    let (mut r_lo, mut r_hi) = (0u128, 0u128);

    for bit in (0..256).rev() {
        // r <<= 1, then bring in the next bit of a from the top.
        r_hi = (r_hi << 1) | (r_lo >> 127);
        r_lo <<= 1;
        let next_bit = if bit < 128 {
            (a.0 >> bit) & 1
        } else {
            (a.1 >> (bit - 128)) & 1
        };
        r_lo |= next_bit;

        // r >= b ?  (lexicographic on (hi, lo))
        let take = r_hi > b.1 || (r_hi == b.1 && r_lo >= b.0);
        if take {
            let (new_lo, borrow) = r_lo.overflowing_sub(b.0);
            r_lo = new_lo;
            r_hi = r_hi.wrapping_sub(b.1).wrapping_sub(borrow as u128);
            if bit < 128 {
                q_lo |= 1u128 << bit;
            } else {
                q_hi |= 1u128 << (bit - 128);
            }
        }
    }

    ((q_lo, q_hi), (r_lo, r_hi))
}

// ERROR TYPES
// ================================================================================================

/// Error types that can occur during U256_DIV operations.
#[derive(Debug, thiserror::Error)]
pub enum U256DivError {
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
