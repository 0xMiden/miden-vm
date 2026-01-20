use alloc::vec::Vec;

use miden_air::trace::decoder::NUM_USER_OP_HELPERS;
use miden_core::{Felt, ZERO, field::PrimeField64};
use paste::paste;

use crate::{
    ExecutionError, OperationError,
    fast::Tracer,
    processor::{OperationHelperRegisters, Processor, StackInterface, SystemInterface},
    utils::split_element,
};

#[cfg(test)]
mod tests;

const U32_MAX: u64 = u32::MAX as u64;

macro_rules! require_u32_operands {
    ($processor:expr, [$($idx:expr),*]) => {{
        let mut invalid_values = Vec::new();

        paste!{
            $(
                let [<operand_ $idx>] = $processor.stack().get($idx);
                if [<operand_ $idx>].as_canonical_u64() > U32_MAX {
                    invalid_values.push([<operand_ $idx>]);
                }
            )*

            if !invalid_values.is_empty() {
                return Err(OperationError::NotU32Values { values: invalid_values });
            }
            // Return tuple of operands based on indices
            ($([<operand_ $idx>]),*)
        }
    }};
}

/// Removes and splits the top element of the stack into two 32-bit values, and pushes them onto
/// the stack.
///
/// Input: [value, ...] where value is a field element
/// Output: [lo, hi, ...] where lo is on top (primary result is the u32 value)
#[inline(always)]
pub(super) fn op_u32split<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    let (top_hi, top_lo) = {
        let top = processor.stack().get(0);
        split_element(top)
    };
    tracer.record_u32_range_checks(processor.system().clk(), top_lo, top_hi);

    processor.stack().increment_size(tracer)?;
    processor.stack().set(0, top_lo);
    processor.stack().set(1, top_hi);

    Ok(P::HelperRegisters::op_u32split_registers(top_lo, top_hi))
}

/// Adds the top two elements of the stack and pushes the result onto the stack.
///
/// Input: [a, b, ...] where a is on top
/// Output: [sum, carry, ...] where sum is on top
#[inline(always)]
pub(super) fn op_u32add<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], OperationError> {
    let (carry, sum) = {
        let (a, b) = require_u32_operands!(processor, [0, 1]);

        let result = Felt::new(a.as_canonical_u64() + b.as_canonical_u64());
        split_element(result)
    };
    tracer.record_u32_range_checks(processor.system().clk(), sum, carry);

    processor.stack().set(0, sum);
    processor.stack().set(1, carry);

    Ok(P::HelperRegisters::op_u32add_registers(sum, carry))
}

/// Pops three elements off the stack, adds them, splits the result into low and high 32-bit
/// values, and pushes these values back onto the stack.
///
/// Input: [a, b, c, ...] where a is on top
/// Output: [sum, carry, ...] where sum is on top
///
/// The size of the stack is decremented by 1.
#[inline(always)]
pub(super) fn op_u32add3<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], OperationError> {
    let (carry, sum) = {
        let (a, b, c) = require_u32_operands!(processor, [0, 1, 2]);

        let result = Felt::new(a.as_canonical_u64() + b.as_canonical_u64() + c.as_canonical_u64());
        split_element(result)
    };
    tracer.record_u32_range_checks(processor.system().clk(), sum, carry);

    // write sum to the new top of the stack, and carry after
    processor.stack().decrement_size(tracer);
    processor.stack().set(0, sum);
    processor.stack().set(1, carry);

    Ok(P::HelperRegisters::op_u32add3_registers(sum, carry))
}

/// Pops two elements off the stack, subtracts the top element from the second element, and
/// pushes the result as well as a flag indicating whether there was underflow back onto the
/// stack.
///
/// Input: [b, a, ...] where b (subtrahend) is on top
/// Output: [borrow, diff, ...] where borrow is on top, computes a - b
#[inline(always)]
pub(super) fn op_u32sub<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], OperationError> {
    let (b, a) = require_u32_operands!(processor, [0, 1]);

    let result = a.as_canonical_u64().wrapping_sub(b.as_canonical_u64());
    let borrow = Felt::new(result >> 63);
    let diff = Felt::new(result & u32::MAX as u64);

    tracer.record_u32_range_checks(processor.system().clk(), diff, ZERO);

    processor.stack().set(0, borrow);
    processor.stack().set(1, diff);

    Ok(P::HelperRegisters::op_u32sub_registers(diff))
}

/// Pops two elements off the stack, multiplies them, splits the result into low and high
/// 32-bit values, and pushes these values back onto the stack.
///
/// Input: [a, b, ...] where a is on top
/// Output: [lo, hi, ...] where lo is on top
#[inline(always)]
pub(super) fn op_u32mul<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], OperationError> {
    let (a, b) = require_u32_operands!(processor, [0, 1]);

    let result = Felt::new(a.as_canonical_u64() * b.as_canonical_u64());
    let (hi, lo) = split_element(result);
    tracer.record_u32_range_checks(processor.system().clk(), lo, hi);

    processor.stack().set(0, lo);
    processor.stack().set(1, hi);

    Ok(P::HelperRegisters::op_u32mul_registers(hi, lo))
}

/// Pops three elements off the stack, multiplies the first two and adds the third element to
/// the result, splits the result into low and high 32-bit values, and pushes these values
/// back onto the stack.
///
/// Input: [a, b, c, ...] where a is on top
/// Output: [lo, hi, ...] where lo is on top, computes a * b + c
#[inline(always)]
pub(super) fn op_u32madd<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], OperationError> {
    let (a, b, c) = require_u32_operands!(processor, [0, 1, 2]);

    let result = Felt::new(a.as_canonical_u64() * b.as_canonical_u64() + c.as_canonical_u64());
    let (hi, lo) = split_element(result);
    tracer.record_u32_range_checks(processor.system().clk(), lo, hi);

    // write lo to the new top of the stack, and hi after
    processor.stack().decrement_size(tracer);
    processor.stack().set(0, lo);
    processor.stack().set(1, hi);

    Ok(P::HelperRegisters::op_u32madd_registers(hi, lo))
}

/// Pops two elements off the stack, divides the second element by the top element, and pushes
/// the remainder and the quotient back onto the stack.
///
/// Input: [b, a, ...] where b (divisor) is on top, a (dividend) is below
/// Output: [remainder, quotient, ...] where remainder is on top, computes a / b
///
/// # Errors
/// Returns an error if the divisor is ZERO.
#[inline(always)]
pub(super) fn op_u32div<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], OperationError> {
    let (denominator, numerator) = {
        let (b, a) = require_u32_operands!(processor, [0, 1]);

        // b is divisor (top element), a is dividend (second element)
        (b.as_canonical_u64(), a.as_canonical_u64())
    };

    if denominator == 0 {
        return Err(OperationError::DivideByZero);
    }

    // a/b = q + r/b for some q>=0 and 0<=r<b
    let quotient = numerator / denominator;
    let remainder = numerator - quotient * denominator;

    // remainder is placed on top of the stack, followed by quotient
    processor.stack().set(0, Felt::new(remainder));
    processor.stack().set(1, Felt::new(quotient));

    // These range checks help enforce that quotient <= numerator.
    let lo = Felt::new(numerator - quotient);
    // These range checks help enforce that remainder < denominator.
    let hi = Felt::new(denominator - remainder - 1);

    tracer.record_u32_range_checks(processor.system().clk(), lo, hi);
    Ok(P::HelperRegisters::op_u32div_registers(hi, lo))
}

/// Pops two elements off the stack, computes their bitwise AND, and pushes the result back
/// onto the stack.
///
/// Input: [a, b, ...] where a is on top
/// Output: [result, ...] where result = a AND b
#[inline(always)]
pub(super) fn op_u32and<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), OperationError> {
    let (a, b) = require_u32_operands!(processor, [0, 1]);
    tracer.record_u32and(a, b);

    let result = a.as_canonical_u64() & b.as_canonical_u64();

    // Update stack
    processor.stack().decrement_size(tracer);
    processor.stack().set(0, Felt::new(result));
    Ok(())
}

/// Pops two elements off the stack, computes their bitwise XOR, and pushes the result back onto
/// the stack.
///
/// Input: [a, b, ...] where a is on top
/// Output: [result, ...] where result = a XOR b
#[inline(always)]
pub(super) fn op_u32xor<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), OperationError> {
    let (a, b) = require_u32_operands!(processor, [0, 1]);
    tracer.record_u32xor(a, b);

    let result = a.as_canonical_u64() ^ b.as_canonical_u64();

    // Update stack
    processor.stack().decrement_size(tracer);
    processor.stack().set(0, Felt::new(result));
    Ok(())
}

/// Pops top two element off the stack, splits them into low and high 32-bit values, checks if
/// the high values are equal to 0; if they are, puts the original elements back onto the
/// stack; if they are not, returns an error.
#[inline(always)]
pub(super) fn op_u32assert2<P: Processor>(
    processor: &mut P,
    _err_code: Felt,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], OperationError> {
    let (first, second) = require_u32_operands!(processor, [0, 1]);

    tracer.record_u32_range_checks(processor.system().clk(), first, second);

    // Stack remains unchanged for assert operations

    Ok(P::HelperRegisters::op_u32assert2_registers(first, second))
}
