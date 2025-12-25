use alloc::vec::Vec;

use miden_air::trace::decoder::NUM_USER_OP_HELPERS;
use miden_core::{Felt, ZERO};
use paste::paste;

use crate::{
    ErrorContext, ExecutionError,
    fast::Tracer,
    processor::{OperationHelperRegisters, Processor, StackInterface, SystemInterface},
    utils::split_element,
};

#[cfg(test)]
mod tests;

const U32_MAX: u64 = u32::MAX as u64;

macro_rules! require_u32_operands {
    ($processor:expr, [$($idx:expr),*], $err_ctx:expr) => {{
        let mut invalid_values = Vec::new();

        paste!{
            $(
                let [<operand_ $idx>] = $processor.stack().get($idx);
                if [<operand_ $idx>].as_int() > U32_MAX {
                    invalid_values.push([<operand_ $idx>]);
                }
            )*

            if !invalid_values.is_empty() {
                return Err(ExecutionError::not_u32_values(invalid_values, $err_ctx));
            }
            // Return tuple of operands based on indices
            ($([<operand_ $idx>]),*)
        }
    }};
}

/// Removes and splits the top element of the stack into two 32-bit values, and pushes them onto
/// the stack.
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
    processor.stack().set(0, top_hi);
    processor.stack().set(1, top_lo);

    Ok(P::HelperRegisters::op_u32split_registers(top_hi, top_lo))
}

/// Adds the top two elements of the stack and pushes the result onto the stack.
#[inline(always)]
pub(super) fn op_u32add<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    let (sum_hi, sum_lo) = {
        let (b, a) = require_u32_operands!(processor, [0, 1], err_ctx);

        let result = Felt::new(a.as_int() + b.as_int());
        split_element(result)
    };
    tracer.record_u32_range_checks(processor.system().clk(), sum_lo, sum_hi);

    processor.stack().set(0, sum_hi);
    processor.stack().set(1, sum_lo);

    Ok(P::HelperRegisters::op_u32add_registers(sum_hi, sum_lo))
}

/// Pops three elements off the stack, adds them, splits the result into low and high 32-bit
/// values, and pushes these values back onto the stack.
///
/// The size of the stack is decremented by 1.
#[inline(always)]
pub(super) fn op_u32add3<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    let (sum_hi, sum_lo) = {
        let (c, b, a) = require_u32_operands!(processor, [0, 1, 2], err_ctx);

        let sum = Felt::new(a.as_int() + b.as_int() + c.as_int());
        split_element(sum)
    };
    tracer.record_u32_range_checks(processor.system().clk(), sum_lo, sum_hi);

    // write the high 32 bits to the new top of the stack, and low 32 bits after
    processor.stack().decrement_size(tracer);
    processor.stack().set(0, sum_hi);
    processor.stack().set(1, sum_lo);

    Ok(P::HelperRegisters::op_u32add3_registers(sum_hi, sum_lo))
}

/// Pops two elements off the stack, subtracts the top element from the second element, and
/// pushes the result as well as a flag indicating whether there was underflow back onto the
/// stack.
#[inline(always)]
pub(super) fn op_u32sub<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    let (first_old, second_old) = require_u32_operands!(processor, [0, 1], err_ctx);

    let result = second_old.as_int().wrapping_sub(first_old.as_int());
    let first_new = Felt::new(result >> 63);
    let second_new = Felt::new(result & u32::MAX as u64);

    tracer.record_u32_range_checks(processor.system().clk(), second_new, ZERO);

    processor.stack().set(0, first_new);
    processor.stack().set(1, second_new);

    Ok(P::HelperRegisters::op_u32sub_registers(second_new))
}

/// Pops two elements off the stack, multiplies them, splits the result into low and high
/// 32-bit values, and pushes these values back onto the stack.
#[inline(always)]
pub(super) fn op_u32mul<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    let (b, a) = require_u32_operands!(processor, [0, 1], err_ctx);

    let result = Felt::new(a.as_int() * b.as_int());
    let (hi, lo) = split_element(result);
    tracer.record_u32_range_checks(processor.system().clk(), lo, hi);

    processor.stack().set(0, hi);
    processor.stack().set(1, lo);

    Ok(P::HelperRegisters::op_u32mul_registers(hi, lo))
}

/// Pops three elements off the stack, multiplies the first two and adds the third element to
/// the result, splits the result into low and high 32-bit values, and pushes these values
/// back onto the stack.
#[inline(always)]
pub(super) fn op_u32madd<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    let (b, a, c) = require_u32_operands!(processor, [0, 1, 2], err_ctx);

    let result = Felt::new(a.as_int() * b.as_int() + c.as_int());
    let (hi, lo) = split_element(result);
    tracer.record_u32_range_checks(processor.system().clk(), lo, hi);

    // write the high 32 bits to the new top of the stack, and low 32 bits after
    processor.stack().decrement_size(tracer);
    processor.stack().set(0, hi);
    processor.stack().set(1, lo);

    Ok(P::HelperRegisters::op_u32madd_registers(hi, lo))
}

/// Pops two elements off the stack, divides the second element by the top element, and pushes
/// the quotient and the remainder back onto the stack.
///
/// # Errors
/// Returns an error if the divisor is ZERO.
#[inline(always)]
pub(super) fn op_u32div<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    let (denominator, numerator) = {
        let (denominator, numerator) = require_u32_operands!(processor, [0, 1], err_ctx);

        (denominator.as_int(), numerator.as_int())
    };

    if denominator == 0 {
        return Err(ExecutionError::divide_by_zero(processor.system().clk(), err_ctx));
    }

    // a/b = n*q + r for some n>=0 and 0<=r<b
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
#[inline(always)]
pub(super) fn op_u32and<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let (b, a) = require_u32_operands!(processor, [0, 1], err_ctx);
    tracer.record_u32and(a, b);

    let result = a.as_int() & b.as_int();

    // Update stack
    processor.stack().decrement_size(tracer);
    processor.stack().set(0, Felt::new(result));
    Ok(())
}

/// Pops two elements off the stack, computes their bitwise XOR, and pushes the result back onto
/// the stack.
#[inline(always)]
pub(super) fn op_u32xor<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let (b, a) = require_u32_operands!(processor, [0, 1], err_ctx);
    tracer.record_u32xor(a, b);

    let result = a.as_int() ^ b.as_int();

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
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    let (first, second) = require_u32_operands!(processor, [0, 1], err_ctx);

    tracer.record_u32_range_checks(processor.system().clk(), first, second);

    // Stack remains unchanged for assert operations

    Ok(P::HelperRegisters::op_u32assert2_registers(first, second))
}
