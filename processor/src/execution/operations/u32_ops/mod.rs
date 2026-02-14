use alloc::vec::Vec;

use paste::paste;

use crate::{
    ExecutionError, Felt, ZERO,
    field::PrimeField64,
    operation::OperationError,
    processor::{Processor, StackInterface, SystemInterface},
    tracer::{OperationHelperRegisters, Tracer},
};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const U32_MAX: u64 = u32::MAX as u64;

// HELPER MACROS
// ================================================================================================

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

// U32 OPERATIONS
// ================================================================================================

/// Removes and splits the top element of the stack into two 32-bit values, and pushes them onto
/// the stack.
///
/// Input: [value, ...] where value is a field element
/// Output: [lo, hi, ...] where lo is on top (primary result is the u32 value)
#[inline(always)]
pub(super) fn op_u32split<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, ExecutionError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let (top_hi, top_lo) = {
        let top = processor.stack().get(0);
        split_element(top)
    };
    tracer.record_u32_range_checks(processor.system().clock(), top_lo, top_hi);

    processor.stack_mut().increment_size()?;
    processor.stack_mut().set(0, top_lo);
    tracer.increment_stack_size(processor);

    processor.stack_mut().set(1, top_hi);

    Ok(OperationHelperRegisters::U32Split { lo: top_lo, hi: top_hi })
}

/// Adds the top two elements of the stack and pushes the result onto the stack.
///
/// Input: [a, b, ...] where a is on top
/// Output: [sum, carry, ...] where sum is on top
#[inline(always)]
pub(super) fn op_u32add<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError> {
    let (carry, sum) = {
        let (a, b) = require_u32_operands!(processor, [0, 1]);

        let result = Felt::new(a.as_canonical_u64() + b.as_canonical_u64());
        split_element(result)
    };
    tracer.record_u32_range_checks(processor.system().clock(), sum, carry);

    processor.stack_mut().set(0, sum);
    processor.stack_mut().set(1, carry);

    Ok(OperationHelperRegisters::U32Add { sum, carry })
}

/// Pops three elements off the stack, adds them, splits the result into low and high 32-bit
/// values, and pushes these values back onto the stack.
///
/// Input: [a, b, c, ...] where a is on top
/// Output: [sum, carry, ...] where sum is on top
///
/// The size of the stack is decremented by 1.
#[inline(always)]
pub(super) fn op_u32add3<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let (carry, sum) = {
        let (a, b, c) = require_u32_operands!(processor, [0, 1, 2]);

        let result = Felt::new(a.as_canonical_u64() + b.as_canonical_u64() + c.as_canonical_u64());
        split_element(result)
    };
    tracer.record_u32_range_checks(processor.system().clock(), sum, carry);

    // write sum to the new top of the stack, and carry after
    processor.stack_mut().decrement_size();
    tracer.decrement_stack_size();
    processor.stack_mut().set(0, sum);
    processor.stack_mut().set(1, carry);

    Ok(OperationHelperRegisters::U32Add3 { sum, carry })
}

/// Pops two elements off the stack, subtracts the top element from the second element, and
/// pushes the result as well as a flag indicating whether there was underflow back onto the
/// stack.
///
/// Input: [b, a, ...] where b (subtrahend) is on top
/// Output: [borrow, diff, ...] where borrow is on top, computes a - b
#[inline(always)]
pub(super) fn op_u32sub<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError> {
    let (b, a) = require_u32_operands!(processor, [0, 1]);

    let result = a.as_canonical_u64().wrapping_sub(b.as_canonical_u64());
    let borrow = Felt::new(result >> 63);
    let diff = Felt::new(result & u32::MAX as u64);

    tracer.record_u32_range_checks(processor.system().clock(), diff, ZERO);

    processor.stack_mut().set(0, borrow);
    processor.stack_mut().set(1, diff);

    Ok(OperationHelperRegisters::U32Sub { second_new: diff })
}

/// Pops two elements off the stack, multiplies them, splits the result into low and high
/// 32-bit values, and pushes these values back onto the stack.
///
/// Input: [a, b, ...] where a is on top
/// Output: [lo, hi, ...] where lo is on top
#[inline(always)]
pub(super) fn op_u32mul<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError> {
    let (a, b) = require_u32_operands!(processor, [0, 1]);

    let result = Felt::new(a.as_canonical_u64() * b.as_canonical_u64());
    let (hi, lo) = split_element(result);
    tracer.record_u32_range_checks(processor.system().clock(), lo, hi);

    processor.stack_mut().set(0, lo);
    processor.stack_mut().set(1, hi);

    Ok(OperationHelperRegisters::U32Mul { lo, hi })
}

/// Pops three elements off the stack, multiplies the first two and adds the third element to
/// the result, splits the result into low and high 32-bit values, and pushes these values
/// back onto the stack.
///
/// Input: [a, b, c, ...] where a is on top
/// Output: [lo, hi, ...] where lo is on top, computes a * b + c
#[inline(always)]
pub(super) fn op_u32madd<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let (a, b, c) = require_u32_operands!(processor, [0, 1, 2]);

    let result = Felt::new(a.as_canonical_u64() * b.as_canonical_u64() + c.as_canonical_u64());
    let (hi, lo) = split_element(result);
    tracer.record_u32_range_checks(processor.system().clock(), lo, hi);

    // write lo to the new top of the stack, and hi after
    processor.stack_mut().decrement_size();
    tracer.decrement_stack_size();
    processor.stack_mut().set(0, lo);
    processor.stack_mut().set(1, hi);

    Ok(OperationHelperRegisters::U32Madd { lo, hi })
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
pub(super) fn op_u32div<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError> {
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
    processor.stack_mut().set(0, Felt::new(remainder));
    processor.stack_mut().set(1, Felt::new(quotient));

    // These range checks help enforce that quotient <= numerator.
    let lo = Felt::new(numerator - quotient);
    // These range checks help enforce that remainder < denominator.
    let hi = Felt::new(denominator - remainder - 1);

    tracer.record_u32_range_checks(processor.system().clock(), lo, hi);
    Ok(OperationHelperRegisters::U32Div { lo, hi })
}

/// Pops two elements off the stack, computes their bitwise AND, and pushes the result back
/// onto the stack.
///
/// Input: [a, b, ...] where a is on top
/// Output: [result, ...] where result = a AND b
#[inline(always)]
pub(super) fn op_u32and<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let (a, b) = require_u32_operands!(processor, [0, 1]);
    tracer.record_u32and(a, b);

    let result = a.as_canonical_u64() & b.as_canonical_u64();

    // Update stack
    processor.stack_mut().decrement_size();
    tracer.decrement_stack_size();
    processor.stack_mut().set(0, Felt::new(result));
    Ok(OperationHelperRegisters::Empty)
}

/// Pops two elements off the stack, computes their bitwise XOR, and pushes the result back onto
/// the stack.
///
/// Input: [a, b, ...] where a is on top
/// Output: [result, ...] where result = a XOR b
#[inline(always)]
pub(super) fn op_u32xor<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let (a, b) = require_u32_operands!(processor, [0, 1]);
    tracer.record_u32xor(a, b);

    let result = a.as_canonical_u64() ^ b.as_canonical_u64();

    // Update stack
    processor.stack_mut().decrement_size();
    tracer.decrement_stack_size();
    processor.stack_mut().set(0, Felt::new(result));
    Ok(OperationHelperRegisters::Empty)
}

/// Pops top two element off the stack, splits them into low and high 32-bit values, checks if
/// the high values are equal to 0; if they are, puts the original elements back onto the
/// stack; if they are not, returns an error.
#[inline(always)]
pub(super) fn op_u32assert2<P: Processor, T: Tracer>(
    processor: &mut P,
    _err_code: Felt,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError> {
    let (first, second) = require_u32_operands!(processor, [0, 1]);

    tracer.record_u32_range_checks(processor.system().clock(), first, second);

    // Stack remains unchanged for assert operations

    Ok(OperationHelperRegisters::U32Assert2 { first, second })
}

// HELPER FUNCTIONS
// ================================================================================================

/// Splits an element into two field elements containing 32-bit integer values
#[inline(always)]
fn split_element(value: Felt) -> (Felt, Felt) {
    let value = value.as_canonical_u64();
    let lo = (value as u32) as u64;
    let hi = value >> 32;
    (Felt::new(hi), Felt::new(lo))
}
