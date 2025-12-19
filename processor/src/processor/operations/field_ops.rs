use miden_air::trace::decoder::NUM_USER_OP_HELPERS;
use miden_core::{Felt, FieldElement, ONE, ZERO};

use crate::{
    ErrorContext, ExecutionError,
    fast::Tracer,
    operations::utils::assert_binary,
    processor::{OperationHelperRegisters, Processor, StackInterface, SystemInterface},
};

#[cfg(test)]
mod tests;

/// Pops two elements off the stack, adds them together, and pushes the result back onto the
/// stack.
#[inline(always)]
pub(super) fn op_add<P: Processor>(processor: &mut P, tracer: &mut impl Tracer) {
    pop2_applyfn_push(processor, |a, b| Ok(a + b), tracer).unwrap()
}

/// Pops an element off the stack, computes its additive inverse, and pushes the result back
/// onto the stack.
#[inline(always)]
pub(super) fn op_neg<P: Processor>(processor: &mut P) {
    let element = processor.stack().get(0);
    processor.stack().set(0, -element);
}

/// Pops two elements off the stack, multiplies them, and pushes the result back onto the
/// stack.
#[inline(always)]
pub(super) fn op_mul<P: Processor>(processor: &mut P, tracer: &mut impl Tracer) {
    pop2_applyfn_push(processor, |a, b| Ok(a * b), tracer).unwrap();
}

/// Pops an element off the stack, computes its multiplicative inverse, and pushes the result
/// back onto the stack.
///
/// # Errors
/// Returns an error if the value on the top of the stack is ZERO.
#[inline(always)]
pub(super) fn op_inv<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    let top = processor.stack().get_mut(0);
    if (*top) == ZERO {
        return Err(ExecutionError::divide_by_zero(processor.system().clk(), err_ctx));
    }
    *top = top.inv();
    Ok(())
}

/// Pops an element off the stack, adds ONE to it, and pushes the result back onto the stack.
#[inline(always)]
pub(super) fn op_incr<P: Processor>(processor: &mut P) {
    *processor.stack().get_mut(0) += ONE;
}

/// Pops two elements off the stack, computes their boolean AND, and pushes the result back
/// onto the stack.
///
/// # Errors
/// Returns an error if either of the two elements on the top of the stack is not a binary
/// value.
#[inline(always)]
pub(super) fn op_and<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    pop2_applyfn_push(
        processor,
        |a, b| {
            assert_binary(b, err_ctx)?;
            assert_binary(a, err_ctx)?;

            if a == ONE && b == ONE { Ok(ONE) } else { Ok(ZERO) }
        },
        tracer,
    )
}

/// Pops two elements off the stack, computes their boolean OR, and pushes the result back
/// onto the stack.
///
/// # Errors
/// Returns an error if either of the two elements on the top of the stack is not a binary
/// value.
#[inline(always)]
pub(super) fn op_or<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    pop2_applyfn_push(
        processor,
        |a, b| {
            assert_binary(b, err_ctx)?;
            assert_binary(a, err_ctx)?;

            if a == ONE || b == ONE { Ok(ONE) } else { Ok(ZERO) }
        },
        tracer,
    )
}

/// Pops an element off the stack, computes its boolean NOT, and pushes the result back onto
/// the stack.
///
/// # Errors
/// Returns an error if the value on the top of the stack is not a binary value.
#[inline(always)]
pub(super) fn op_not<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    let top = processor.stack().get_mut(0);
    if *top == ZERO {
        *top = ONE;
    } else if *top == ONE {
        *top = ZERO;
    } else {
        return Err(ExecutionError::not_binary_value_op(*top, err_ctx));
    }
    Ok(())
}

/// Pops two elements off the stack and compares them. If the elements are equal, pushes ONE
/// onto the stack, otherwise pushes ZERO onto the stack.
#[inline(always)]
pub(super) fn op_eq<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    let b = processor.stack().get(0);
    let a = processor.stack().get(1);

    // Directly manipulate the stack instead of using pop2_applyfn_push() since we need
    // to return user op helpers, which makes the abstraction less suitable here.
    processor.stack().decrement_size(tracer);
    let result = if a == b { ONE } else { ZERO };
    processor.stack().set(0, result);

    Ok(P::HelperRegisters::op_eq_registers(a, b))
}

/// Pops an element off the stack and compares it to ZERO. If the element is ZERO, pushes ONE
/// onto the stack, otherwise pushes ZERO onto the stack.
#[inline(always)]
pub(super) fn op_eqz<P: Processor>(processor: &mut P) -> [Felt; NUM_USER_OP_HELPERS] {
    let top = processor.stack().get_mut(0);
    let old_top = *top;

    if old_top == ZERO {
        *top = ONE;
    } else {
        *top = ZERO;
    };

    P::HelperRegisters::op_eqz_registers(old_top)
}

/// Computes a single turn of exp accumulation for the given inputs. The top 4 elements in the
/// stack are arranged as follows (from the top):
/// - 0: least significant bit of the exponent in the previous trace if there's an expacc call,
///   otherwise ZERO,
/// - 1: base of the exponentiation; i.e. `b` in `b^a`,
/// - 2: accumulated result of the exponentiation so far,
/// - 3: the exponent; i.e. `a` in `b^a`.
///
/// It is expected that `Expacc` is called at least `num_exp_bits` times, where `num_exp_bits`
/// is the number of bits needed to represent `exp`. The initial call to `Expacc` should set the
/// stack as [0, base, 1, exponent]. The subsequent call will set the stack either as
/// - [0, base^2, acc, exp/2], or
/// - [1, base^2, acc * base, exp/2],
///
/// depending on the least significant bit of the exponent.
///
/// Expacc is based on the observation that the exponentiation of a number can be computed by
/// repeatedly squaring the base and multiplying those powers of the base by the accumulator,
/// for the powers of the base which correspond to the exponent's bits which are set to 1.
///
/// For example, take b^5 = (b^2)^2 * b. Over the course of 3 iterations (5 = 101b), the
/// algorithm will compute b, b^2 and b^4 (placed in `base_acc`). Hence, we want to multiply
/// `base_acc` in `result_acc` when `base_acc = b` and when `base_acc = b^4`, which occurs on
/// the first and third iterations (corresponding to the `1` bits in the binary representation
/// of 5).
#[inline(always)]
pub(super) fn op_expacc<P: Processor>(processor: &mut P) -> [Felt; NUM_USER_OP_HELPERS] {
    let old_base = processor.stack().get(1);
    let old_acc = processor.stack().get(2);
    let old_exp_int = processor.stack().get(3).as_int();

    // Compute new exponent.
    let new_exp = Felt::new(old_exp_int >> 1);

    // Compute new accumulator. We update the accumulator only when the least significant bit of
    // the exponent is 1.
    let exp_lsb = old_exp_int & 1;
    let acc_update_val = if exp_lsb == 1 { old_base } else { ONE };
    let new_acc = old_acc * acc_update_val;

    // Compute the new base.
    let new_base = old_base * old_base;

    processor.stack().set(0, Felt::new(exp_lsb));
    processor.stack().set(1, new_base);
    processor.stack().set(2, new_acc);
    processor.stack().set(3, new_exp);

    P::HelperRegisters::op_expacc_registers(acc_update_val)
}

/// Gets the top four values from the stack [b1, b0, a1, a0], where a = (a1, a0) and
/// b = (b1, b0) are elements of the extension field, and outputs the product c = (c1, c0)
/// where c0 = b0 * a0 - 2 * b1 * a1 and c1 = (b0 + b1) * (a1 + a0) - b0 * a0. It pushes 0 to
/// the first and second positions on the stack, c1 and c2 to the third and fourth positions,
/// and leaves the rest of the stack unchanged.
#[inline(always)]
pub(super) fn op_ext2mul<P: Processor>(processor: &mut P) {
    const TWO: Felt = Felt::new(2);
    let [a0, a1, b0, b1] = processor.stack().get_word(0).into();

    /* top 2 elements remain unchanged */

    let b0_times_a0 = b0 * a0;
    processor.stack().set(2, (b0 + b1) * (a1 + a0) - b0_times_a0);
    processor.stack().set(3, b0_times_a0 - TWO * b1 * a1);
}

// HELPERS
// ----------------------------------------------------------------------------------------------

/// Pops the top two elements from the stack, applies the given function to them, and pushes the
/// result back onto the stack.
///
/// The size of the stack is decremented by 1.
#[inline(always)]
fn pop2_applyfn_push<P: Processor>(
    processor: &mut P,
    f: impl FnOnce(Felt, Felt) -> Result<Felt, ExecutionError>,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let b = processor.stack().get(0);
    let a = processor.stack().get(1);

    processor.stack().decrement_size(tracer);
    processor.stack().set(0, f(a, b)?);

    Ok(())
}
