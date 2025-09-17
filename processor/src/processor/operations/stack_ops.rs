use miden_core::{Felt, ZERO};

use crate::{
    ErrorContext, ExecutionError,
    fast::Tracer,
    processor::{Processor, StackInterface},
};

/// Pushes a new element onto the stack.
#[inline(always)]
pub(super) fn op_push<P: Processor>(processor: &mut P, element: Felt, tracer: &mut impl Tracer) {
    processor.stack().increment_size(tracer);
    processor.stack().set(0, element);
}

/// Pushes a `ZERO` on top of the stack.
#[inline(always)]
pub(super) fn op_pad<P: Processor>(processor: &mut P, tracer: &mut impl Tracer) {
    processor.stack().increment_size(tracer);
    processor.stack().set(0, ZERO);
}

/// Swaps the top two elements of the stack.
#[inline(always)]
pub(super) fn op_swap<P: Processor>(processor: &mut P) {
    processor.stack().swap(0, 1);
}

/// Swaps the top two double words of the stack.
#[inline(always)]
pub(super) fn op_swap_double_word<P: Processor>(processor: &mut P) {
    processor.stack().swap(0, 8);
    processor.stack().swap(1, 9);
    processor.stack().swap(2, 10);
    processor.stack().swap(3, 11);
    processor.stack().swap(4, 12);
    processor.stack().swap(5, 13);
    processor.stack().swap(6, 14);
    processor.stack().swap(7, 15);
}

/// Duplicates the n'th element from the top of the stack to the top of the stack.
///
/// The size of the stack is incremented by 1.
#[inline(always)]
pub(super) fn dup_nth<P: Processor>(processor: &mut P, n: usize, tracer: &mut impl Tracer) {
    let to_dup = processor.stack().get(n);
    processor.stack().increment_size(tracer);
    processor.stack().set(0, to_dup);
}

/// Analogous to `Process::op_cswap`.
#[inline(always)]
pub(super) fn op_cswap<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let condition = processor.stack().get(0);
    processor.stack().decrement_size(tracer);

    match condition.as_int() {
        0 => {
            // do nothing, a and b are already in the right place
        },
        1 => {
            processor.stack().swap(0, 1);
        },
        _ => {
            return Err(ExecutionError::not_binary_value_op(condition, err_ctx));
        },
    }

    Ok(())
}

/// Analogous to `Process::op_cswapw`.
#[inline(always)]
pub(super) fn op_cswapw<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let condition = processor.stack().get(0);
    processor.stack().decrement_size(tracer);

    match condition.as_int() {
        0 => {
            // do nothing, the words are already in the right place
        },
        1 => {
            processor.stack().swap(0, 4);
            processor.stack().swap(1, 5);
            processor.stack().swap(2, 6);
            processor.stack().swap(3, 7);
        },
        _ => {
            return Err(ExecutionError::not_binary_value_op(condition, err_ctx));
        },
    }

    Ok(())
}
