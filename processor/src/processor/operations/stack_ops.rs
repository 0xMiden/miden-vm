use miden_core::{Felt, ZERO};

use crate::{
    ExecutionError, OperationError,
    fast::Tracer,
    processor::{Processor, StackInterface},
};

/// Pushes a new element onto the stack.
#[inline(always)]
pub(super) fn op_push<P: Processor>(
    processor: &mut P,
    element: Felt,
    tracer: &mut impl Tracer,
) -> Result<(), OperationError> {
    processor.stack().increment_size(tracer).map_err(map_stack_error)?;
    processor.stack().set(0, element);
    Ok(())
}

/// Pushes a `ZERO` on top of the stack.
#[inline(always)]
pub(super) fn op_pad<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), OperationError> {
    processor.stack().increment_size(tracer).map_err(map_stack_error)?;
    processor.stack().set(0, ZERO);
    Ok(())
}

/// Swaps the top two elements of the stack.
#[inline(always)]
pub(super) fn op_swap<P: Processor>(processor: &mut P) -> Result<(), OperationError> {
    processor.stack().swap(0, 1);
    Ok(())
}

/// Swaps the top two double words of the stack.
#[inline(always)]
pub(super) fn op_swap_double_word<P: Processor>(processor: &mut P) -> Result<(), OperationError> {
    processor.stack().swap(0, 8);
    processor.stack().swap(1, 9);
    processor.stack().swap(2, 10);
    processor.stack().swap(3, 11);
    processor.stack().swap(4, 12);
    processor.stack().swap(5, 13);
    processor.stack().swap(6, 14);
    processor.stack().swap(7, 15);
    Ok(())
}

/// Duplicates the n'th element from the top of the stack to the top of the stack.
///
/// The size of the stack is incremented by 1.
#[inline(always)]
pub(super) fn dup_nth<P: Processor>(
    processor: &mut P,
    n: usize,
    tracer: &mut impl Tracer,
) -> Result<(), OperationError> {
    let to_dup = processor.stack().get(n);
    processor.stack().increment_size(tracer).map_err(map_stack_error)?;
    processor.stack().set(0, to_dup);

    Ok(())
}

/// Analogous to `Process::op_cswap`.
#[inline(always)]
pub(super) fn op_cswap<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), OperationError> {
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
            return Err(OperationError::not_binary_value_op(condition));
        },
    }

    Ok(())
}

/// Analogous to `Process::op_cswapw`.
#[inline(always)]
pub(super) fn op_cswapw<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), OperationError> {
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
            return Err(OperationError::not_binary_value_op(condition));
        },
    }

    Ok(())
}

fn map_stack_error(err: ExecutionError) -> OperationError {
    match err {
        ExecutionError::OperationError { err, .. } => err,
        ExecutionError::FailedToExecuteProgram(reason) => {
            OperationError::failed_to_execute_program(reason)
        },
        _ => OperationError::failed_to_execute_program("stack operation failed"),
    }
}
