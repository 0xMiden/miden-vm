use crate::{
    ExecutionError, Felt, ZERO,
    field::PrimeField64,
    operation::OperationError,
    processor::{Processor, StackInterface},
    tracer::{OperationHelperRegisters, Tracer},
};

#[cfg(test)]
mod tests;

// STACK OPERATIONS
// ================================================================================================

/// Pushes a new element onto the stack.
#[inline(always)]
pub(super) fn op_push<P, T>(
    processor: &mut P,
    element: Felt,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, ExecutionError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    processor.stack_mut().increment_size(tracer)?;
    processor.stack_mut().set(0, element);
    Ok(OperationHelperRegisters::Empty)
}

/// Pushes a `ZERO` on top of the stack.
#[inline(always)]
pub(super) fn op_pad<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, ExecutionError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    processor.stack_mut().increment_size(tracer)?;
    processor.stack_mut().set(0, ZERO);
    Ok(OperationHelperRegisters::Empty)
}

/// Swaps the top two elements of the stack.
#[inline(always)]
pub(super) fn op_swap<P: Processor>(processor: &mut P) -> OperationHelperRegisters {
    processor.stack_mut().swap(0, 1);
    OperationHelperRegisters::Empty
}

/// Swaps the top two double words of the stack.
#[inline(always)]
pub(super) fn op_swap_double_word<P: Processor>(processor: &mut P) -> OperationHelperRegisters {
    processor.stack_mut().swap(0, 8);
    processor.stack_mut().swap(1, 9);
    processor.stack_mut().swap(2, 10);
    processor.stack_mut().swap(3, 11);
    processor.stack_mut().swap(4, 12);
    processor.stack_mut().swap(5, 13);
    processor.stack_mut().swap(6, 14);
    processor.stack_mut().swap(7, 15);
    OperationHelperRegisters::Empty
}

/// Duplicates the n'th element from the top of the stack to the top of the stack.
///
/// The size of the stack is incremented by 1.
#[inline(always)]
pub(super) fn dup_nth<P, T>(
    processor: &mut P,
    n: usize,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, ExecutionError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let to_dup = processor.stack().get(n);
    processor.stack_mut().increment_size(tracer)?;
    processor.stack_mut().set(0, to_dup);

    Ok(OperationHelperRegisters::Empty)
}

/// Pops an element off the stack, and if the element is 1, swaps the top two elements on the
/// stack. If the popped element is 0, the stack remains unchanged.
///
/// # Errors
/// Returns an error if the top element of the stack is neither 0 nor 1.
#[inline(always)]
pub(super) fn op_cswap<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let condition = processor.stack().get(0);
    processor.stack_mut().decrement_size(tracer);

    match condition.as_canonical_u64() {
        0 => {
            // do nothing, a and b are already in the right place
        },
        1 => {
            processor.stack_mut().swap(0, 1);
        },
        _ => {
            return Err(OperationError::NotBinaryValue { value: condition });
        },
    }

    Ok(OperationHelperRegisters::Empty)
}

/// Pops an element off the stack, and if the element is 1, swaps elements 0, 1, 2, and 3 with
/// elements 4, 5, 6, and 7. If the popped element is 0, the stack remains unchanged.
///
/// # Errors
/// Returns an error if the top element of the stack is neither 0 nor 1.
#[inline(always)]
pub(super) fn op_cswapw<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let condition = processor.stack().get(0);
    processor.stack_mut().decrement_size(tracer);

    match condition.as_canonical_u64() {
        0 => {
            // do nothing, the words are already in the right place
        },
        1 => {
            processor.stack_mut().swap(0, 4);
            processor.stack_mut().swap(1, 5);
            processor.stack_mut().swap(2, 6);
            processor.stack_mut().swap(3, 7);
        },
        _ => {
            return Err(OperationError::NotBinaryValue { value: condition });
        },
    }

    Ok(OperationHelperRegisters::Empty)
}
