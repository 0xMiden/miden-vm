use crate::{
    ExecutionError, Felt, ONE,
    errors::OperationError,
    mast::ExecutableMastForest,
    processor::{Processor, StackInterface, SystemInterface},
    tracer::OperationHelperRegisters,
};

#[cfg(test)]
mod tests;

// SYTEM HANDLERS
// ================================================================================================

/// Pops a value off the stack and asserts that it is equal to ONE.
///
/// # Errors
/// Returns an error if the popped value is not ONE.
#[inline(always)]
pub(super) fn op_assert<P, F>(
    processor: &mut P,
    err_code: Felt,
    program: &F,
) -> Result<OperationHelperRegisters, OperationError>
where
    P: Processor,
    F: ExecutableMastForest,
{
    if processor.stack().get(0) != ONE {
        let err_msg = program.resolve_error_message(err_code);
        return Err(OperationError::FailedAssertion { err_code, err_msg });
    }
    processor.stack_mut().decrement_size()?;
    Ok(OperationHelperRegisters::Empty)
}

/// Writes the current stack depth to the top of the stack.
#[inline(always)]
pub(super) fn op_sdepth<P>(processor: &mut P) -> Result<OperationHelperRegisters, ExecutionError>
where
    P: Processor,
{
    let depth = processor.stack().depth();
    processor.stack_mut().increment_size()?;
    processor.stack_mut().set(0, Felt::from_u32(depth));

    Ok(OperationHelperRegisters::Empty)
}

/// Overwrites the top four stack items with the value of the CALLER_HASH register, which is the
/// hash of the procedure that initiated the most recent SYSCALL, or ZERO if not in a syscall
/// context.
// Uniform return type with sibling `op_*` handlers dispatched in `execute_op`.
#[inline(always)]
pub(super) fn op_caller<P: Processor>(processor: &mut P) -> OperationHelperRegisters {
    let caller_hash = processor.system().caller_hash();
    processor.stack_mut().set_word(0, &caller_hash);

    OperationHelperRegisters::Empty
}

/// Writes the current clock value to the top of the stack.
#[inline(always)]
pub(super) fn op_clk<P>(processor: &mut P) -> Result<OperationHelperRegisters, ExecutionError>
where
    P: Processor,
{
    let clk: Felt = processor.system().clock().into();
    processor.stack_mut().increment_size()?;
    processor.stack_mut().set(0, clk);

    Ok(OperationHelperRegisters::Empty)
}
