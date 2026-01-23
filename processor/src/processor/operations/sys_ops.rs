use miden_core::{Felt, ONE, field::PrimeCharacteristicRing, mast::MastForest};

use crate::{
    ExecutionError, Host,
    errors::OperationError,
    fast::Tracer,
    processor::{Processor, StackInterface, SystemInterface},
};

#[cfg(test)]
mod tests;

/// Pops a value off the stack and asserts that it is equal to ONE.
///
/// # Errors
/// Returns an error if the popped value is not ONE.
#[inline(always)]
pub(super) fn op_assert<P: Processor>(
    processor: &mut P,
    err_code: Felt,
    host: &mut impl Host,
    program: &MastForest,
    tracer: &mut impl Tracer,
) -> Result<(), OperationError> {
    if processor.stack().get(0) != ONE {
        let process = &mut processor.state();
        // Notify host of assertion failure for side effects only (logging, debugging, telemetry).
        // The return value is intentionally ignored because the host callback is for observation,
        // not for modifying the error. The error message comes from the program's error table.
        let _ = host.on_assert_failed(process, err_code);
        let err_msg = program.resolve_error_message(err_code);
        return Err(OperationError::FailedAssertion { err_code, err_msg });
    }
    processor.stack().decrement_size(tracer);
    Ok(())
}

/// Writes the current stack depth to the top of the stack.
#[inline(always)]
pub(super) fn op_sdepth<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let depth = processor.stack().depth();
    processor.stack().increment_size(tracer)?;
    processor.stack().set(0, Felt::from_u32(depth));

    Ok(())
}

/// Analogous to `Process::op_caller`.
#[inline(always)]
pub(super) fn op_caller<P: Processor>(processor: &mut P) -> Result<(), ExecutionError> {
    let caller_hash = processor.system().caller_hash();
    processor.stack().set_word(0, &caller_hash);

    Ok(())
}

/// Writes the current clock value to the top of the stack.
#[inline(always)]
pub(super) fn op_clk<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let clk: Felt = processor.system().clk().into();
    processor.stack().increment_size(tracer)?;
    processor.stack().set(0, clk);

    Ok(())
}
