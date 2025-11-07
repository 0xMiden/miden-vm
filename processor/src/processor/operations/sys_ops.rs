use miden_core::{Felt, ONE, mast::MastForest};

use crate::{
    BaseHost, OperationError,
    fast::Tracer,
    processor::{Processor, StackInterface, SystemInterface},
};

/// Pops a value off the stack and asserts that it is equal to ONE.
///
/// # Errors
/// Returns an error if the popped value is not ONE.
#[inline(always)]
pub(super) fn op_assert<P: Processor>(
    processor: &mut P,
    err_code: Felt,
    host: &mut impl BaseHost,
    program: &MastForest,
    tracer: &mut impl Tracer,
) -> Result<(), OperationError> {
    if processor.stack().get(0) != ONE {
        let process = &mut processor.state();
        host.on_assert_failed(process, err_code);
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
) -> Result<(), OperationError> {
    let depth = processor.stack().depth();
    processor.stack().increment_size(tracer)?;
    processor.stack().set(0, depth.into());

    Ok(())
}

/// Analogous to `Process::op_caller`.
#[inline(always)]
pub(super) fn op_caller<P: Processor>(processor: &mut P) -> Result<(), OperationError> {
    let caller_hash = processor.system().caller_hash();
    processor.stack().set_word(0, &caller_hash);

    Ok(())
}

/// Writes the current clock value to the top of the stack.
#[inline(always)]
pub(super) fn op_clk<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), OperationError> {
    let clk: Felt = processor.system().clk().into();
    processor.stack().increment_size(tracer)?;
    processor.stack().set(0, clk);

    Ok(())
}
