//! Operations that log and clear the rolling precompile accumulator.

use miden_core::{
    chiplets::hasher::{BLOCK_HI_RANGE, BLOCK_LO_RANGE, CV_RANGE, STATE_WIDTH},
    deferred::DEFERRED_AND_INIT_CV,
};

use crate::{
    Felt, Word, ZERO,
    errors::OperationError,
    processor::{HasherInterface, Processor, StackInterface, SystemInterface},
    tracer::{OperationHelperRegisters, Tracer},
};

// LOG DEFERRED OPERATION
// ================================================================================================

/// Folds a precomputed statement digest into the rolling deferred root.
///
/// Stack transition:
/// `[STMNT, ...] -> [STATE_NEW, ...]`
///
/// - Hasher computes `Eidos::compress(DEFERRED_AND_INIT_CV, STATE_PREV || STMNT)`; `STATE_NEW` is
///   the output chaining value.
/// - `STATE_PREV` is the previous rolling state, threaded internally and exposed to constraints via
///   helper registers.
#[inline(always)]
pub(super) fn op_log_deferred<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError> {
    let statement_digest: Word = processor.stack().get_word(0);
    let state_prev = processor.system().deferred_root();

    // Hasher input: [STATE_PREV, STMNT, DEFERRED_AND_INIT_CV].
    let mut hasher_state: [Felt; STATE_WIDTH] = [ZERO; 12];
    hasher_state[BLOCK_LO_RANGE].copy_from_slice(state_prev.as_slice());
    hasher_state[BLOCK_HI_RANGE].copy_from_slice(statement_digest.as_slice());
    hasher_state[CV_RANGE].copy_from_slice(DEFERRED_AND_INIT_CV.as_slice());

    let (addr, output_state) = processor.hasher().compress(hasher_state)?;

    let state_new: Word = output_state[CV_RANGE].try_into().unwrap();

    processor.system_mut().log_deferred_statement(statement_digest, state_new)?;

    processor.stack_mut().set_word(0, &state_new);

    tracer.record_hasher_compress(hasher_state, output_state);

    Ok(OperationHelperRegisters::LogDeferred { addr, state_prev })
}

/// Clears the accumulator identified by the top stack word, preserving the entire stack.
///
/// # Security
///
/// Only a trusted kernel epilogue should execute this operation, after recursively verifying
/// the exact root on the stack. The root-context check also accepts top-level code and does not
/// establish that the caller performed verification.
#[inline(always)]
pub(super) fn op_clear_deferred<P: Processor>(
    processor: &mut P,
) -> Result<OperationHelperRegisters, OperationError> {
    let ctx = processor.system().ctx();
    if !ctx.is_root() {
        return Err(OperationError::ClearDeferredOutsideRootContext { ctx });
    }

    let previous_root = processor.stack().get_word(0);
    processor.system_mut().clear_deferred(previous_root)?;
    Ok(OperationHelperRegisters::Empty)
}
