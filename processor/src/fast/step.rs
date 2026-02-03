//! This module defines items relevant to controlling execution stopping conditions.

use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{mast::MastForest, program::Kernel};

use crate::{
    ExecutionError, Stopper,
    continuation_stack::{Continuation, ContinuationStack},
    fast::FastProcessor,
};

// RESUME CONTEXT
// ===============================================================================================

/// The context required to resume execution of a program from the last point at which it was
/// stopped.
#[derive(Debug)]
pub struct ResumeContext {
    pub(crate) current_forest: Arc<MastForest>,
    pub(crate) continuation_stack: ContinuationStack,
    pub(crate) kernel: Kernel,
}

impl ResumeContext {
    /// Returns a reference to the continuation stack.
    pub fn continuation_stack(&self) -> &ContinuationStack {
        &self.continuation_stack
    }

    /// Returns a reference to the MAST forest being currently executed.
    pub fn current_forest(&self) -> &Arc<MastForest> {
        &self.current_forest
    }

    /// Returns a reference to the kernel being currently executed.
    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }
}

// STOPPERS
// ===============================================================================================

/// A [`Stopper`] that never stops execution (except for returning an error when the maximum cycle
/// count is exceeded).
pub struct NeverStopper;

impl Stopper for NeverStopper {
    type Processor = FastProcessor;

    #[inline(always)]
    fn should_stop(
        &self,
        processor: &FastProcessor,
        _continuation_after_stop: impl FnOnce() -> Option<Continuation>,
    ) -> ControlFlow<BreakReason> {
        check_if_max_cycles_exceeded(processor)
    }
}

/// A [`Stopper`] that always stops execution after each single step. An error is returned if the
/// maximum cycle count is exceeded.
pub struct StepStopper;

impl Stopper for StepStopper {
    type Processor = FastProcessor;

    #[inline(always)]
    fn should_stop(
        &self,
        processor: &FastProcessor,
        continuation_after_stop: impl FnOnce() -> Option<Continuation>,
    ) -> ControlFlow<BreakReason> {
        check_if_max_cycles_exceeded(processor)?;

        ControlFlow::Break(BreakReason::Stopped(continuation_after_stop()))
    }
}

/// Checks if the maximum cycle count has been exceeded, returning a `BreakReason::Err` if so.
#[inline(always)]
fn check_if_max_cycles_exceeded(processor: &FastProcessor) -> ControlFlow<BreakReason> {
    if processor.clk > processor.options.max_cycles() as usize {
        ControlFlow::Break(BreakReason::Err(ExecutionError::CycleLimitExceeded(
            processor.options.max_cycles(),
        )))
    } else {
        ControlFlow::Continue(())
    }
}

// BREAK REASON
// ===============================================================================================

/// The reason why execution was interrupted.
#[derive(Debug)]
pub enum BreakReason {
    /// An execution error occurred
    Err(ExecutionError),
    /// Execution was stopped by a [`Stopper`]. Provides the continuation to add to the continuation
    /// stack before returning, if any. The mental model to have in mind when choosing the
    /// continuation to add on a call to `FastProcessor::increment_clk()` is:
    ///
    /// "If execution is stopped here, does the current continuation stack properly encode the next
    /// step of execution?"
    ///
    /// If yes, then `None` should be returned. If not, then the continuation that runs the next
    /// step in `FastProcessor::execute_impl()` should be returned.
    Stopped(Option<Continuation>),
}
