//! This module defines items relevant to controlling execution stopping conditions, through the
//! `FastProcessor::step()` method.

use alloc::sync::Arc;

use miden_core::{Kernel, mast::MastForest};

use crate::{
    ExecutionError,
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

// STOPPER
// ===============================================================================================

/// A trait for types that determine whether execution should be stopped at a given point.
pub trait Stopper {
    fn should_stop(&self, processor: &FastProcessor) -> bool;
}

/// A [`Stopper`] that never stops execution.
pub struct NeverStopper;

impl Stopper for NeverStopper {
    fn should_stop(&self, _processor: &FastProcessor) -> bool {
        false
    }
}

/// A [`Stopper`] that always stops execution after each single step.
pub struct StepStopper;

impl Stopper for StepStopper {
    fn should_stop(&self, _processor: &FastProcessor) -> bool {
        true
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

impl BreakReason {
    #[inline(always)]
    pub fn stopped(_: ()) -> Self {
        Self::Stopped(None)
    }
}
