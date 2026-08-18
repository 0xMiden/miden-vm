//! This module defines items relevant to controlling execution stopping conditions.

use alloc::{sync::Arc, vec::Vec};
use core::ops::ControlFlow;

use miden_core::{mast::MastForest, program::KernelDescriptor};
use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

use crate::{
    ExecutionError, FastProcessor, SourceInlineCallContext, Stopper,
    continuation_stack::{Continuation, ContinuationStack},
};

// RESUME CONTEXT
// ===============================================================================================

/// The context required to resume execution of a program from the last point at which it was
/// stopped.
#[derive(Debug)]
pub struct ResumeContext {
    pub(crate) current_forest: Arc<MastForest>,
    pub(crate) continuation_stack: ContinuationStack<Arc<MastForest>>,
    pub(crate) kernel: KernelDescriptor,
    pub(crate) package_debug_info: Option<Arc<PackageDebugInfo>>,
    pub(crate) inline_call_contexts: Vec<Option<SourceInlineCallContext>>,
}

impl ResumeContext {
    /// Returns a reference to the continuation stack.
    pub fn continuation_stack(&self) -> &ContinuationStack<Arc<MastForest>> {
        &self.continuation_stack
    }

    /// Returns a reference to the MAST forest being currently executed.
    pub fn current_forest(&self) -> &Arc<MastForest> {
        &self.current_forest
    }

    /// Returns a reference to the debug info associated with the current forest, if available
    pub fn debug_info(&self) -> Option<Arc<PackageDebugInfo>> {
        self.package_debug_info.clone()
    }

    /// Returns the source/debug occurrence associated with the next continuation, if available.
    pub fn next_source_node_id(&self) -> Option<DebugSourceNodeId> {
        self.continuation_stack
            .peek_continuation_with_source_node_id()
            .and_then(|(_, source_node_id)| source_node_id)
    }

    /// Returns dynamic-boundary inline contexts active for the next operation, ordered from the
    /// innermost boundary to the outermost.
    pub fn inherited_inline_call_contexts(&self) -> impl Iterator<Item = &SourceInlineCallContext> {
        let effective_depth = self.continuation_stack.iter_continuations_for_next_clock().fold(
            self.inline_call_contexts.len(),
            |depth, continuation| match continuation {
                Continuation::EnterForest { inline_context_depth, .. } => *inline_context_depth,
                _ => depth,
            },
        );
        self.inline_call_contexts[..effective_depth.min(self.inline_call_contexts.len())]
            .iter()
            .rev()
            .filter_map(Option::as_ref)
    }

    /// Returns a reference to the kernel being currently executed.
    pub fn kernel(&self) -> &KernelDescriptor {
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
    type Forest = Arc<MastForest>;

    #[inline(always)]
    fn should_stop(
        &self,
        processor: &FastProcessor,
        continuation_stack: &ContinuationStack<Arc<MastForest>>,
        _continuation_after_stop: impl FnOnce() -> Option<(
            Continuation<Arc<MastForest>>,
            Option<DebugSourceNodeId>,
        )>,
    ) -> ControlFlow<BreakReason<Arc<MastForest>>> {
        check_if_max_cycles_exceeded(processor)?;
        check_if_continuation_stack_too_large(processor, continuation_stack)
    }
}

/// A [`Stopper`] that always stops execution after each single step. An error is returned if the
/// maximum cycle count is exceeded.
pub struct StepStopper;

impl Stopper for StepStopper {
    type Processor = FastProcessor;
    type Forest = Arc<MastForest>;

    #[inline(always)]
    fn should_stop(
        &self,
        processor: &FastProcessor,
        continuation_stack: &ContinuationStack<Arc<MastForest>>,
        continuation_after_stop: impl FnOnce() -> Option<(
            Continuation<Arc<MastForest>>,
            Option<DebugSourceNodeId>,
        )>,
    ) -> ControlFlow<BreakReason<Arc<MastForest>>> {
        check_if_max_cycles_exceeded(processor)?;
        check_if_continuation_stack_too_large(processor, continuation_stack)?;

        ControlFlow::Break(BreakReason::Stopped(continuation_after_stop()))
    }
}

/// Checks if the maximum cycle count has been exceeded, returning a `BreakReason::Err` if so.
#[inline(always)]
fn check_if_max_cycles_exceeded<F>(processor: &FastProcessor) -> ControlFlow<BreakReason<F>> {
    if processor.clk > processor.options.max_cycles() as usize {
        ControlFlow::Break(BreakReason::Err(ExecutionError::CycleLimitExceeded(
            processor.options.max_cycles(),
        )))
    } else {
        ControlFlow::Continue(())
    }
}

/// Checks if the continuation stack size exceeds the maximum allowed, returning a
/// `BreakReason::Err` if so.
#[inline(always)]
fn check_if_continuation_stack_too_large<F>(
    processor: &FastProcessor,
    continuation_stack: &ContinuationStack<F>,
) -> ControlFlow<BreakReason<F>> {
    if continuation_stack.len() > processor.options.max_num_continuations() {
        ControlFlow::Break(BreakReason::Err(ExecutionError::Internal(
            "continuation stack size exceeded the allowed maximum",
        )))
    } else {
        ControlFlow::Continue(())
    }
}

// BREAK REASON
// ===============================================================================================

/// The reason why execution was interrupted.
#[derive(Debug)]
pub enum BreakReason<F> {
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
    Stopped(Option<(Continuation<F>, Option<DebugSourceNodeId>)>),
}
