#![no_std]
// Trace tests intentionally use index-based `for i in a..b` over column slices; clippy's iterator
// suggestion is noisier than helpful there.
#![cfg_attr(test, allow(clippy::needless_range_loop))]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::ops::ControlFlow;

use miden_mast_package::debug_info::DebugSourceNodeId;

mod continuation_stack;
mod errors;
mod execution;
mod execution_options;
mod executor;
mod fast;
mod host;
mod processor;
mod tracer;

use miden_core::mast::ExecutableMastForest;

use crate::{
    advice::{AdviceInputs, AdviceProvider},
    continuation_stack::ContinuationStack,
    errors::MapExecErr,
    trace::RowIndex,
};

#[cfg(any(test, feature = "testing"))]
mod test_utils;
#[cfg(any(test, feature = "testing"))]
pub use test_utils::{ProcessorStateSnapshot, TestHost};

#[cfg(test)]
mod tests;

// RE-EXPORTS
// ================================================================================================

pub use continuation_stack::{Continuation, SourceInlineCallContext};
pub use errors::{
    AceError, ExecutionError, HostError, MemoryError, PackageSourceDebugContext,
    advice_error_with_package_source_context, event_error_with_package_source_context,
    procedure_not_found_with_package_source_context,
};
pub use execution_options::{ExecutionOptions, ExecutionOptionsError};
pub use executor::ProgramExecutor;
pub use fast::{BreakReason, ExecutionOutput, FastProcessor, ResumeContext};
pub use host::{
    BaseHost, FutureMaybeSend, Host, LoadedMastForest, MastForestStore, MemMastForestStore,
    SyncHost,
    debug::{StdoutWriter, format_value, write_interval, write_stack},
    default::{DefaultHost, HostLibrary},
};
pub use miden_core::{
    ContextId, EMPTY_WORD, Felt, MemoryAddress, ONE, WORD_SIZE, Word, ZERO, crypto, field, mast,
    program::{
        ExecutionClaim, InputError, KernelDescriptor, MIN_STACK_DEPTH, Program, ProgramInfo,
        StackInputs, StackOutputs,
    },
    serde, utils,
};
pub use trace::{ExecutionWitness, PrecompileWitness, VmWitness};

pub mod advice {
    pub use miden_core::advice::{AdviceInputs, AdviceMap, AdviceStack};
    pub use miden_event_handler::AdviceMutation;

    pub use super::host::advice::{AdviceError, AdviceProvider};
}

/// Compatibility facade for common handler-facing types.
///
/// New handlers should import these types directly from `miden_event_handler`. Deprecated
/// compatibility types remain here for v0.31 and will be removed in v0.32.
pub mod event {
    pub use miden_core::events::*;
    #[allow(deprecated)]
    pub use miden_event_handler::{
        AdviceProviderView, EventContext, EventError, EventHandler, NoopEventHandler,
        NoopTraceHandler, TraceError, TraceHandler,
    };

    pub use crate::host::handlers::{EventHandlerRegistry, TraceHandlerRegistry};
}

/// Compatibility alias for the context passed to host callbacks.
#[deprecated(note = "use miden_event_handler::EventContext")]
pub type ProcessorState<'a> = miden_event_handler::EventContext<'a>;

pub mod operation {
    pub use miden_core::operations::*;

    pub use crate::errors::{BinaryValueErrorContext, OperationError};
}

pub mod trace;

// STOPPER
// ===============================================================================================

/// A trait for types that determine whether execution should be stopped after each clock cycle.
///
/// This allows for flexible control over the execution process, enabling features such as stepping
/// through execution (see [`crate::FastProcessor::step`]) or limiting execution to a certain number
/// of clock cycles (used in parallel trace generation to fill the trace for a predetermined trace
/// fragment).
pub trait Stopper {
    type Processor;

    /// The forest representation used by the executor this stopper is paired with.
    ///
    /// For live execution this is `Arc<MastForest>`; for replay it is `Arc<SparseMastForest>`.
    type Forest: ExecutableMastForest + Clone;

    /// Determines whether execution should be stopped at the end of each clock cycle.
    ///
    /// This method is guaranteed to be called at the end of each clock cycle, *after* the processor
    /// state has been updated to reflect the effects of the operations executed during that cycle
    /// (*including* the processor clock). Hence, a processor clock of `N` indicates that clock
    /// cycle `N - 1` has just completed.
    ///
    /// The `continuation_after_stop` is provided in cases where simply resuming execution from the
    /// top of the continuation stack is not sufficient to continue execution correctly. For
    /// example, when stopping execution in the middle of a basic block, we need to provide a
    /// `ResumeBasicBlock` continuation to ensure that execution resumes at the correct operation
    /// within the basic block (i.e. the operation right after the one that was last executed before
    /// being stopped). No continuation is provided in case of error, since it is expected that
    /// execution will not be resumed.
    fn should_stop(
        &self,
        processor: &Self::Processor,
        continuation_stack: &ContinuationStack<Self::Forest>,
        continuation_after_stop: impl FnOnce() -> Option<(
            Continuation<Self::Forest>,
            Option<DebugSourceNodeId>,
        )>,
    ) -> ControlFlow<BreakReason<Self::Forest>>;
}

// HELPERS
// ===============================================================================================

/// Lifts an [`Option<T>`] into a [`ControlFlow`] suitable for the execution loop, mapping `None`
/// to a break carrying an [`ExecutionError::Internal`] with `err_msg`.
///
/// Intended for use with `?` at sites where a `None` represents a violated internal invariant —
/// most commonly a missing node returned by
/// [`ExecutableMastForest::get_node_by_id`](miden_core::mast::ExecutableMastForest::get_node_by_id).
/// For functions returning `ControlFlow<InternalBreakReason<F>>`, chain
/// `.map_break(InternalBreakReason::from)` before `?`.
#[track_caller]
fn option_map_break_reason<F, T>(
    opt: Option<T>,
    err_msg: &'static str,
) -> ControlFlow<BreakReason<F>, T> {
    match opt {
        Some(value) => ControlFlow::Continue(value),
        None => ControlFlow::Break(BreakReason::Err(ExecutionError::Internal(err_msg))),
    }
}
