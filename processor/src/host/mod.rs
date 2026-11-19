use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{error::Error, future::Future};

use miden_core::{
    Felt, Word,
    advice::{AdviceMap, AdviceStack},
    crypto::merkle::InnerNodeInfo,
    events::{EventId, EventName},
};
use miden_debug_types::{Location, SourceFile, SourceSpan};

use crate::ProcessorState;

pub(super) mod advice;

pub mod debug;

pub mod default;

pub mod handlers;
use handlers::{EventError, TraceError};

mod mast_forest_store;
pub use mast_forest_store::{LoadedMastForest, MastForestStore, MemMastForestStore};

/// An error returned when a host cannot retrieve a MAST forest.
pub type MastForestLoadError = Box<dyn Error + Send + Sync + 'static>;

// ADVICE MAP MUTATIONS
// ================================================================================================

/// Any possible way an event can modify the advice provider.
#[derive(Debug, PartialEq, Eq)]
pub enum AdviceMutation {
    ExtendStack { stack: AdviceStack },
    ExtendMap { map: AdviceMap },
    ExtendMerkleStore { inner_nodes: Vec<InnerNodeInfo> },
}

impl AdviceMutation {
    pub fn extend_advice_stack(stack: AdviceStack) -> Self {
        Self::ExtendStack { stack }
    }

    /// Extends the advice stack with `elements`, ordered from the top of the stack down.
    ///
    /// The typed [`AdviceMutation::extend_advice_stack`] is the one to reach for when the caller
    /// already holds an [`AdviceStack`], or needs its element/word/dword layout helpers. This one
    /// covers the common case of a host reply that is just a handful of field elements, which
    /// would otherwise have to build an [`AdviceStack`] only to hand it straight over.
    pub fn extend_advice_stack_with(elements: impl IntoIterator<Item = Felt>) -> Self {
        Self::ExtendStack { stack: elements.into_iter().collect() }
    }

    pub fn extend_map(map: AdviceMap) -> Self {
        Self::ExtendMap { map }
    }

    pub fn extend_merkle_store(inner_nodes: impl IntoIterator<Item = InnerNodeInfo>) -> Self {
        Self::ExtendMerkleStore { inner_nodes: Vec::from_iter(inner_nodes) }
    }
}
// HOST TRAIT
// ================================================================================================

/// Defines the host functionality shared by both sync and async execution.
///
/// There are two main categories of interactions between the VM and the host:
/// 1. getting a library's MAST forest,
/// 2. handling VM events (regular events can mutate the process' advice provider, while trace
///    events are read-only),
pub trait BaseHost {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`SourceSpan`] and optional [`SourceFile`] for the provided location.
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>);

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`EventName`] registered for the provided [`EventId`], if any.
    ///
    /// Hosts that maintain an event registry can override this method to surface human-readable
    /// names for diagnostics. The default implementation returns `None`.
    fn resolve_event(&self, _event_id: EventId) -> Option<&EventName> {
        None
    }

    /// Returns the [`EventName`] registered for the provided trace [`EventId`], if any.
    ///
    /// Hosts that maintain an trace handler registry can override this method to surface
    /// human-readable names for diagnostics. The default implementation returns `None`.
    fn resolve_trace(&self, _trace_id: EventId) -> Option<&EventName> {
        None
    }
}

impl<T: BaseHost + ?Sized> BaseHost for &mut T {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (**self).get_label_and_source_file(location)
    }

    fn resolve_event(&self, event_id: EventId) -> Option<&EventName> {
        (**self).resolve_event(event_id)
    }

    fn resolve_trace(&self, trace_id: EventId) -> Option<&EventName> {
        (**self).resolve_trace(trace_id)
    }
}

/// Defines a synchronous interface by which the VM can interact with the host during execution.
pub trait SyncHost: BaseHost {
    /// Returns the forest for the requested procedure root.
    ///
    /// `Ok(None)` means the procedure was not found. `Err` preserves a retrieval failure.
    fn get_mast_forest(
        &self,
        node_digest: &Word,
    ) -> Result<Option<LoadedMastForest>, MastForestLoadError>;

    /// Handles the event emitted from the VM and provides advice mutations to be applied to
    /// the advice provider.
    ///
    /// The event ID is available at the top of the stack (position 0) when this handler is called.
    /// This allows the handler to access both the event ID and any additional context data that
    /// may have been pushed onto the stack prior to the emit operation.
    ///
    /// ## Implementation notes
    /// - Extract the event ID via `EventId::from_felt(process.get_stack_item(0))`
    /// - Return errors without event names or IDs - the caller will enrich them via
    ///   [`BaseHost::resolve_event()`]
    /// - System events are handled by the VM before and don't call this method
    fn on_event(&mut self, process: &ProcessorState<'_>)
    -> Result<Vec<AdviceMutation>, EventError>;

    /// Handles a trace event emitted from the VM.
    ///
    /// Trace events are optional, read-only events. [`SystemEvent::TraceEvent`] is at stack
    /// position 0 and the user trace event ID is at position 1 when this handler is called. The
    /// handler cannot mutate the advice provider. Hosts that do not care about trace events can use
    /// this default no-op implementation. Hosts are expected not to raise an error on encountering
    /// a trace event for which no handler is registered.
    ///
    /// Return errors without event names or IDs - the caller will enrich them via
    /// [`BaseHost::resolve_trace()`].
    ///
    /// [`SystemEvent::TraceEvent`]: miden_core::events::SystemEvent::TraceEvent
    fn on_trace(&mut self, _process: &ProcessorState<'_>) -> Result<(), TraceError> {
        Ok(())
    }
}

/// Defines an async interface by which the VM can interact with the host during execution.
///
/// This mirrors the historic async host surface while allowing the sync-first core to depend on
/// [`BaseHost`].
/// # Example
///
/// Return retrieval errors from the host, then inspect their source after execution.
///
/// ```
/// use miden_processor::{
///     BaseHost, FastProcessor, FutureMaybeSend, Host,
///     LoadedMastForest, MastForestLoadError, ProcessorError, ProcessorState, StackInputs, Word,
///     advice::AdviceMutation, event::EventError,
/// };
/// # use std::sync::Arc;
/// # use miden_debug_types::{Location, SourceFile, SourceSpan};
///
/// struct DatabaseHost;
/// # impl BaseHost for DatabaseHost {
/// #     fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
/// #         (SourceSpan::UNKNOWN, None)
/// #     }
/// # }
///
/// impl Host for DatabaseHost {
///     fn get_mast_forest(&self, _root: &Word)
///         -> impl FutureMaybeSend<Result<Option<LoadedMastForest>, MastForestLoadError>> {
///         async { Err(std::io::Error::other("database unavailable").into()) }
///     }
/// #     fn on_event(&mut self, _: &ProcessorState<'_>)
/// #         -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
/// #         async { Ok(Vec::new()) }
/// #     }
/// }
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// # let program = miden_assembly::Assembler::default()
/// #     .assemble_program("program", "begin dynexec end").unwrap().unwrap_program();
/// let mut host = DatabaseHost;
/// let error = FastProcessor::new(StackInputs::default())
///     .execute(&program, &mut host).await.unwrap_err();
/// let ProcessorError::MastForestLoad { source, .. } = error.kind() else {
///     panic!("expected the database error");
/// };
/// assert_eq!(
///     source.downcast_ref::<std::io::Error>().unwrap().to_string(),
///     "database unavailable",
/// );
/// # }
/// ```
pub trait Host: BaseHost {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the forest for the requested procedure root.
    ///
    /// `Ok(None)` means the procedure was not found. `Err` preserves a retrieval failure.
    ///
    /// # Cancellation safety
    ///
    /// Dropping a pending lookup must leave shared host and datastore state valid and permit
    /// another lookup without losing stored forests. Implementations must arrange any required
    /// cleanup before affected resources are reused.
    fn get_mast_forest(
        &self,
        node_digest: &Word,
    ) -> impl FutureMaybeSend<Result<Option<LoadedMastForest>, MastForestLoadError>>;

    /// Handles the event emitted from the VM and provides advice mutations to be applied to
    /// the advice provider.
    ///
    /// The event ID is available at the top of the stack (position 0) when this handler is called.
    /// This allows the handler to access both the event ID and any additional context data that
    /// may have been pushed onto the stack prior to the emit operation.
    ///
    /// ## Implementation notes
    /// - Extract the event ID via `EventId::from_felt(process.get_stack_item(0))`
    /// - Return errors without event names or IDs - the caller will enrich them via
    ///   [`BaseHost::resolve_event()`]
    /// - System events are handled by the VM before and don't call this method
    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>>;

    /// Handles a trace event emitted from the VM.
    ///
    /// Trace events are optional, read-only events. [`SystemEvent::TraceEvent`] is at stack
    /// position 0 and the user trace event ID is at position 1 when this handler is called. The
    /// handler cannot mutate the advice provider. Hosts that do not care about trace events can use
    /// this default no-op implementation. Hosts are expected not to raise an error on encountering
    /// a trace event for which no handler is registered.
    ///
    /// Return errors without event names or IDs - the caller will enrich them via
    /// [`BaseHost::resolve_trace()`].
    ///
    /// [`SystemEvent::TraceEvent`]: miden_core::events::SystemEvent::TraceEvent
    fn on_trace(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<(), TraceError>> {
        async move { Ok(()) }
    }
}

impl<T> Host for T
where
    T: SyncHost,
{
    fn get_mast_forest(
        &self,
        node_digest: &Word,
    ) -> impl FutureMaybeSend<Result<Option<LoadedMastForest>, MastForestLoadError>> {
        let result = SyncHost::get_mast_forest(self, node_digest);
        async move { result }
    }

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        let result = SyncHost::on_event(self, process);
        async move { result }
    }

    fn on_trace(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<(), TraceError>> {
        let result = SyncHost::on_trace(self, process);
        async move { result }
    }
}

/// Alias for a `Future`
///
/// Unless the compilation target family is `wasm`, we add `Send` to the required bounds. For
/// `wasm` compilation targets there is no `Send` bound.
#[cfg(target_family = "wasm")]
pub trait FutureMaybeSend<O>: Future<Output = O> {}

#[cfg(target_family = "wasm")]
impl<T, O> FutureMaybeSend<O> for T where T: Future<Output = O> {}

/// Alias for a `Future`
///
/// Unless the compilation target family is `wasm`, we add `Send` to the required bounds. For
/// `wasm` compilation targets there is no `Send` bound.
#[cfg(not(target_family = "wasm"))]
pub trait FutureMaybeSend<O>: Future<Output = O> + Send {}

#[cfg(not(target_family = "wasm"))]
impl<T, O> FutureMaybeSend<O> for T where T: Future<Output = O> + Send {}

#[cfg(test)]
mod tests {
    use super::{AdviceMutation, AdviceStack, Felt};

    /// The iterator helper must be indistinguishable from building the stack by hand, so that a
    /// handler can switch to it without changing what the VM sees.
    ///
    /// Driven from a lazy `Map` rather than a collection, since taking any `IntoIterator` is the
    /// point of the helper.
    #[test]
    fn extend_advice_stack_with_matches_the_typed_helper() {
        let mut stack = AdviceStack::new();
        stack.append_elements((1..=3u32).map(Felt::from_u32));

        assert_eq!(
            AdviceMutation::extend_advice_stack_with((1..=3u32).map(Felt::from_u32)),
            AdviceMutation::extend_advice_stack(stack)
        );
    }
}
