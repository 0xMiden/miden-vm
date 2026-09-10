// Compatibility owner for legacy mutations and Host/SyncHost callback forwarding.
#![allow(deprecated)]

use alloc::{sync::Arc, vec::Vec};
use core::future::Future;

use miden_core::{
    Felt, Word,
    advice::{AdviceMap, AdviceStack},
    crypto::merkle::InnerNodeInfo,
    events::{EventId, EventName},
};
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_event_handler::{AdviceRecorder, EventContext};

use crate::ProcessorState;

// The engine owns raw state and recognizes this private signal only with an empty batch.
#[derive(Debug, thiserror::Error)]
#[error("host uses legacy event callbacks")]
pub(crate) struct LegacyHostFallback;

#[derive(Debug, thiserror::Error)]
#[error("no event handler registered")]
pub(crate) struct UnhandledEvent;

#[warn(deprecated)]
pub(super) mod advice;

#[warn(deprecated)]
pub mod debug;

pub mod default;

pub mod handlers;
use handlers::{EventError, TraceError};

#[warn(deprecated)]
mod mast_forest_store;
pub use mast_forest_store::{LoadedMastForest, MastForestStore, MemMastForestStore};

// ADVICE MAP MUTATIONS
// ================================================================================================

/// Any possible way an event can modify the advice provider.
#[derive(Debug, PartialEq, Eq)]
#[deprecated(note = "record output with miden_event_handler::AdviceRecorder")]
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
    /// Handles either invocation kind using pre-callback state and typed pending advice.
    /// The default asks the execution engine to invoke the existing legacy callback instead.
    fn handle_event(
        &mut self,
        _context: EventContext<'_>,
        _advice: &mut AdviceRecorder<'_>,
    ) -> Result<(), EventError> {
        Err(LegacyHostFallback.into())
    }

    /// Returns MAST forest corresponding to the specified digest, or None if the MAST forest for
    /// this digest could not be found in this host.
    fn get_mast_forest(&self, node_digest: &Word) -> Option<LoadedMastForest>;

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
    #[deprecated(note = "implement handle_event with EventContext and AdviceRecorder")]
    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        Err(UnhandledEvent.into())
    }

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
    #[deprecated(note = "implement handle_event and inspect context.kind()")]
    fn on_trace(&mut self, _process: &ProcessorState<'_>) -> Result<(), TraceError> {
        Ok(())
    }
}

/// Defines an async interface by which the VM can interact with the host during execution.
///
/// This mirrors the historic async host surface while allowing the sync-first core to depend on
/// [`BaseHost`].
pub trait Host: BaseHost {
    /// Handles either invocation kind. The engine discards pending advice on error or cancellation.
    /// The default preserves legacy callbacks; new implementations may borrow the recorder across
    /// await, subject to the native Send and relaxed Wasm future bounds.
    fn handle_event(
        &mut self,
        _context: EventContext<'_>,
        _advice: &mut AdviceRecorder<'_>,
    ) -> impl FutureMaybeSend<Result<(), EventError>> {
        async { Err(LegacyHostFallback.into()) }
    }

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns MAST forest corresponding to the specified digest, or None if the MAST forest for
    /// this digest could not be found in this host.
    fn get_mast_forest(&self, node_digest: &Word)
    -> impl FutureMaybeSend<Option<LoadedMastForest>>;

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
    #[deprecated(note = "implement handle_event with EventContext and AdviceRecorder")]
    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        async { Err(UnhandledEvent.into()) }
    }

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
    #[deprecated(note = "implement handle_event and inspect context.kind()")]
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
    fn handle_event(
        &mut self,
        context: EventContext<'_>,
        advice: &mut AdviceRecorder<'_>,
    ) -> impl FutureMaybeSend<Result<(), EventError>> {
        let result = SyncHost::handle_event(self, context, advice);
        async move { result }
    }
    fn get_mast_forest(
        &self,
        node_digest: &Word,
    ) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
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
