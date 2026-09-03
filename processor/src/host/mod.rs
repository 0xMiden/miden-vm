use alloc::{sync::Arc, vec::Vec};
use core::future::Future;

use miden_core::{
    Word,
    events::{EventId, EventName},
};
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_event_handler::{AdviceMutation, EventContext, EventError, TraceError};

pub(super) mod advice;

pub mod debug;

pub mod default;

pub mod handlers;

mod mast_forest_store;
pub use mast_forest_store::{LoadedMastForest, MastForestStore, MemMastForestStore};

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
    /// Returns MAST forest corresponding to the specified digest, or None if the MAST forest for
    /// this digest could not be found in this host.
    fn get_mast_forest(&self, node_digest: &Word) -> Option<LoadedMastForest>;

    /// Handles the event emitted from the VM and provides advice mutations to be applied to
    /// the advice provider.
    ///
    /// The semantic event ID and invocation metadata are available directly from `context`.
    ///
    /// ## Implementation notes
    /// - Return errors without event names or IDs - the caller will enrich them via
    ///   [`BaseHost::resolve_event()`]
    /// - System events are handled by the VM before and don't call this method
    fn on_event(&mut self, context: &EventContext<'_>) -> Result<Vec<AdviceMutation>, EventError>;

    /// Handles a trace event emitted from the VM.
    ///
    /// Trace events are optional and read-only. The semantic trace ID is available directly from
    /// `context`; handlers do not decode its stack position. Hosts that do not care about trace
    /// events can use this default no-op implementation.
    ///
    /// Return errors without event names or IDs - the caller will enrich them via
    /// [`BaseHost::resolve_trace()`].
    ///
    /// [`SystemEvent::TraceEvent`]: miden_core::events::SystemEvent::TraceEvent
    fn on_trace(&mut self, _context: &EventContext<'_>) -> Result<(), TraceError> {
        Ok(())
    }
}

/// Defines an async interface by which the VM can interact with the host during execution.
///
/// This mirrors the historic async host surface while allowing the sync-first core to depend on
/// [`BaseHost`].
pub trait Host: BaseHost {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns MAST forest corresponding to the specified digest, or None if the MAST forest for
    /// this digest could not be found in this host.
    fn get_mast_forest(&self, node_digest: &Word)
    -> impl FutureMaybeSend<Option<LoadedMastForest>>;

    /// Handles the event emitted from the VM and provides advice mutations to be applied to
    /// the advice provider.
    ///
    /// The semantic event ID and invocation metadata are available directly from `context`.
    ///
    /// ## Implementation notes
    /// - Return errors without event names or IDs - the caller will enrich them via
    ///   [`BaseHost::resolve_event()`]
    /// - System events are handled by the VM before and don't call this method
    fn on_event(
        &mut self,
        context: &EventContext<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>>;

    /// Handles a trace event emitted from the VM.
    ///
    /// Trace events are optional and read-only. The semantic trace ID is available directly from
    /// `context`; handlers do not decode its stack position.
    ///
    /// Return errors without event names or IDs - the caller will enrich them via
    /// [`BaseHost::resolve_trace()`].
    ///
    /// [`SystemEvent::TraceEvent`]: miden_core::events::SystemEvent::TraceEvent
    fn on_trace(
        &mut self,
        _context: &EventContext<'_>,
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
    ) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
        let result = SyncHost::get_mast_forest(self, node_digest);
        async move { result }
    }

    fn on_event(
        &mut self,
        context: &EventContext<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        let result = SyncHost::on_event(self, context);
        async move { result }
    }

    fn on_trace(
        &mut self,
        context: &EventContext<'_>,
    ) -> impl FutureMaybeSend<Result<(), TraceError>> {
        let result = SyncHost::on_trace(self, context);
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
    use miden_core::{Felt, advice::AdviceStack};
    use miden_event_handler::AdviceMutation;

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
