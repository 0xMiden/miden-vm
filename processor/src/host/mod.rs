use alloc::{sync::Arc, vec::Vec};
use core::future::Future;

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
use handlers::EventError;

mod mast_forest_store;
pub use mast_forest_store::{LoadedMastForest, MastForestStore, MemMastForestStore};

// ADVICE MAP MUTATIONS
// ================================================================================================

/// Any possible way an event can modify the advice provider.
#[derive(Debug, PartialEq, Eq)]
pub enum AdviceMutation {
    ExtendStack { stack: AdviceStack },
    ExtendMap { other: AdviceMap },
    ExtendMerkleStore { infos: Vec<InnerNodeInfo> },
}

impl AdviceMutation {
    pub fn extend_stack(iter: impl IntoIterator<Item = Felt>) -> Self {
        let mut stack = AdviceStack::new();
        stack.push_elements(iter);
        Self::extend_advice_stack(stack)
    }

    pub fn extend_advice_stack(stack: AdviceStack) -> Self {
        Self::ExtendStack { stack }
    }

    pub fn extend_map(other: AdviceMap) -> Self {
        Self::ExtendMap { other }
    }

    pub fn extend_merkle_store(infos: impl IntoIterator<Item = InnerNodeInfo>) -> Self {
        Self::ExtendMerkleStore { infos: Vec::from_iter(infos) }
    }
}
// HOST TRAIT
// ================================================================================================

/// Defines the host functionality shared by both sync and async execution.
///
/// There are three main categories of interactions between the VM and the host:
/// 1. getting a library's MAST forest,
/// 2. handling VM events (which can mutate the process' advice provider).
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
}

/// Defines a synchronous interface by which the VM can interact with the host during execution.
pub trait SyncHost: BaseHost {
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
    /// - System events (IDs 0-255) are handled by the VM before calling this method
    fn on_event(&mut self, process: &ProcessorState<'_>)
    -> Result<Vec<AdviceMutation>, EventError>;
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
    /// The event ID is available at the top of the stack (position 0) when this handler is called.
    /// This allows the handler to access both the event ID and any additional context data that
    /// may have been pushed onto the stack prior to the emit operation.
    ///
    /// ## Implementation notes
    /// - Extract the event ID via `EventId::from_felt(process.get_stack_item(0))`
    /// - Return errors without event names or IDs - the caller will enrich them via
    ///   [`BaseHost::resolve_event()`]
    /// - System events (IDs 0-255) are handled by the VM before calling this method
    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>>;
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
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        let result = SyncHost::on_event(self, process);
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
