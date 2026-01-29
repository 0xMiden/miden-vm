use alloc::{sync::Arc, vec::Vec};
use core::future::Future;

use miden_core::{
    AdviceMap, DebugOptions, EventId, EventName, Felt, Word, crypto::merkle::InnerNodeInfo,
    mast::MastForest, precompile::PrecompileRequest,
};
use miden_debug_types::{Location, SourceFile, SourceSpan};

use crate::{DebugError, EventError, ProcessorState, TraceError};

pub(super) mod advice;

pub mod debug;

pub mod default;

pub mod handlers;
use handlers::DebugHandler;

mod mast_forest_store;
pub use mast_forest_store::{MastForestStore, MemMastForestStore};

// ADVICE MAP MUTATIONS
// ================================================================================================

/// Any possible way an event can modify the advice provider.
#[derive(Debug, PartialEq, Eq)]
pub enum AdviceMutation {
    ExtendStack { values: Vec<Felt> },
    ExtendMap { other: AdviceMap },
    ExtendMerkleStore { infos: Vec<InnerNodeInfo> },
    ExtendPrecompileRequests { data: Vec<PrecompileRequest> },
}

impl AdviceMutation {
    pub fn extend_stack(iter: impl IntoIterator<Item = Felt>) -> Self {
        Self::ExtendStack { values: Vec::from_iter(iter) }
    }

    pub fn extend_map(other: AdviceMap) -> Self {
        Self::ExtendMap { other }
    }

    pub fn extend_merkle_store(infos: impl IntoIterator<Item = InnerNodeInfo>) -> Self {
        Self::ExtendMerkleStore { infos: Vec::from_iter(infos) }
    }

    pub fn extend_precompile_requests(data: impl IntoIterator<Item = PrecompileRequest>) -> Self {
        Self::ExtendPrecompileRequests { data: Vec::from_iter(data) }
    }
}
// HOST TRAIT
// ================================================================================================

/// Defines an interface by which the VM can interact with the host.
///
/// There are three main categories of interactions between the VM and the host:
/// 1. getting a library's MAST forest,
/// 2. handling VM events (which can mutate the process' advice provider), and
/// 3. handling debug and trace events.
pub trait Host {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`SourceSpan`] and optional [`SourceFile`] for the provided location.
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>);

    // Note: we don't use the `async` keyword in get_mast_forest and on_event, since we need to
    // specify the `+ Send` bound to the returned Future, and `async` doesn't allow us to do that.

    /// Returns MAST forest corresponding to the specified digest, or None if the MAST forest for
    /// this digest could not be found in this host.
    fn get_mast_forest(&self, node_digest: &Word) -> impl FutureMaybeSend<Option<Arc<MastForest>>>;

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
    ///   [`Host::resolve_event()`]
    /// - System events (IDs 0-255) are handled by the VM before calling this method
    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>>;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Handles the debug request from the VM.
    fn on_debug(
        &mut self,
        process: &mut ProcessorState,
        options: &DebugOptions,
    ) -> Result<(), DebugError> {
        let mut handler = debug::DefaultDebugHandler::default();
        handler.on_debug(process, options)
    }

    /// Handles the trace emitted from the VM.
    fn on_trace(&mut self, process: &mut ProcessorState, trace_id: u32) -> Result<(), TraceError> {
        let mut handler = debug::DefaultDebugHandler::default();
        handler.on_trace(process, trace_id)
    }

    /// Returns the [`EventName`] registered for the provided [`EventId`], if any.
    ///
    /// Hosts that maintain an event registry can override this method to surface human-readable
    /// names for diagnostics. The default implementation returns `None`.
    fn resolve_event(&self, _event_id: EventId) -> Option<&EventName> {
        None
    }
}

/// Alias for a `Future`
///
/// Unless the compilation target family is `wasm`, we add `Send` to the required bounds. For
/// `wasm` compilation targets there is no `Send` bound.
///
/// We also provide a blank implementation of this trait for all features.
#[cfg(target_family = "wasm")]
pub trait FutureMaybeSend<O>: Future<Output = O> {}

#[cfg(target_family = "wasm")]
impl<T, O> FutureMaybeSend<O> for T where T: Future<Output = O> {}

/// Alias for a `Future`
///
/// Unless the compilation target family is `wasm`, we add `Send` to the required bounds. For
/// `wasm` compilation targets there is no `Send` bound.
///
/// We also provide a blank implementation of this trait for all features.
#[cfg(not(target_family = "wasm"))]
pub trait FutureMaybeSend<O>: Future<Output = O> + Send {}

#[cfg(not(target_family = "wasm"))]
impl<T, O> FutureMaybeSend<O> for T where T: Future<Output = O> + Send {}
