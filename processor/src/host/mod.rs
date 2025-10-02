use alloc::{sync::Arc, vec::Vec};
use core::future::Future;

use miden_core::{
    AdviceMap, DebugOptions, Felt, Word, crypto::merkle::InnerNodeInfo, mast::MastForest,
};
use miden_debug_types::{Location, SourceFile, SourceSpan};

use crate::{EventError, ExecutionError, ProcessState};

pub(super) mod advice;

pub mod debug;

pub mod default;

pub mod handlers;
use handlers::DebugHandler;

mod mast_forest_store;
pub use mast_forest_store::{MastForestStore, MemMastForestStore};

// ADVICE MAP MUTATIONS
// ================================================================================================

/// Any possible way an event can modify the advice map
#[derive(Debug, PartialEq, Eq)]
pub enum AdviceMutation {
    ExtendStack { values: Vec<Felt> },
    ExtendMap { other: AdviceMap },
    ExtendMerkleStore { infos: Vec<InnerNodeInfo> },
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
}
// HOST TRAIT
// ================================================================================================

/// Defines the common interface between [SyncHost] and [AsyncHost], by which the VM can interact
/// with the host.
///
/// There are three main categories of interactions between the VM and the host:
/// 1. getting a library's MAST forest,
/// 2. handling VM events (which can mutate the process' advice provider), and
/// 3. handling debug and trace events.
pub trait BaseHost {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`SourceSpan`] and optional [`SourceFile`] for the provided location.
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>);

    /// Handles the debug request from the VM.
    fn on_debug(
        &mut self,
        process: &mut ProcessState,
        options: &DebugOptions,
    ) -> Result<(), ExecutionError> {
        let mut handler = debug::DefaultDebugHandler::default();
        handler.on_debug(process, options)
    }

    /// Handles the trace emitted from the VM.
    fn on_trace(
        &mut self,
        process: &mut ProcessState,
        trace_id: u32,
    ) -> Result<(), ExecutionError> {
        let mut handler = debug::DefaultDebugHandler::default();
        handler.on_trace(process, trace_id)
    }

    /// Handles the failure of the assertion instruction.
    fn on_assert_failed(&mut self, _process: &ProcessState, _err_code: Felt) {}
}

/// Defines an interface by which the VM can interact with the host.
///
/// There are four main categories of interactions between the VM and the host:
/// 1. accessing the advice provider,
/// 2. getting a library's MAST forest,
/// 3. handling VM events (which can mutate the process' advice provider), and
/// 4. handling debug and trace events.
pub trait SyncHost: BaseHost {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns MAST forest corresponding to the specified digest, or None if the MAST forest for
    /// this digest could not be found in this host.
    fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>>;

    /// Invoked when the VM encounters an `EMIT` operation.
    ///
    /// The event ID is available at the top of the stack (position 0) when this handler is called.
    /// This allows the handler to access both the event ID and any additional context data that
    /// may have been pushed onto the stack prior to the emit operation.
    fn on_event(&mut self, process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError>;
}

// ASYNC HOST trait
// ================================================================================================

/// Analogous to the [SyncHost] trait, but designed for asynchronous execution contexts.
pub trait AsyncHost: BaseHost {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    // Note: we don't use the `async` keyword in this method, since we need to specify the `+ Send`
    // bound to the returned Future, and `async` doesn't allow us to do that.

    /// Returns MAST forest corresponding to the specified digest, or None if the MAST forest for
    /// this digest could not be found in this host.
    fn get_mast_forest(&self, node_digest: &Word) -> impl FutureMaybeSend<Option<Arc<MastForest>>>;

    /// Handles the event emitted from the VM and provides advice mutations to be applied to
    /// the advice provider.
    ///
    /// The event ID is available at the top of the stack (position 0) when this handler is called.
    /// This allows the handler to access both the event ID and any additional context data that
    /// may have been pushed onto the stack prior to the emit operation.
    fn on_event(
        &mut self,
        process: &ProcessState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>>;
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
