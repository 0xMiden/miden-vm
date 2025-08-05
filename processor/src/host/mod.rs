use alloc::{sync::Arc, vec::Vec};
use core::future::Future;

use miden_core::{
    AdviceMap, DebugOptions, Felt, Word, crypto::merkle::InnerNodeInfo, mast::MastForest,
};
use miden_debug_types::{Location, SourceFile, SourceSpan};

use crate::{EventError, ExecutionError, ProcessState};

pub(super) mod advice;

#[cfg(feature = "std")]
mod debug;

pub mod default;
use default::DefaultDebugHandler;

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
        DefaultDebugHandler.on_debug(process, options)
    }

    /// Handles the trace emitted from the VM.
    fn on_trace(
        &mut self,
        process: &mut ProcessState,
        trace_id: u32,
    ) -> Result<(), ExecutionError> {
        DefaultDebugHandler.on_trace(process, trace_id)
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
    /// this digest could not be found in this [SyncHost].
    fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>>;

    /// Handles the event emitted from the VM.
    fn on_event(
        &mut self,
        process: &ProcessState,
        event_id: u32,
    ) -> Result<Vec<AdviceMutation>, EventError>;
}

// ASYNC HOST trait
// ================================================================================================

/// Analogous to the [SyncHost] trait, but designed for asynchronous execution contexts.
pub trait AsyncHost: BaseHost {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns MAST forest corresponding to the specified digest, or None if the MAST forest for
    /// this digest could not be found in this [AsyncHost].
    fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>>;

    // Note: we don't use the `async` keyword in both of these methods, since we need to specify the
    // `+ Send` bound to the returned Future, and `async` doesn't allow us to do that.

    /// Handles the event emitted from the VM and provides advice mutations to be applied to
    /// the advice provider.
    fn on_event(
        &mut self,
        process: &ProcessState<'_>,
        event_id: u32,
    ) -> impl AsyncHostFuture<Result<Vec<AdviceMutation>, EventError>>;
}

/// Alias for a `Future`
///
/// If feature `std` is enabled, we add `Send` to the required bounds, otherwise we do not. This
/// impacts usability with a multithreaded executor.
#[cfg(not(feature = "std"))]
pub trait AsyncHostFuture<O>: Future<Output = O> {}

#[cfg(not(feature = "std"))]
impl<T, O> AsyncHostFuture<O> for T where T: Future<Output = O> {}

#[cfg(feature = "std")]
pub trait AsyncHostFuture<O>: Future<Output = O> + Send {}

#[cfg(feature = "std")]
impl<T, O> AsyncHostFuture<O> for T where T: Future<Output = O> + Send {}
