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
    ExtendStack { iter: Vec<Felt> },
    ExtendMap { other: AdviceMap },
    ExtendMerkleStore { iter: Vec<InnerNodeInfo> },
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

    // Note: we don't use the `async` keyword in both of these methods, since we need to specify the
    // `+ Send` bound to the returned Future, and `async` doesn't allow us to do that.

    /// Returns MAST forest corresponding to the specified digest, or None if the MAST forest for
    /// this digest could not be found in this [AsyncHost].
    fn get_mast_forest(
        &self,
        node_digest: &Word,
    ) -> impl Future<Output = Option<Arc<MastForest>>> + Send;

    /// Handles the event emitted from the VM and provides advice mutations to be applied to
    /// the advice provider.
    fn on_event(
        &mut self,
        process: &ProcessState<'_>,
        event_id: u32,
    ) -> impl Future<Output = Result<Vec<AdviceMutation>, EventError>> + Send;
}
