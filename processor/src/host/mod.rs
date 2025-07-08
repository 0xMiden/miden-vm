use alloc::sync::Arc;
use core::future::Future;

use vm_core::{DebugOptions, Felt, Word, mast::MastForest};

use crate::{ExecutionError, ProcessState, errors::ErrorContext};

pub(super) mod advice;

#[cfg(feature = "std")]
mod debug;

mod mast_forest_store;
pub use mast_forest_store::{MastForestStore, MemMastForestStore};

// HOST TRAIT
// ================================================================================================

/// Defines the common interface between [SyncHost] and [AsyncHost], by which the VM can interact
/// with the host.
///
/// There are three main categories of interactions between the VM and the host:
/// 1. getting a library's MAST forest,
/// 2. handling advice events (which internally mutates the advice provider), and
/// 3. handling debug and trace events.
pub trait BaseHost {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Handles the debug request from the VM.
    fn on_debug(
        &mut self,
        process: &mut ProcessState,
        options: &DebugOptions,
    ) -> Result<(), ExecutionError> {
        let _ = (&process, options);
        #[cfg(feature = "std")]
        debug::print_debug_info(process, options);
        Ok(())
    }

    /// Handles the trace emitted from the VM.
    fn on_trace(
        &mut self,
        process: &mut ProcessState,
        trace_id: u32,
    ) -> Result<(), ExecutionError> {
        let _ = (&process, trace_id);
        #[cfg(feature = "std")]
        std::println!(
            "Trace with id {} emitted at step {} in context {}",
            trace_id,
            process.clk(),
            process.ctx()
        );
        Ok(())
    }

    /// Handles the failure of the assertion instruction.
    fn on_assert_failed(&mut self, _process: &mut ProcessState, _err_code: Felt) {}
}

/// Defines an interface by which the VM can interact with the host.
///
/// There are four main categories of interactions between the VM and the host:
/// 1. accessing the advice provider,
/// 2. getting a library's MAST forest,
/// 3. handling advice events (which internally mutates the advice provider), and
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
        process: &mut ProcessState,
        event_id: u32,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError>;
}

// DEFAULT HOST IMPLEMENTATION
// ================================================================================================

/// A default [BaseHost], [SyncHost] and [AsyncHost] implementation that provides the essential
/// functionality required by the VM.
#[derive(Debug, Clone, Default)]
pub struct DefaultHost {
    store: MemMastForestStore,
}

impl DefaultHost {
    pub fn load_mast_forest(&mut self, mast_forest: Arc<MastForest>) -> Result<(), ExecutionError> {
        self.store.insert(mast_forest);
        Ok(())
    }
}

impl BaseHost for DefaultHost {}

impl SyncHost for DefaultHost {
    fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>> {
        self.store.get(node_digest)
    }

    fn on_event(
        &mut self,
        process: &mut ProcessState,
        event_id: u32,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let _ = (&process, event_id, err_ctx);
        #[cfg(feature = "std")]
        std::println!(
            "Event with id {} emitted at step {} in context {}",
            event_id,
            process.clk(),
            process.ctx()
        );
        Ok(())
    }
}

impl AsyncHost for DefaultHost {
    async fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>> {
        self.store.get(node_digest)
    }

    // Note: clippy complains about this not using the `async` keyword, but if we use `async`, it
    // doesn't compile.
    #[allow(clippy::manual_async_fn)]
    fn on_event(
        &mut self,
        _process: &mut ProcessState<'_>,
        _event_id: u32,
        _err_ctx: &impl ErrorContext,
    ) -> impl Future<Output = Result<(), ExecutionError>> + Send {
        async { Ok(()) }
    }
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

    /// Handles the event emitted from the VM.
    fn on_event(
        &mut self,
        process: &mut ProcessState<'_>,
        event_id: u32,
        err_ctx: &impl ErrorContext,
    ) -> impl Future<Output = Result<(), ExecutionError>> + Send;
}
