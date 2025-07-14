use alloc::{boxed::Box, sync::Arc};

use miden_core::{DebugOptions, Felt, Word, mast::MastForest};

use crate::{
    AsyncHost, BaseHost, DebugHandler, EventHandler, EventHandlerRegistry, ExecutionError,
    HostLibrary, MastForestStore, MemMastForestStore, ProcessState, SyncHost, host::EventError,
};
// DEFAULT HOST IMPLEMENTATION
// ================================================================================================

/// A default Host implementation that provides the essential functionality required by the VM.
#[derive(Debug)]
pub struct DefaultHost<D: DebugHandler = DefaultDebugHandler> {
    store: MemMastForestStore,
    event_handlers: EventHandlerRegistry,
    debug_handler: D,
}

impl Default for DefaultHost {
    fn default() -> Self {
        Self {
            store: MemMastForestStore::default(),
            event_handlers: EventHandlerRegistry::default(),
            debug_handler: DefaultDebugHandler,
        }
    }
}

impl<D: DebugHandler> DefaultHost<D> {
    /// Stores all procedure roots of a [`MastForest`] making them available during
    /// program execution.
    pub fn load_mast_forest(&mut self, mast_forest: Arc<MastForest>) -> Result<(), ExecutionError> {
        self.store.insert(mast_forest);
        Ok(())
    }

    /// Load a library containing a [`MastForest`] and a list of event handlers.
    pub fn load_library(&mut self, library: &impl HostLibrary) -> Result<(), ExecutionError> {
        self.load_mast_forest(library.mast_forest())?;
        for (id, handler) in library.event_handlers() {
            self.event_handlers.register(id, handler)?;
        }
        Ok(())
    }

    /// Loads a single [`EventHandler`] into this host.
    ///
    /// The handler can be either a closure or a free function with signature
    /// `fn(&mut ProcessState) -> Result<(), EventHandler>`
    pub fn load_handler(
        &mut self,
        id: u32,
        handler: impl EventHandler,
    ) -> Result<(), ExecutionError> {
        self.event_handlers.register(id, Box::new(handler))
    }

    /// Replace the current [`DebugHandler`] with a custom one.
    pub fn with_debug_handler<H: DebugHandler>(self, handler: H) -> DefaultHost<H> {
        DefaultHost {
            store: self.store,
            event_handlers: self.event_handlers,
            debug_handler: handler,
        }
    }
}

impl BaseHost for DefaultHost {
    fn on_debug(
        &mut self,
        process: &mut ProcessState,
        options: &DebugOptions,
    ) -> Result<(), ExecutionError> {
        self.debug_handler.on_debug(process, options)
    }

    fn on_trace(
        &mut self,
        process: &mut ProcessState,
        trace_id: u32,
    ) -> Result<(), ExecutionError> {
        self.debug_handler.on_trace(process, trace_id)
    }

    /// Handles the failure of the assertion instruction.
    fn on_assert_failed(&mut self, _process: &mut ProcessState, _err_code: Felt) {}
}

impl SyncHost for DefaultHost {
    fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>> {
        self.store.get(node_digest)
    }

    fn on_event(&mut self, process: &mut ProcessState, event_id: u32) -> Result<(), EventError> {
        if self
            .event_handlers
            .handle_event(event_id, process)
            .map_err(|err| EventError::HandlerError { id: event_id, err })?
        {
            // the event was handled by the registered event handlers; just return
            return Ok(());
        }

        Err(EventError::UnhandledEvent { id: event_id })
    }
}

impl AsyncHost for DefaultHost {
    async fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>> {
        self.store.get(node_digest)
    }

    async fn on_event(
        &mut self,
        process: &mut ProcessState<'_>,
        event_id: u32,
    ) -> Result<(), EventError> {
        <Self as SyncHost>::on_event(self, process, event_id)
    }
}

// DEFAULT DEBUG HANDLER IMPLEMENTATION
// ================================================================================================

/// Concrete [`DebugHandler`] which re-uses the default `on_debug` and `on_trace` implementations.
#[derive(Clone, Default)]
pub struct DefaultDebugHandler;

impl DebugHandler for DefaultDebugHandler {}
