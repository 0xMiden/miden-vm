use alloc::{boxed::Box, sync::Arc, vec::Vec};

use miden_core::{DebugOptions, Felt, Word, mast::MastForest};

use crate::{
    AdviceMutation, AsyncHost, BaseHost, DebugHandler, EventHandler, EventHandlerRegistry,
    ExecutionError, MastForestStore, MemMastForestStore, ProcessState, SyncHost, host::EventError,
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
    /// Loads a [`HostLibrary`] containing a [`MastForest`] with its list of event handlers.
    pub fn load_library(&mut self, library: impl Into<HostLibrary>) -> Result<(), ExecutionError> {
        let library = library.into();
        self.store.insert(library.mast_forest);

        for (id, handler) in library.handlers {
            self.event_handlers.register(id, handler)?;
        }
        Ok(())
    }

    /// Adds a [`HostLibrary`] containing a [`MastForest`] with its list of event handlers.
    /// to the host.
    pub fn with_library(mut self, library: impl Into<HostLibrary>) -> Result<Self, ExecutionError> {
        self.load_library(library)?;
        Ok(self)
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

    /// Unload a handler with the given id, returning a flag indicating whether a handler
    /// was previously registered with this id.
    pub fn unload_handler(&mut self, id: u32) -> bool {
        self.event_handlers.unregister(id)
    }

    /// Replaces a handler with the given id, returning a flag indicating whether a handler
    /// was previously registered with this id.
    pub fn replace_handler(&mut self, id: u32, handler: impl EventHandler) -> bool {
        let existed = self.event_handlers.unregister(id);
        self.load_handler(id, handler).unwrap();
        existed
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
    fn on_assert_failed(&mut self, _process: &ProcessState, _err_code: Felt) {}
}

impl SyncHost for DefaultHost {
    fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>> {
        self.store.get(node_digest)
    }

    fn on_event(
        &mut self,
        process: &ProcessState,
        event_id: u32,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        if let Some(mutations) = self.event_handlers.handle_event(event_id, process)? {
            // the event was handled by the registered event handlers; just return
            return Ok(mutations);
        }

        // EventError is a `Box` so we can define the error anonymously.
        #[derive(Debug, thiserror::Error)]
        #[error("no event handler was registered with given id")]
        struct UnhandledEvent;

        Err(UnhandledEvent.into())
    }
}

impl AsyncHost for DefaultHost {
    async fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>> {
        self.store.get(node_digest)
    }

    fn on_event(
        &mut self,
        process: &ProcessState<'_>,
        event_id: u32,
    ) -> impl Future<Output = Result<Vec<AdviceMutation>, EventError>> + Send {
        let result = <Self as SyncHost>::on_event(self, process, event_id);
        async move { result }
    }
}

// HOST LIBRARY
// ================================================================================================

/// A rich library representing a [`MastForest`] which also exports
/// a list of handlers for events it may call.
#[derive(Default)]
pub struct HostLibrary {
    /// A `MastForest` with procedures exposed by this library.
    pub mast_forest: Arc<MastForest>,
    /// List of handlers along with an event id to call them with `emit`.
    pub handlers: Vec<(u32, Box<dyn EventHandler>)>,
}

impl From<Arc<MastForest>> for HostLibrary {
    fn from(mast_forest: Arc<MastForest>) -> Self {
        Self { mast_forest, handlers: vec![] }
    }
}

impl From<&Arc<MastForest>> for HostLibrary {
    fn from(mast_forest: &Arc<MastForest>) -> Self {
        Self {
            mast_forest: mast_forest.clone(),
            handlers: vec![],
        }
    }
}

// DEFAULT DEBUG HANDLER IMPLEMENTATION
// ================================================================================================

/// Concrete [`DebugHandler`] which re-uses the default `on_debug` and `on_trace` implementations.
#[derive(Clone, Default)]
pub struct DefaultDebugHandler;

impl DebugHandler for DefaultDebugHandler {}
