use alloc::{sync::Arc, vec::Vec};

use miden_core::{DebugOptions, EventId, EventName, Felt, Word, mast::MastForest};
use miden_debug_types::{
    DefaultSourceManager, Location, SourceFile, SourceManager, SourceManagerSync, SourceSpan,
};

use crate::{
    AdviceMutation, AsyncHost, BaseHost, DebugHandler, EventHandler, EventHandlerRegistry,
    ExecutionError, MastForestStore, MemMastForestStore, ProcessState, SyncHost,
    host::{EventError, FutureMaybeSend, debug::DefaultDebugHandler},
};

// DEFAULT HOST IMPLEMENTATION
// ================================================================================================

/// A default Host implementation that provides the essential functionality required by the VM.
#[derive(Debug)]
pub struct DefaultHost<
    D: DebugHandler = DefaultDebugHandler,
    S: SourceManager = DefaultSourceManager,
> {
    store: MemMastForestStore,
    event_handlers: EventHandlerRegistry,
    debug_handler: D,
    source_manager: Arc<S>,
}

impl Default for DefaultHost {
    fn default() -> Self {
        Self {
            store: MemMastForestStore::default(),
            event_handlers: EventHandlerRegistry::default(),
            debug_handler: DefaultDebugHandler::default(),
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }
}

impl<D, S> DefaultHost<D, S>
where
    D: DebugHandler,
    S: SourceManager,
{
    /// Use the given source manager implementation instead of the default one
    /// [`DefaultSourceManager`].
    pub fn with_source_manager<O>(self, source_manager: Arc<O>) -> DefaultHost<D, O>
    where
        O: SourceManager,
    {
        DefaultHost::<D, O> {
            store: self.store,
            event_handlers: self.event_handlers,
            debug_handler: self.debug_handler,
            source_manager,
        }
    }

    /// Loads a [`HostLibrary`] containing a [`MastForest`] with its list of event handlers.
    pub fn load_library(&mut self, library: impl Into<HostLibrary>) -> Result<(), ExecutionError> {
        let library = library.into();
        self.store.insert(library.mast_forest);

        for (event, handler) in library.handlers {
            self.event_handlers.register(event, handler)?;
        }
        Ok(())
    }

    /// Adds a [`HostLibrary`] containing a [`MastForest`] with its list of event handlers.
    /// to the host.
    pub fn with_library(mut self, library: impl Into<HostLibrary>) -> Result<Self, ExecutionError> {
        self.load_library(library)?;
        Ok(self)
    }

    /// Registers a single [`EventHandler`] into this host.
    ///
    /// The handler can be either a closure or a free function with signature
    /// `fn(&mut ProcessState) -> Result<(), EventHandler>`
    pub fn register_handler(
        &mut self,
        event: EventName,
        handler: Arc<dyn EventHandler>,
    ) -> Result<(), ExecutionError> {
        self.event_handlers.register(event, handler)
    }

    /// Un-registers a handler with the given id, returning a flag indicating whether a handler
    /// was previously registered with this id.
    pub fn unregister_handler(&mut self, id: EventId) -> bool {
        self.event_handlers.unregister(id)
    }

    /// Replaces a handler with the given event, returning a flag indicating whether a handler
    /// was previously registered with this event ID.
    pub fn replace_handler(&mut self, event: EventName, handler: Arc<dyn EventHandler>) -> bool {
        let event_id = event.to_event_id();
        let existed = self.event_handlers.unregister(event_id);
        self.register_handler(event, handler).unwrap();
        existed
    }

    /// Replace the current [`DebugHandler`] with a custom one.
    pub fn with_debug_handler<H: DebugHandler>(self, handler: H) -> DefaultHost<H, S> {
        DefaultHost::<H, S> {
            store: self.store,
            event_handlers: self.event_handlers,
            debug_handler: handler,
            source_manager: self.source_manager,
        }
    }

    /// Returns a reference to the [`DebugHandler`], useful for recovering debug information
    /// emitted during a program execution.
    pub fn debug_handler(&self) -> &D {
        &self.debug_handler
    }
}

impl<D, S> BaseHost for DefaultHost<D, S>
where
    D: DebugHandler,
    S: SourceManager,
{
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }

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

    fn resolve_event(&self, event_id: EventId) -> Option<&EventName> {
        self.event_handlers.resolve_event(event_id)
    }
}

impl<D, S> SyncHost for DefaultHost<D, S>
where
    D: DebugHandler,
    S: SourceManager,
{
    fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>> {
        self.store.get(node_digest)
    }

    fn on_event(&mut self, process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
        let event_id = EventId::from_felt(process.get_stack_item(0));
        if let Some(mutations) = self.event_handlers.handle_event(event_id, process)? {
            // the event was handled by the registered event handlers; just return
            return Ok(mutations);
        }

        // EventError is a `Box<dyn Error>` so we can define the error anonymously.
        #[derive(Debug, thiserror::Error)]
        #[error("no event handler registered")]
        struct UnhandledEvent;

        Err(UnhandledEvent.into())
    }
}

impl<D, S> AsyncHost for DefaultHost<D, S>
where
    D: DebugHandler,
    S: SourceManagerSync,
{
    fn get_mast_forest(&self, node_digest: &Word) -> impl FutureMaybeSend<Option<Arc<MastForest>>> {
        let result = <Self as SyncHost>::get_mast_forest(self, node_digest);
        async move { result }
    }

    fn on_event(
        &mut self,
        process: &ProcessState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        let result = <Self as SyncHost>::on_event(self, process);
        async move { result }
    }
}

// NOOPHOST
// ================================================================================================

/// A Host which does nothing.
pub struct NoopHost;

impl BaseHost for NoopHost {
    #[inline(always)]
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl SyncHost for NoopHost {
    #[inline(always)]
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<Arc<MastForest>> {
        None
    }

    #[inline(always)]
    fn on_event(&mut self, _process: &ProcessState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

impl AsyncHost for NoopHost {
    #[inline(always)]
    fn get_mast_forest(
        &self,
        _node_digest: &Word,
    ) -> impl FutureMaybeSend<Option<Arc<MastForest>>> {
        async { None }
    }

    #[inline(always)]
    fn on_event(
        &mut self,
        _process: &ProcessState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        async { Ok(Vec::new()) }
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
    /// List of handlers along with their event names to call them with `emit`.
    pub handlers: Vec<(EventName, Arc<dyn EventHandler>)>,
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
