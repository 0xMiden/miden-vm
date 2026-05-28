use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Word,
    deferred::PrecompileRegistry,
    events::{EventId, EventName},
    mast::MastForest,
    operations::DebugOptions,
};
use miden_debug_types::{DefaultSourceManager, Location, SourceFile, SourceManager, SourceSpan};

use super::{
    debug::DefaultDebugHandler,
    handlers::{EventError, EventHandler, EventHandlerRegistry},
};
use crate::{
    BaseHost, DebugError, DebugHandler, ExecutionError, MastForestStore, MemMastForestStore,
    ProcessorState, SyncHost, TraceError, advice::AdviceMutation,
};

// DEFAULT HOST IMPLEMENTATION
// ================================================================================================

/// A default SyncHost implementation that provides the essential functionality required by the VM.
#[derive(Debug)]
pub struct DefaultHost<
    D: DebugHandler = DefaultDebugHandler,
    S: SourceManager = DefaultSourceManager,
> {
    store: MemMastForestStore,
    event_handlers: EventHandlerRegistry,
    debug_handler: D,
    source_manager: Arc<S>,
    precompiles: Arc<PrecompileRegistry>,
}

impl Default for DefaultHost {
    fn default() -> Self {
        Self {
            store: MemMastForestStore::default(),
            event_handlers: EventHandlerRegistry::default(),
            debug_handler: DefaultDebugHandler::default(),
            source_manager: Arc::new(DefaultSourceManager::default()),
            precompiles: Arc::new(PrecompileRegistry::default()),
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
            precompiles: self.precompiles,
        }
    }

    /// Loads a [`HostLibrary`] containing a [`MastForest`], event handlers, and deferred
    /// precompiles.
    ///
    /// Library precompiles are merged into the host's existing registry rather than replacing it.
    pub fn load_library(&mut self, library: impl Into<HostLibrary>) -> Result<(), ExecutionError> {
        let HostLibrary { mast_forest, handlers, precompiles } = library.into();

        self.store.insert(mast_forest);

        for (event, handler) in handlers {
            self.event_handlers.register(event, handler)?;
        }

        if !precompiles.is_empty() {
            Arc::make_mut(&mut self.precompiles).merge(precompiles);
        }

        Ok(())
    }

    /// Adds a [`HostLibrary`] containing a [`MastForest`] with its list of event handlers.
    /// to the host.
    pub fn with_library(mut self, library: impl Into<HostLibrary>) -> Result<Self, ExecutionError> {
        self.load_library(library)?;
        Ok(self)
    }

    /// Replaces the deferred precompile registry installed in this host.
    pub fn with_precompiles(mut self, precompiles: Arc<PrecompileRegistry>) -> Self {
        self.precompiles = precompiles;
        self
    }

    /// Registers a single [`EventHandler`] into this host.
    ///
    /// The handler can be either a closure or a free function with signature
    /// `fn(&mut ProcessorState) -> Result<(), EventHandler>`
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
            precompiles: self.precompiles,
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
        process: &ProcessorState,
        options: &DebugOptions,
    ) -> Result<(), DebugError> {
        self.debug_handler.on_debug(process, options)
    }

    fn on_trace(&mut self, process: &ProcessorState, trace_id: u32) -> Result<(), TraceError> {
        self.debug_handler.on_trace(process, trace_id)
    }

    fn precompiles(&self) -> &PrecompileRegistry {
        &self.precompiles
    }

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

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        let event_id = EventId::from_felt(process.get_stack_item(0));

        match self.event_handlers.handle_event(event_id, process) {
            Ok(Some(mutations)) => Ok(mutations),
            Ok(None) => {
                #[derive(Debug, thiserror::Error)]
                #[error("no event handler registered")]
                struct UnhandledEvent;

                Err(UnhandledEvent.into())
            },
            Err(e) => Err(e),
        }
    }
}

// NOOPHOST
// ================================================================================================

/// A SyncHost which does nothing.
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
    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

// HOST LIBRARY
// ================================================================================================

/// A rich library representing a [`MastForest`] which also exports event handlers and deferred
/// precompiles required by procedures in that forest.
#[derive(Default)]
pub struct HostLibrary {
    /// A `MastForest` with procedures exposed by this library.
    pub mast_forest: Arc<MastForest>,
    /// List of handlers along with their event names to call them with `emit`.
    pub handlers: Vec<(EventName, Arc<dyn EventHandler>)>,
    /// Deferred precompile registry required by this library's system-event wrappers.
    pub precompiles: PrecompileRegistry,
}

impl From<Arc<MastForest>> for HostLibrary {
    fn from(mast_forest: Arc<MastForest>) -> Self {
        Self {
            mast_forest,
            handlers: vec![],
            precompiles: PrecompileRegistry::default(),
        }
    }
}

impl From<&Arc<MastForest>> for HostLibrary {
    fn from(mast_forest: &Arc<MastForest>) -> Self {
        Self {
            mast_forest: mast_forest.clone(),
            handlers: vec![],
            precompiles: PrecompileRegistry::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_core::{
        Felt, ZERO,
        deferred::{Node, NodeType, Payload, Precompile, PrecompileError, Tag, WitnessBuilder},
    };

    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct Fixture {
        name: &'static str,
    }

    impl Fixture {
        fn new(name: &'static str) -> Self {
            Self { name }
        }

        fn tag(&self) -> Tag {
            Tag { id: self.id(), args: [ZERO; 3] }
        }
    }

    impl Precompile for Fixture {
        fn name(&self) -> &'static str {
            self.name
        }

        fn id(&self) -> Felt {
            miden_core::deferred::precompile_id(self)
        }

        fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
            if args != [ZERO; 3] {
                return None;
            }
            Some(NodeType::Value)
        }

        fn reduce(
            &self,
            args: [Felt; 3],
            payload: &Payload,
            _witness: &mut WitnessBuilder<'_>,
        ) -> Result<Node, PrecompileError> {
            let felts = payload.as_felts()?;
            Ok(Node::leaf(Tag::new(self.id(), args), *felts))
        }
    }

    fn library_with_precompile(precompile: Fixture) -> HostLibrary {
        HostLibrary {
            mast_forest: Arc::new(MastForest::new()),
            handlers: vec![],
            precompiles: PrecompileRegistry::default().with_precompile(precompile),
        }
    }

    #[test]
    fn load_library_extends_existing_precompiles() {
        let a = Fixture::new("host-a");
        let b = Fixture::new("host-b");
        let tag_a = a.tag();
        let tag_b = b.tag();
        let installed = Arc::new(PrecompileRegistry::default().with_precompile(a));
        let mut host = DefaultHost::default().with_precompiles(installed.clone());

        host.load_library(library_with_precompile(b)).unwrap();

        let host_precompiles = BaseHost::precompiles(&host);
        assert!(matches!(host_precompiles.decode(tag_a).unwrap(), NodeType::Value));
        assert!(matches!(host_precompiles.decode(tag_b).unwrap(), NodeType::Value));
        assert!(matches!(installed.decode(tag_b), Err(PrecompileError::InvalidNode)));
    }
}
