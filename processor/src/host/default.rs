use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Felt, Word,
    deferred::{DeferredError, DeferredTag, Payload, TagKind},
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
    ProcessorState, SyncHost, TraceError,
    advice::AdviceMutation,
    deferred::{
        DeferredState, EVENT_ASSERT_EQ, EVENT_REGISTER_LEAF, EVENT_REGISTER_OP, Field0Handler,
        TypeHandlerRegistry, assert_eq as deferred_assert_eq, register_node,
    },
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
    deferred_state: DeferredState,
    deferred_registry: TypeHandlerRegistry,
    deferred_event_ids: DeferredEventIds,
}

/// Cached event IDs for the three deferred system events. Computed once at host construction
/// so [`DefaultHost::on_event`] can fast-path the intercept check.
#[derive(Debug, Clone, Copy)]
struct DeferredEventIds {
    register_leaf: EventId,
    register_op: EventId,
    assert_eq: EventId,
}

impl DeferredEventIds {
    fn new() -> Self {
        Self {
            register_leaf: EventId::from_name(EVENT_REGISTER_LEAF),
            register_op: EventId::from_name(EVENT_REGISTER_OP),
            assert_eq: EventId::from_name(EVENT_ASSERT_EQ),
        }
    }
}

impl Default for DefaultHost {
    fn default() -> Self {
        let mut deferred_registry = TypeHandlerRegistry::new();
        // Registering Field0Handler can only fail on a duplicate prefix, which is impossible
        // on a fresh registry — unwrap is sound here.
        deferred_registry
            .register(Arc::new(Field0Handler))
            .expect("Field0Handler registration on empty registry");

        Self {
            store: MemMastForestStore::default(),
            event_handlers: EventHandlerRegistry::default(),
            debug_handler: DefaultDebugHandler::default(),
            source_manager: Arc::new(DefaultSourceManager::default()),
            deferred_state: DeferredState::new(),
            deferred_registry,
            deferred_event_ids: DeferredEventIds::new(),
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
            deferred_state: self.deferred_state,
            deferred_registry: self.deferred_registry,
            deferred_event_ids: self.deferred_event_ids,
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
            deferred_state: self.deferred_state,
            deferred_registry: self.deferred_registry,
            deferred_event_ids: self.deferred_event_ids,
        }
    }

    /// Returns a reference to the [`DebugHandler`], useful for recovering debug information
    /// emitted during a program execution.
    pub fn debug_handler(&self) -> &D {
        &self.debug_handler
    }

    /// Returns a read-only view of the deferred-DAG state populated by the three deferred
    /// system events.
    pub fn deferred_state(&self) -> &DeferredState {
        &self.deferred_state
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

        // Intercept the three deferred system events. We bypass EventHandlerRegistry here
        // because EventHandler::on_event takes &self, which would force the deferred state and
        // type-handler registry behind interior-mutability primitives that aren't available in
        // no_std. The plan flagged this contingency; mirrors how the VM intercepts SystemEvents.
        let ids = self.deferred_event_ids;
        if event_id == ids.register_leaf {
            return self.handle_register_node(process, TagKind::Leaf);
        }
        if event_id == ids.register_op {
            return self.handle_register_node(process, TagKind::BinaryOp);
        }
        if event_id == ids.assert_eq {
            return self.handle_assert_eq(process);
        }

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

// DEFERRED EVENT DISPATCH HELPERS
// ================================================================================================

impl<D, S> DefaultHost<D, S>
where
    D: DebugHandler,
    S: SourceManager,
{
    fn handle_register_node(
        &mut self,
        process: &ProcessorState<'_>,
        expected_kind: TagKind,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        let tag = read_tag(process, 1)?;
        let payload = read_payload(process, 5);

        register_node(
            &mut self.deferred_state,
            &self.deferred_registry,
            tag,
            payload,
            expected_kind,
        )
        .map_err(deferred_error_to_event_error)?;

        Ok(Vec::new())
    }

    fn handle_assert_eq(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        let tag = read_tag(process, 1)?;
        let lhs_digest = read_digest(process, 5);
        let rhs_digest = read_digest(process, 9);

        deferred_assert_eq(
            &mut self.deferred_state,
            &self.deferred_registry,
            tag,
            lhs_digest,
            rhs_digest,
        )
        .map_err(deferred_error_to_event_error)?;
        Ok(Vec::new())
    }
}

fn read_tag(process: &ProcessorState<'_>, start: usize) -> Result<DeferredTag, EventError> {
    let felts: [Felt; 4] = core::array::from_fn(|i| process.get_stack_item(start + i));
    DeferredTag::from_felts(felts).map_err(deferred_error_to_event_error)
}

fn read_payload(process: &ProcessorState<'_>, start: usize) -> Payload {
    let felts: [Felt; 8] = core::array::from_fn(|i| process.get_stack_item(start + i));
    Payload::new(felts)
}

fn read_digest(process: &ProcessorState<'_>, start: usize) -> Word {
    let felts: [Felt; 4] = core::array::from_fn(|i| process.get_stack_item(start + i));
    Word::new(felts)
}

fn deferred_error_to_event_error(err: DeferredError) -> EventError {
    #[derive(Debug, thiserror::Error)]
    #[error("deferred event failed: {0:?}")]
    struct Wrapped(DeferredError);
    Wrapped(err).into()
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
