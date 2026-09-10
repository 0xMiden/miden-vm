use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Word,
    events::{EventId, EventName},
    mast::MastForest,
};
use miden_debug_types::{DefaultSourceManager, Location, SourceFile, SourceManager, SourceSpan};
use miden_event_handler::{AdviceRecorder, EventContext};
use miden_mast_package::{PackageDebugInfoError, debug_info::PackageDebugInfo};

use super::handlers::{
    EventError, EventHandler, EventHandlerRegistry, HandlerRegistry, TraceError, TraceHandler,
    TraceHandlerRegistry, registration,
};
use crate::{
    BaseHost, ExecutionError, LoadedMastForest, MastForestStore, MemMastForestStore,
    ProcessorState, SyncHost, advice::AdviceMutation,
};

// DEFAULT HOST IMPLEMENTATION
// ================================================================================================

/// A default SyncHost implementation that provides the essential functionality required by the VM.
#[derive(Debug)]
pub struct DefaultHost<S: SourceManager = DefaultSourceManager> {
    store: MemMastForestStore,
    handlers: HandlerRegistry,
    event_handlers: EventHandlerRegistry,
    trace_handlers: TraceHandlerRegistry,
    source_manager: Arc<S>,
}

impl Default for DefaultHost {
    fn default() -> Self {
        Self {
            store: MemMastForestStore::default(),
            handlers: HandlerRegistry::default(),
            event_handlers: EventHandlerRegistry::default(),
            trace_handlers: TraceHandlerRegistry::default(),
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }
}

impl<S> DefaultHost<S>
where
    S: SourceManager,
{
    /// Use the given source manager implementation instead of the default one
    /// [`DefaultSourceManager`].
    pub fn with_source_manager<O>(self, source_manager: Arc<O>) -> DefaultHost<O>
    where
        O: SourceManager,
    {
        DefaultHost::<O> {
            store: self.store,
            handlers: self.handlers,
            event_handlers: self.event_handlers,
            trace_handlers: self.trace_handlers,
            source_manager,
        }
    }

    /// Loads a [`HostLibrary`] containing a [`MastForest`] with its list of event handlers.
    ///
    /// The load is atomic: if one handler fails to register, the host keeps the state it had
    /// before the call. It holds no handler of the library and it does not hold the MAST forest.
    ///
    /// # Errors
    /// Returns an error when a handler of the library has an empty or reserved event name, or
    /// when its event already has a handler in this host.
    pub fn load_library(&mut self, library: impl Into<HostLibrary>) -> Result<(), ExecutionError> {
        let library = library.into();
        for (event, _) in &library.handlers {
            self.check_portable_collision(event)?;
        }

        let mut registered = Vec::with_capacity(library.handlers.len());
        for (event, handler) in library.handlers {
            let id = event.to_event_id();
            if let Err(err) = self.event_handlers.register(event, handler) {
                for id in registered {
                    self.event_handlers.unregister(id);
                }
                return Err(err);
            }
            registered.push(id);
        }

        self.store.insert_loaded(LoadedMastForest::with_package_debug_info(
            library.mast_forest,
            library.package_debug_info,
        ));
        Ok(())
    }

    /// Loads a library using the supplied portable handlers in place of its legacy handler list.
    /// Each identity receives both invocation kinds. Handler registration and forest loading are
    /// atomic: any invalid name or collision leaves the host unchanged. Existing `load_library`
    /// retains legacy event-only delivery, replacement, and separate trace registration semantics.
    pub fn load_library_with_event_handlers(
        &mut self,
        library: impl Into<HostLibrary>,
        handlers: impl IntoIterator<Item = (EventName, registration::EventHandler)>,
    ) -> Result<(), ExecutionError> {
        let library = library.into();
        let mut registered = Vec::new();
        for (name, handler) in handlers {
            let id = name.to_event_id();
            if let Err(error) = self.register_event_handler(name, handler) {
                for id in registered {
                    self.handlers.unregister(id);
                }
                return Err(error);
            }
            registered.push(id);
        }
        self.store.insert_loaded(LoadedMastForest::with_package_debug_info(
            library.mast_forest,
            library.package_debug_info,
        ));
        Ok(())
    }

    /// Adds a [`HostLibrary`] containing a [`MastForest`] with its list of event handlers.
    /// to the host.
    pub fn with_library(mut self, library: impl Into<HostLibrary>) -> Result<Self, ExecutionError> {
        self.load_library(library)?;
        Ok(self)
    }

    /// Registers one portable handler for both regular events and traces. Identities already
    /// present in either legacy registry are rejected; kind restrictions belong inside handlers.
    pub fn register_event_handler(
        &mut self,
        name: EventName,
        handler: impl Into<registration::EventHandler>,
    ) -> Result<(), ExecutionError> {
        let id = name.to_event_id();
        if self.event_handlers.resolve_event(id).is_some()
            || self.trace_handlers.resolve_trace(id).is_some()
        {
            return Err(crate::errors::HostError::DuplicateEventHandler { event: name }.into());
        }
        self.handlers.register(name, handler)
    }

    /// Removes a portable registration for both invocation kinds.
    pub fn unregister_event_handler(&mut self, id: EventId) -> bool {
        self.handlers.unregister(id)
    }

    fn check_portable_collision(&self, event: &EventName) -> Result<(), ExecutionError> {
        if self.handlers.resolve(event.to_event_id()).is_some() {
            return Err(
                crate::errors::HostError::DuplicateEventHandler { event: event.clone() }.into()
            );
        }
        Ok(())
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
        self.check_portable_collision(&event)?;
        self.event_handlers.register(event, handler)
    }

    /// Un-registers a handler with the given id, returning a flag indicating whether a handler
    /// was previously registered with this id.
    pub fn unregister_handler(&mut self, id: EventId) -> bool {
        self.event_handlers.unregister(id)
    }

    /// Replaces a handler with the given event, returning a flag indicating whether a handler
    /// was previously registered with this event ID.
    ///
    /// # Errors
    /// Returns an error when the event name is empty or reserved; the host is not changed
    /// then.
    pub fn replace_handler(
        &mut self,
        event: EventName,
        handler: Arc<dyn EventHandler>,
    ) -> Result<bool, ExecutionError> {
        self.check_portable_collision(&event)?;
        self.event_handlers.replace(event, handler)
    }

    /// Registers a single [`TraceHandler`] into this host.
    ///
    /// Trace handlers observe VM state for optional, read-only trace events; they cannot mutate the
    /// advice provider. Unhandled trace event IDs are ignored. The handler can be either a closure
    /// or a free function.
    pub fn register_trace_handler(
        &mut self,
        event: EventName,
        handler: Arc<dyn TraceHandler>,
    ) -> Result<(), ExecutionError> {
        self.check_portable_collision(&event)?;
        self.trace_handlers.register(event, handler)
    }

    /// Un-registers a trace handler with the given id, returning a flag indicating whether a
    /// handler was previously registered with this id.
    pub fn unregister_trace_handler(&mut self, id: EventId) -> bool {
        self.trace_handlers.unregister(id)
    }

    /// Replaces a trace handler with the given event, returning a flag indicating whether a
    /// handler was previously registered with this event ID.
    ///
    /// # Errors
    /// Returns an error when the event name is empty or reserved; the host is not changed
    /// then.
    pub fn replace_trace_handler(
        &mut self,
        event: EventName,
        handler: Arc<dyn TraceHandler>,
    ) -> Result<bool, ExecutionError> {
        self.check_portable_collision(&event)?;
        self.trace_handlers.replace(event, handler)
    }
}

impl<S> BaseHost for DefaultHost<S>
where
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

    fn resolve_event(&self, event_id: EventId) -> Option<&EventName> {
        self.handlers
            .resolve(event_id)
            .or_else(|| self.event_handlers.resolve_event(event_id))
    }

    fn resolve_trace(&self, trace_id: EventId) -> Option<&EventName> {
        self.handlers
            .resolve(trace_id)
            .or_else(|| self.trace_handlers.resolve_trace(trace_id))
    }
}

impl<S> SyncHost for DefaultHost<S>
where
    S: SourceManager,
{
    fn handle_event(
        &mut self,
        context: EventContext<'_>,
        advice: &mut AdviceRecorder<'_>,
    ) -> Result<(), EventError> {
        if self.handlers.handle_event(context.id(), context, advice)? {
            Ok(())
        } else {
            Err(super::LegacyHostFallback.into())
        }
    }

    fn get_mast_forest(&self, node_digest: &Word) -> Option<LoadedMastForest> {
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

    fn on_trace(&mut self, process: &ProcessorState<'_>) -> Result<(), TraceError> {
        // The trace id sits one below the `SystemEvent::TraceEvent` id.
        let trace_id = EventId::from_felt(process.get_stack_item(1));
        match self.trace_handlers.handle_trace(trace_id, process) {
            Ok(Some(())) => Ok(()),
            // Traces are optional/readonly, so an unhandled trace is not an error.
            Ok(None) => Ok(()),
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
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<LoadedMastForest> {
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
pub struct HostLibrary {
    /// A `MastForest` with procedures exposed by this library.
    pub mast_forest: Arc<MastForest>,
    /// Package-owned debug info that belongs to `mast_forest`.
    pub package_debug_info: Result<Option<PackageDebugInfo>, PackageDebugInfoError>,
    /// List of handlers along with their event names to call them with `emit`.
    pub handlers: Vec<(EventName, Arc<dyn EventHandler>)>,
}

impl HostLibrary {
    /// Replaces the event handlers of this library.
    ///
    /// Use this to supply handlers that the source of the library does not provide, for example
    /// the Wasm event handlers of a package.
    pub fn set_handlers(mut self, handlers: Vec<(EventName, Arc<dyn EventHandler>)>) -> Self {
        self.handlers = handlers;
        self
    }
}

impl Default for HostLibrary {
    fn default() -> Self {
        Self {
            mast_forest: Arc::new(MastForest::new()),
            package_debug_info: Ok(None),
            handlers: Vec::new(),
        }
    }
}

/// Converts a package into a host library.
///
/// The packaged Wasm event handlers are NOT loaded: this crate cannot depend on the Wasm runner
/// crate. To get a library with the handlers of the `event_handlers` section, use
/// `miden_wasm_event_handlers::host_library_from_package`.
impl From<Arc<miden_mast_package::Package>> for HostLibrary {
    fn from(package: Arc<miden_mast_package::Package>) -> Self {
        let package_debug_info = match package.debug_info() {
            Ok(debug_info) => Ok(debug_info),
            Err(PackageDebugInfoError::UntrustedSections) => Ok(None),
            Err(err) => Err(err),
        };
        Self {
            mast_forest: package.mast_forest().clone(),
            package_debug_info,
            handlers: vec![],
        }
    }
}

impl From<Arc<MastForest>> for HostLibrary {
    fn from(mast_forest: Arc<MastForest>) -> Self {
        Self {
            mast_forest,
            package_debug_info: Ok(None),
            handlers: vec![],
        }
    }
}

impl From<&Arc<MastForest>> for HostLibrary {
    fn from(mast_forest: &Arc<MastForest>) -> Self {
        Self {
            mast_forest: mast_forest.clone(),
            package_debug_info: Ok(None),
            handlers: vec![],
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::{mast::BasicBlockNodeBuilder, operations::Operation};

    use super::{super::handlers::NoopEventHandler, *};
    use crate::errors::HostError;

    #[test]
    fn portable_library_loading_is_atomic_and_legacy_pairs_stay_separate() {
        use miden_event_handler::NoopHandler;
        for invalid in [false, true] {
            let mut host = DefaultHost::default();
            let library = library(&[]);
            let digest = library.mast_forest.local_procedure_digests().next().unwrap();
            let name = EventName::new("test::portable::library");
            let second = if invalid { EventName::new("") } else { name.clone() };
            let handlers = vec![(name.clone(), NoopHandler.into()), (second, NoopHandler.into())];
            assert!(host.load_library_with_event_handlers(library, handlers).is_err());
            assert!(host.handlers.resolve(name.to_event_id()).is_none());
            assert!(host.store.get(&digest).is_none());
        }
        let mut host = DefaultHost::default();
        let name = EventName::new("test::legacy::pair");
        host.register_handler(name.clone(), Arc::new(NoopEventHandler)).unwrap();
        host.register_trace_handler(name.clone(), Arc::new(|_: &ProcessorState<'_>| Ok(())))
            .unwrap();
        assert!(host.register_event_handler(name.clone(), NoopHandler).is_err());
        assert!(host.replace_handler(name.clone(), Arc::new(NoopEventHandler)).unwrap());
        assert!(host.unregister_handler(name.to_event_id()));
        assert!(host.unregister_trace_handler(name.to_event_id()));
    }

    /// Builds a library with one procedure and one handler per event name.
    fn library(events: &[&'static str]) -> HostLibrary {
        let mut mast_forest = MastForest::new();
        let block = BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(block);

        let handlers = events
            .iter()
            .map(|event| {
                (EventName::new(event), Arc::new(NoopEventHandler) as Arc<dyn EventHandler>)
            })
            .collect();
        HostLibrary::from(Arc::new(mast_forest)).set_handlers(handlers)
    }

    /// Returns `true` when the host resolves a handler for the named event.
    fn is_registered(host: &DefaultHost, event: &'static str) -> bool {
        host.resolve_event(EventName::new(event).to_event_id()).is_some()
    }

    #[test]
    fn load_library_registers_the_handlers_and_the_forest() {
        let library = library(&["test::a", "test::b"]);
        let procedure = library.mast_forest.local_procedure_digests().next().unwrap();

        let mut host = DefaultHost::default();
        host.load_library(library).unwrap();

        assert!(is_registered(&host, "test::a"));
        assert!(is_registered(&host, "test::b"));
        assert!(host.get_mast_forest(&procedure).is_some());
    }

    #[test]
    fn failed_load_library_leaves_no_partial_state() {
        let mut host = DefaultHost::default();
        host.register_handler(EventName::new("test::b"), Arc::new(NoopEventHandler))
            .unwrap();

        // The second handler of the library collides with the handler of the host.
        let library = library(&["test::a", "test::b"]);
        let procedure = library.mast_forest.local_procedure_digests().next().unwrap();
        let err = host.load_library(library).unwrap_err();

        assert!(
            matches!(err, ExecutionError::HostError(HostError::DuplicateEventHandler { .. })),
            "unexpected error: {err}"
        );
        assert!(!is_registered(&host, "test::a"), "the first handler must be rolled back");
        assert!(host.get_mast_forest(&procedure).is_none(), "the forest must not be loaded");
    }
}
