use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Word,
    events::{EventId, EventName},
    mast::MastForest,
};
use miden_debug_types::{DefaultSourceManager, Location, SourceFile, SourceManager, SourceSpan};
use miden_event_handler::{AdviceRecorder, EventContext};
use miden_mast_package::{PackageDebugInfoError, debug_info::PackageDebugInfo};

use super::handlers::{EventError, HandlerRegistry, TraceError, registration};
#[allow(deprecated)] // Retained raw-state registries and callback traits.
use super::handlers::{EventHandler, EventHandlerRegistry, TraceHandler, TraceHandlerRegistry};
#[allow(deprecated)] // Retained raw-state callback signatures.
use crate::ProcessorState;
#[allow(deprecated)] // Legacy callback return type.
use crate::advice::AdviceMutation;
use crate::{
    BaseHost, ExecutionError, LoadedMastForest, MastForestStore, MemMastForestStore, SyncHost,
};

// DEFAULT HOST IMPLEMENTATION
// ================================================================================================

/// A default SyncHost implementation that provides the essential functionality required by the VM.
#[derive(Debug)]
pub struct DefaultHost<S: SourceManager = DefaultSourceManager> {
    store: MemMastForestStore,
    handlers: HandlerRegistry,
    #[allow(deprecated)] // Legacy event-only bindings.
    event_handlers: EventHandlerRegistry,
    #[allow(deprecated)] // Legacy trace-only bindings.
    trace_handlers: TraceHandlerRegistry,
    source_manager: Arc<S>,
}

impl Default for DefaultHost {
    #[allow(deprecated)] // Initialize retained legacy registries.
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
    #[allow(deprecated)] // Load retained event-only bindings.
    #[deprecated(note = "use load_library with EventLibrary")]
    pub fn load_legacy_library(
        &mut self,
        library: impl Into<HostLibrary>,
    ) -> Result<(), ExecutionError> {
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

    /// Loads a library with its portable handlers for both regular events and traces.
    ///
    /// Loading is atomic: an invalid name or a collision with any existing handler leaves the
    /// host unchanged, including its MAST forests and package debug information.
    pub fn load_library(&mut self, library: impl Into<EventLibrary>) -> Result<(), ExecutionError> {
        let library = library.into();
        let mut registered = Vec::with_capacity(library.handlers.len());
        for (name, handler) in library.handlers {
            let id = name.to_event_id();
            if let Err(error) = self.register_handler(name, handler) {
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

    /// Loads a library with legacy event-only handlers, returning the configured host.
    #[allow(deprecated)] // Forward to the retained event-only loader.
    #[deprecated(note = "use with_library with EventLibrary")]
    pub fn with_legacy_library(
        mut self,
        library: impl Into<HostLibrary>,
    ) -> Result<Self, ExecutionError> {
        self.load_legacy_library(library)?;
        Ok(self)
    }

    /// Loads a portable library, returning the configured host.
    pub fn with_library(
        mut self,
        library: impl Into<EventLibrary>,
    ) -> Result<Self, ExecutionError> {
        self.load_library(library)?;
        Ok(self)
    }

    /// Registers one portable handler for both regular events and traces. Identities already
    /// present in either legacy registry are rejected; kind restrictions belong inside handlers.
    pub fn register_handler(
        &mut self,
        name: EventName,
        handler: impl Into<registration::EventHandler>,
    ) -> Result<(), ExecutionError> {
        self.check_legacy_collision(&name)?;
        self.handlers.register(name, handler)
    }

    /// Removes a portable registration for both invocation kinds.
    pub fn unregister_handler(&mut self, id: EventId) -> bool {
        self.handlers.unregister(id)
    }

    /// Replaces a portable handler for both invocation kinds, returning whether one existed.
    ///
    /// An invalid name or a collision with a legacy handler leaves the host unchanged.
    pub fn replace_handler(
        &mut self,
        name: EventName,
        handler: impl Into<registration::EventHandler>,
    ) -> Result<bool, ExecutionError> {
        self.check_legacy_collision(&name)?;
        self.handlers.replace(name, handler)
    }

    fn check_legacy_collision(&self, event: &EventName) -> Result<(), ExecutionError> {
        let id = event.to_event_id();
        if self.event_handlers.resolve_event(id).is_some()
            || self.trace_handlers.resolve_trace(id).is_some()
        {
            return Err(
                crate::errors::HostError::DuplicateEventHandler { event: event.clone() }.into()
            );
        }
        Ok(())
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
    /// `fn(&ProcessorState) -> Result<Vec<AdviceMutation>, EventError>`
    #[allow(deprecated)] // Retained raw-state registration API.
    #[deprecated(note = "use register_handler, unregister_handler, and replace_handler")]
    pub fn register_legacy_handler(
        &mut self,
        event: EventName,
        handler: Arc<dyn EventHandler>,
    ) -> Result<(), ExecutionError> {
        self.check_portable_collision(&event)?;
        self.event_handlers.register(event, handler)
    }

    /// Un-registers a handler with the given id, returning a flag indicating whether a handler
    /// was previously registered with this id.
    #[allow(deprecated)] // Retained raw-state registration API.
    #[deprecated(note = "use register_handler, unregister_handler, and replace_handler")]
    pub fn unregister_legacy_handler(&mut self, id: EventId) -> bool {
        self.event_handlers.unregister(id)
    }

    /// Replaces a handler with the given event, returning a flag indicating whether a handler
    /// was previously registered with this event ID.
    ///
    /// # Errors
    /// Returns an error when the event name is empty or reserved; the host is not changed
    /// then.
    #[allow(deprecated)] // Retained raw-state registration API.
    #[deprecated(note = "use register_handler, unregister_handler, and replace_handler")]
    pub fn replace_legacy_handler(
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
    #[allow(deprecated)] // Retained raw-state registration API.
    #[deprecated(note = "use register_handler, unregister_handler, and replace_handler")]
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
    #[allow(deprecated)] // Retained raw-state registration API.
    #[deprecated(note = "use register_handler, unregister_handler, and replace_handler")]
    pub fn unregister_trace_handler(&mut self, id: EventId) -> bool {
        self.trace_handlers.unregister(id)
    }

    /// Replaces a trace handler with the given event, returning a flag indicating whether a
    /// handler was previously registered with this event ID.
    ///
    /// # Errors
    /// Returns an error when the event name is empty or reserved; the host is not changed
    /// then.
    #[allow(deprecated)] // Retained raw-state registration API.
    #[deprecated(note = "use register_handler, unregister_handler, and replace_handler")]
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

    #[allow(deprecated)] // Forward the retained raw-state callback.
    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        let event_id = EventId::from_felt(process.get_stack_item(0));
        match self.event_handlers.handle_event(event_id, process) {
            Ok(Some(mutations)) => Ok(mutations),
            Ok(None) => Err(super::UnhandledEvent.into()),
            Err(e) => Err(e),
        }
    }

    #[allow(deprecated)] // Forward the retained raw-state trace callback.
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
    fn handle_event(
        &mut self,
        _context: EventContext<'_>,
        _advice: &mut AdviceRecorder<'_>,
    ) -> Result<(), EventError> {
        Ok(())
    }

    #[allow(deprecated)] // Keep direct legacy NoopHost callbacks as no-ops for downstream hosts.
    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

// HOST LIBRARY
// ================================================================================================

/// A MAST forest, its package debug information, and its portable event and trace handlers.
///
/// Use `CoreLibrary::host_library()` or `miden_wasm_event_handlers::event_library_from_package`
/// to load complete libraries. Raw forests can also be loaded when no handlers are required.
/// There is deliberately no conversion from a package or legacy [`HostLibrary`]: those
/// conversions could omit packaged Wasm handlers or discard legacy bindings.
pub struct EventLibrary {
    /// Procedures exposed by this library.
    pub mast_forest: Arc<MastForest>,
    /// Package-owned debug information belonging to `mast_forest`.
    pub package_debug_info: Result<Option<PackageDebugInfo>, PackageDebugInfoError>,
    /// Portable handlers shared by regular events and traces.
    pub handlers: Vec<(EventName, registration::EventHandler)>,
}

impl EventLibrary {
    /// Pairs a forest and its debug information with the complete portable handler bindings.
    pub fn new(
        mast_forest: Arc<MastForest>,
        package_debug_info: Result<Option<PackageDebugInfo>, PackageDebugInfoError>,
        handlers: impl IntoIterator<Item = (EventName, registration::EventHandler)>,
    ) -> Self {
        Self {
            mast_forest,
            package_debug_info,
            handlers: handlers.into_iter().collect(),
        }
    }
}

impl Default for EventLibrary {
    fn default() -> Self {
        Self::from(Arc::new(MastForest::new()))
    }
}

impl From<Arc<MastForest>> for EventLibrary {
    fn from(mast_forest: Arc<MastForest>) -> Self {
        Self::new(mast_forest, Ok(None), [])
    }
}

impl From<&Arc<MastForest>> for EventLibrary {
    fn from(mast_forest: &Arc<MastForest>) -> Self {
        Self::from(mast_forest.clone())
    }
}

/// A rich library representing a [`MastForest`] which also exports
/// a list of handlers for events it may call.
pub struct HostLibrary {
    /// A `MastForest` with procedures exposed by this library.
    pub mast_forest: Arc<MastForest>,
    /// Package-owned debug info that belongs to `mast_forest`.
    pub package_debug_info: Result<Option<PackageDebugInfo>, PackageDebugInfoError>,
    /// List of handlers along with their event names to call them with `emit`.
    #[allow(deprecated)] // Retain the legacy handler list.
    #[deprecated(note = "use EventLibrary and DefaultHost::load_library")]
    pub handlers: Vec<(EventName, Arc<dyn EventHandler>)>,
}

impl HostLibrary {
    /// Replaces the event handlers of this library.
    ///
    /// Use this to supply handlers that the source of the library does not provide, for example
    /// the Wasm event handlers of a package.
    #[allow(deprecated)] // Retain the legacy handler list.
    #[deprecated(note = "use EventLibrary and DefaultHost::load_library")]
    pub fn set_handlers(mut self, handlers: Vec<(EventName, Arc<dyn EventHandler>)>) -> Self {
        self.handlers = handlers;
        self
    }
}

#[allow(deprecated)] // Initialize the retained legacy handler list.
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
#[allow(deprecated)] // Initialize the retained legacy handler list.
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

#[allow(deprecated)] // Initialize the retained legacy handler list.
impl From<Arc<MastForest>> for HostLibrary {
    fn from(mast_forest: Arc<MastForest>) -> Self {
        Self {
            mast_forest,
            package_debug_info: Ok(None),
            handlers: vec![],
        }
    }
}

#[allow(deprecated)] // Initialize the retained legacy handler list.
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

    #[allow(deprecated)] // Compatibility regression fixtures.
    use super::{super::handlers::NoopEventHandler, *};
    use crate::errors::HostError;

    #[test]
    #[allow(deprecated)] // Exercise retained legacy bindings and their collision behavior.
    fn portable_library_loading_is_atomic_and_legacy_pairs_stay_separate() {
        use miden_event_handler::NoopHandler;
        for failure in ["duplicate", "empty", "reserved", "portable", "legacy", "trace"] {
            let mut host = DefaultHost::default();
            let library = library(&[]);
            let digest = library.mast_forest.local_procedure_digests().next().unwrap();
            let name = EventName::new("test::portable::library");
            let occupied = EventName::new("test::occupied");
            let second = match failure {
                "duplicate" => name.clone(),
                "empty" => EventName::new(""),
                "reserved" => EventName::new("sys::reserved"),
                "portable" => {
                    host.register_handler(occupied.clone(), NoopHandler).unwrap();
                    occupied.clone()
                },
                "legacy" => {
                    host.register_legacy_handler(occupied.clone(), Arc::new(NoopEventHandler))
                        .unwrap();
                    occupied.clone()
                },
                "trace" => {
                    host.register_trace_handler(
                        occupied.clone(),
                        Arc::new(|_: &ProcessorState<'_>| Ok(())),
                    )
                    .unwrap();
                    occupied.clone()
                },
                _ => unreachable!(),
            };
            let handlers = [(name.clone(), NoopHandler.into()), (second, NoopHandler.into())];
            assert!(
                host.load_library(EventLibrary::new(
                    library.mast_forest,
                    library.package_debug_info,
                    handlers,
                ))
                .is_err(),
                "{failure}",
            );
            assert!(host.resolve_event(name.to_event_id()).is_none());
            assert!(host.resolve_trace(name.to_event_id()).is_none());
            assert!(host.store.get(&digest).is_none());
            if matches!(failure, "portable" | "legacy" | "trace") {
                assert!(
                    host.resolve_event(occupied.to_event_id()).is_some()
                        || host.resolve_trace(occupied.to_event_id()).is_some()
                );
            }
        }
        let mut host = DefaultHost::default();
        let name = EventName::new("test::legacy::pair");
        host.register_legacy_handler(name.clone(), Arc::new(NoopEventHandler)).unwrap();
        host.register_trace_handler(name.clone(), Arc::new(|_: &ProcessorState<'_>| Ok(())))
            .unwrap();
        assert!(host.register_handler(name.clone(), NoopHandler).is_err());
        assert!(host.replace_handler(name.clone(), NoopHandler).is_err());
        assert!(host.replace_legacy_handler(name.clone(), Arc::new(NoopEventHandler)).unwrap());
        assert!(host.unregister_legacy_handler(name.to_event_id()));
        // A remaining legacy trace binding still prevents portable replacement.
        assert!(host.replace_handler(name.clone(), NoopHandler).is_err());
        assert!(host.unregister_trace_handler(name.to_event_id()));
        assert!(!host.replace_handler(name.clone(), NoopHandler).unwrap());
        assert!(host.replace_handler(name.clone(), NoopHandler).unwrap());
        assert!(host.register_legacy_handler(name.clone(), Arc::new(NoopEventHandler)).is_err());
        assert!(host.replace_legacy_handler(name.clone(), Arc::new(NoopEventHandler)).is_err());
        assert!(
            host.register_trace_handler(name.clone(), Arc::new(|_: &ProcessorState<'_>| Ok(())),)
                .is_err()
        );
        assert!(
            host.replace_trace_handler(name.clone(), Arc::new(|_: &ProcessorState<'_>| Ok(())),)
                .is_err()
        );
        assert_eq!(host.resolve_event(name.to_event_id()), Some(&name));
        assert_eq!(host.resolve_trace(name.to_event_id()), Some(&name));
        assert!(host.unregister_handler(name.to_event_id()));
        assert!(host.resolve_event(name.to_event_id()).is_none());
        assert!(host.resolve_trace(name.to_event_id()).is_none());
    }

    #[test]
    fn portable_library_loads_handlers_forest_and_debug_info_together() {
        let library = library(&[]);
        let forest = library.mast_forest;
        let procedure = forest.local_procedure_digests().next().unwrap();
        let name = EventName::new("test::portable::library");
        let host = DefaultHost::default()
            .with_library(EventLibrary::new(
                forest.clone(),
                Err(PackageDebugInfoError::UntrustedSections),
                [(name.clone(), miden_event_handler::NoopHandler.into())],
            ))
            .unwrap();
        assert_eq!(host.resolve_event(name.to_event_id()), Some(&name));
        assert_eq!(host.resolve_trace(name.to_event_id()), Some(&name));
        let loaded = host.get_mast_forest(&procedure).unwrap();
        assert!(Arc::ptr_eq(loaded.mast_forest(), &forest));
        assert!(matches!(
            loaded.package_debug_info().unwrap_err().as_ref(),
            PackageDebugInfoError::UntrustedSections,
        ));
    }

    /// Builds a library with one procedure and one handler per event name.
    #[allow(deprecated)] // Exercise retained legacy bindings and their collision behavior.
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
    #[allow(deprecated)] // Exercise retained legacy bindings and their collision behavior.
    fn load_legacy_library_registers_the_handlers_and_the_forest() {
        let library = library(&["test::a", "test::b"]);
        let procedure = library.mast_forest.local_procedure_digests().next().unwrap();

        let mut host = DefaultHost::default();
        host.load_legacy_library(library).unwrap();

        assert!(is_registered(&host, "test::a"));
        assert!(is_registered(&host, "test::b"));
        assert!(host.get_mast_forest(&procedure).is_some());
    }

    #[test]
    #[allow(deprecated)] // Exercise retained legacy bindings and their collision behavior.
    fn failed_load_legacy_library_leaves_no_partial_state() {
        let mut host = DefaultHost::default();
        host.register_legacy_handler(EventName::new("test::b"), Arc::new(NoopEventHandler))
            .unwrap();

        // The second handler of the library collides with the handler of the host.
        let library = library(&["test::a", "test::b"]);
        let procedure = library.mast_forest.local_procedure_digests().next().unwrap();
        let err = host.load_legacy_library(library).unwrap_err();

        assert!(
            matches!(err, ExecutionError::HostError(HostError::DuplicateEventHandler { .. })),
            "unexpected error: {err}"
        );
        assert!(!is_registered(&host, "test::a"), "the first handler must be rolled back");
        assert!(host.get_mast_forest(&procedure).is_none(), "the forest must not be loaded");
    }
}
