use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Word,
    events::{EventId, EventName},
    mast::MastForest,
};
use miden_debug_types::{DefaultSourceManager, Location, SourceFile, SourceManager, SourceSpan};
use miden_mast_package::{PackageDebugInfoError, debug_info::PackageDebugInfo};

use super::handlers::{EventError, EventHandler, EventHandlerRegistry};
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
    event_handlers: EventHandlerRegistry,
    source_manager: Arc<S>,
}

impl Default for DefaultHost {
    fn default() -> Self {
        Self {
            store: MemMastForestStore::default(),
            event_handlers: EventHandlerRegistry::default(),
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
            event_handlers: self.event_handlers,
            source_manager,
        }
    }

    /// Loads a [`HostLibrary`] containing a [`MastForest`] with its list of event handlers.
    pub fn load_library(&mut self, library: impl Into<HostLibrary>) -> Result<(), ExecutionError> {
        let library = library.into();
        self.store.insert_loaded(LoadedMastForest::with_package_debug_info(
            library.mast_forest,
            library.package_debug_info,
        ));

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
        self.event_handlers.resolve_event(event_id)
    }
}

impl<S> SyncHost for DefaultHost<S>
where
    S: SourceManager,
{
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

impl Default for HostLibrary {
    fn default() -> Self {
        Self {
            mast_forest: Arc::new(MastForest::new()),
            package_debug_info: Ok(None),
            handlers: Vec::new(),
        }
    }
}

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
