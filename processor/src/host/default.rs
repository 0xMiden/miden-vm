use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Word,
    deferred::PrecompileRegistry,
    events::{EventId, EventName},
    mast::MastForest,
};
use miden_debug_types::{DefaultSourceManager, Location, SourceFile, SourceManager, SourceSpan};

use super::handlers::{EventError, EventHandler, EventHandlerRegistry};
use crate::{
    BaseHost, ExecutionError, MastForestStore, MemMastForestStore, ProcessorState, SyncHost,
    advice::AdviceMutation,
};

// DEFAULT HOST IMPLEMENTATION
// ================================================================================================

/// A default SyncHost implementation that provides the essential functionality required by the VM.
#[derive(Debug)]
pub struct DefaultHost<S: SourceManager = DefaultSourceManager> {
    store: MemMastForestStore,
    event_handlers: EventHandlerRegistry,
    source_manager: Arc<S>,
    precompiles: Arc<PrecompileRegistry>,
}

impl Default for DefaultHost {
    fn default() -> Self {
        Self {
            store: MemMastForestStore::default(),
            event_handlers: EventHandlerRegistry::default(),
            source_manager: Arc::new(DefaultSourceManager::default()),
            precompiles: Arc::new(PrecompileRegistry::default()),
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
            precompiles: self.precompiles,
        }
    }

    /// Loads a [`HostLibrary`] containing a [`MastForest`] with its event handlers and deferred
    /// precompiles.
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

    /// Installs the deferred precompile registry used by system-event handlers.
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

    fn precompiles(&self) -> &PrecompileRegistry {
        &self.precompiles
    }
}

impl<S> SyncHost for DefaultHost<S>
where
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

/// A rich library representing a [`MastForest`] which also exports
/// a list of handlers for events it may call.
#[derive(Default)]
pub struct HostLibrary {
    /// A `MastForest` with procedures exposed by this library.
    pub mast_forest: Arc<MastForest>,
    /// List of handlers along with their event names to call them with `emit`.
    pub handlers: Vec<(EventName, Arc<dyn EventHandler>)>,
    /// Deferred precompiles exported by this library.
    pub precompiles: PrecompileRegistry,
}

impl From<Arc<miden_mast_package::Package>> for HostLibrary {
    fn from(package: Arc<miden_mast_package::Package>) -> Self {
        Self {
            mast_forest: package.mast_forest().clone(),
            handlers: vec![],
            precompiles: PrecompileRegistry::default(),
        }
    }
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
        ZERO,
        deferred::{DeferredState, PrecompileError},
        testing::precompile::{Hash, Uint},
    };

    use super::*;

    #[test]
    fn load_library_extends_existing_precompiles() {
        let original = Arc::new(PrecompileRegistry::default().with_precompile(Uint));
        let mut host = DefaultHost::default().with_precompiles(original.clone());
        let library = HostLibrary {
            mast_forest: Arc::new(MastForest::new()),
            handlers: Vec::new(),
            precompiles: PrecompileRegistry::default().with_precompile(Hash),
        };

        host.load_library(library).unwrap();

        let mut merged_state = DeferredState::new(usize::MAX);
        assert!(merged_state.register(host.precompiles(), Uint::leaf_node([0; 8])).is_ok());
        assert!(merged_state.register(host.precompiles(), Hash::digest_node([ZERO; 8])).is_ok());

        let mut original_state = DeferredState::new(usize::MAX);
        assert!(matches!(
            original_state.register(&original, Hash::digest_node([ZERO; 8])),
            Err(PrecompileError::InvalidNode)
        ));
    }
}
