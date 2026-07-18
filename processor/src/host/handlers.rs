use alloc::{
    boxed::Box,
    collections::{BTreeMap, btree_map::Entry},
    sync::Arc,
    vec::Vec,
};
use core::{error::Error, fmt, fmt::Debug};

use miden_core::events::{EventId, EventName, SystemEvent};

use crate::{ExecutionError, ProcessorState, advice::AdviceMutation};

// EVENT HANDLER TRAIT
// ================================================================================================

/// An [`EventHandler`] defines a function that that can be called from the processor which can
/// read the VM state and modify the state of the advice provider.
///
/// A struct implementing this trait can access its own state, but any output it produces must
/// be stored in the process's advice provider.
pub trait EventHandler: Send + Sync + 'static {
    /// Handles the event when triggered.
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError>;
}

/// Default implementation for both free functions and closures with signature
/// `fn(&ProcessorState) -> Result<Vec<AdviceMutation>, EventError>`
impl<F> EventHandler for F
where
    F: for<'a> Fn(&'a ProcessorState) -> Result<Vec<AdviceMutation>, EventError>
        + Send
        + Sync
        + 'static,
{
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        self(process)
    }
}

/// A handler which ignores the process state and leaves the `AdviceProvider` unchanged.
pub struct NoopEventHandler;

impl EventHandler for NoopEventHandler {
    fn on_event(&self, _process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

// EVENT ERROR
// ================================================================================================

/// A generic [`Error`] wrapper allowing handlers to return errors to the Host caller.
///
/// Error handlers can define their own [`Error`] type which can be seamlessly converted
/// into this type since it is a [`Box`].
///
/// # Example
///
/// ```rust, ignore
/// pub struct MyError{ /* ... */ };
///
/// fn try_something() -> Result<(), MyError> { /* ... */ }
///
/// fn my_handler(process: &mut ProcessorState) -> Result<(), HandlerError> {
///     // ...
///     try_something()?;
///     // ...
///     Ok(())
/// }
/// ```
pub type EventError = Box<dyn Error + Send + Sync + 'static>;

// EVENT HANDLER REGISTRY
// ================================================================================================

/// Registry for maintaining event handlers.
///
/// # Example
///
/// ```rust, ignore
/// impl Host for MyHost {
///     fn on_event(
///         &mut self,
///         process: &mut ProcessorState,
///         event_id: u32,
///     ) -> Result<(), EventError> {
///         if self
///             .event_handlers
///             .handle_event(event_id, process)
///             .map_err(|err| EventError::HandlerError { id: event_id, err })?
///         {
///             // the event was handled by the registered event handlers; just return
///             return Ok(());
///         }
///
///         // implement custom event handling
///
///         Err(EventError::UnhandledEvent { id: event_id })
///     }
/// }
/// ```
#[derive(Default)]
pub struct EventHandlerRegistry {
    handlers: BTreeMap<EventId, (EventName, Arc<dyn EventHandler>)>,
}

impl EventHandlerRegistry {
    pub fn new() -> Self {
        Self { handlers: BTreeMap::new() }
    }

    /// Registers an [`EventHandler`] with a given event name.
    ///
    /// The [`EventId`] is computed from the event name during registration.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The event is a reserved system event
    /// - A handler with the same event ID is already registered
    pub fn register(
        &mut self,
        event: EventName,
        handler: Arc<dyn EventHandler>,
    ) -> Result<(), ExecutionError> {
        // Check if the event is a reserved system event
        if SystemEvent::from_name(event.as_str()).is_some() {
            return Err(crate::errors::HostError::ReservedEventNamespace { event }.into());
        }

        // Compute EventId from the event name
        let id = event.to_event_id();
        match self.handlers.entry(id) {
            Entry::Vacant(e) => e.insert((event, handler)),
            Entry::Occupied(_) => {
                return Err(crate::errors::HostError::DuplicateEventHandler { event }.into());
            },
        };
        Ok(())
    }

    /// Unregisters a handler with the given identifier, returning a flag whether a handler with
    /// that identifier was previously registered.
    pub fn unregister(&mut self, id: EventId) -> bool {
        self.handlers.remove(&id).is_some()
    }

    /// Returns the [`EventName`] registered for `id`, if any.
    pub fn resolve_event(&self, id: EventId) -> Option<&EventName> {
        self.handlers.get(&id).map(|(event, _)| event)
    }

    /// Handles the event if the registry contains a handler with the same identifier.
    ///
    /// Returns an `Option<_>` indicating whether the event was handled. Returns `None` if the
    /// event was not handled, `Some(mutations)` if it was handled successfully, and propagates
    /// handler errors to the caller.
    pub fn handle_event(
        &self,
        id: EventId,
        process: &ProcessorState,
    ) -> Result<Option<Vec<AdviceMutation>>, EventError> {
        if let Some((_event_name, handler)) = self.handlers.get(&id) {
            let mutations = handler.on_event(process)?;
            return Ok(Some(mutations));
        }

        Ok(None)
    }
}

impl Debug for EventHandlerRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let events: Vec<_> = self.handlers.values().map(|(event, _)| event).collect();
        f.debug_struct("EventHandlerRegistry").field("handlers", &events).finish()
    }
}

// TRACE HANDLER TRAIT
// ================================================================================================

/// Handles an optional, read-only trace event emitted by the VM.
///
/// Trace events are emitted by pushing the user trace event ID and then
/// [`SystemEvent::TraceEvent`] onto the stack before `emit`. When the handler runs,
/// [`SystemEvent::TraceEvent`] is at stack position 0 and the user trace event ID is at position
/// 1. The handler receives a read-only [`ProcessorState`] and cannot return advice mutations.
pub trait TraceHandler: Send + Sync + 'static {
    /// Handles the trace event when triggered.
    fn on_trace(&self, process: &ProcessorState) -> Result<(), TraceError>;
}

/// Default implementation for both free functions and closures with signature
/// `fn(&ProcessorState) -> Result<(), TraceError>`
impl<F> TraceHandler for F
where
    F: for<'a> Fn(&'a ProcessorState) -> Result<(), TraceError> + Send + Sync + 'static,
{
    fn on_trace(&self, process: &ProcessorState) -> Result<(), TraceError> {
        self(process)
    }
}

// TRACE ERROR
// ================================================================================================

/// Error type returned by trace handlers.
///
/// Handlers should return errors without event names or IDs; the processor enriches them with the
/// trace event ID and any name registered in the host's trace handler registry.
pub type TraceError = Box<dyn Error + Send + Sync + 'static>;

// TRACE HANDLER REGISTRY
// ================================================================================================

/// Registry for maintaining trace handlers.
#[derive(Default)]
pub struct TraceHandlerRegistry {
    handlers: BTreeMap<EventId, (EventName, Arc<dyn TraceHandler>)>,
}

impl TraceHandlerRegistry {
    pub fn new() -> Self {
        Self { handlers: BTreeMap::new() }
    }

    /// Registers a [`TraceHandler`] with the given event name.
    ///
    /// The [`EventId`] is computed from the event name during registration.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The event is a reserved system event
    /// - A handler with the same event ID is already registered
    pub fn register(
        &mut self,
        event: EventName,
        handler: Arc<dyn TraceHandler>,
    ) -> Result<(), ExecutionError> {
        // Check if the event is a reserved system event
        if SystemEvent::from_name(event.as_str()).is_some() {
            return Err(crate::errors::HostError::ReservedTraceNamespace { event }.into());
        }

        let id = event.to_event_id();
        match self.handlers.entry(id) {
            Entry::Vacant(e) => e.insert((event, handler)),
            Entry::Occupied(_) => {
                return Err(crate::errors::HostError::DuplicateTraceHandler { event }.into());
            },
        };
        Ok(())
    }

    /// Unregisters a handler with the given identifier, returning whether a handler with that
    /// identifier was previously registered.
    pub fn unregister(&mut self, id: EventId) -> bool {
        self.handlers.remove(&id).is_some()
    }

    /// Returns the [`EventName`] registered for `id`, if any.
    pub fn resolve_trace(&self, id: EventId) -> Option<&EventName> {
        self.handlers.get(&id).map(|(event, _)| event)
    }

    /// Handles the trace event if the registry contains a handler with the same identifier.
    ///
    /// Returns `Ok(None)` if no handler is registered for `id`, `Ok(Some(()))` if the trace was
    /// handled, and propagates handler errors to the caller.
    pub fn handle_trace(
        &self,
        id: EventId,
        process: &ProcessorState,
    ) -> Result<Option<()>, TraceError> {
        if let Some((_event_name, handler)) = self.handlers.get(&id) {
            handler.on_trace(process)?;
            return Ok(Some(()));
        }

        Ok(None)
    }
}

impl Debug for TraceHandlerRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let traces: Vec<_> = self.handlers.values().map(|(event, _)| event).collect();
        f.debug_struct("TraceHandlerRegistry").field("handlers", &traces).finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec::Vec};

    use miden_core::events::{EventId, EventName, SystemEvent};

    use super::{
        EventError, EventHandler, EventHandlerRegistry, NoopEventHandler, TraceError, TraceHandler,
        TraceHandlerRegistry,
    };
    use crate::{
        BaseHost, DefaultHost, ExecutionError, FastProcessor, HostError, ProcessorState,
        StackInputs, advice::AdviceMutation,
    };

    #[derive(Debug, thiserror::Error)]
    #[error("handler intentionally failed")]
    struct HandlerFailed;

    /// An event handler that always errors.
    struct FailingEventHandler;
    impl EventHandler for FailingEventHandler {
        fn on_event(&self, _process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
            Err(HandlerFailed.into())
        }
    }

    /// A trace handler that always errors.
    struct FailingTraceHandler;
    impl TraceHandler for FailingTraceHandler {
        fn on_trace(&self, _process: &ProcessorState) -> Result<(), TraceError> {
            Err(HandlerFailed.into())
        }
    }

    struct NoopTraceHandler;
    impl TraceHandler for NoopTraceHandler {
        fn on_trace(&self, _process: &ProcessorState) -> Result<(), TraceError> {
            Ok(())
        }
    }

    /// Builds a default processor and runs `f` against its [`ProcessorState`].
    ///
    /// Allows exercising the handlers defined above without spinning up a full execution. This is
    /// fine since these handlers ignore processor state.
    fn with_fresh_processor_state(f: impl FnOnce(&ProcessorState)) {
        let processor = FastProcessor::new(StackInputs::default());
        let state = processor.state();
        f(&state);
    }

    #[test]
    fn event_registry_resolve() {
        const NAME: EventName = EventName::new("test::event::register_resolve");
        let id = NAME.to_event_id();

        let mut registry = EventHandlerRegistry::new();
        assert!(registry.resolve_event(id).is_none());

        registry.register(NAME, Arc::new(NoopEventHandler)).unwrap();
        assert_eq!(registry.resolve_event(id), Some(&NAME));
    }

    #[test]
    fn event_registry_handle_hit_and_miss() {
        const NAME: EventName = EventName::new("test::event::handle");
        let id = NAME.to_event_id();

        let mut registry = EventHandlerRegistry::new();
        registry.register(NAME, Arc::new(NoopEventHandler)).unwrap();

        with_fresh_processor_state(|state| {
            let handled =
                registry.handle_event(id, state).expect("registered handler should not error");
            assert!(handled.is_some(), "registered id should be handled");

            let missed = registry
                .handle_event(EventId::from_u64(999), state)
                .expect("unregistered id should not error");
            assert!(missed.is_none(), "unknown id should not be handled");
        });
    }

    #[test]
    fn event_registry_handle_propagates_handler_error() {
        const NAME: EventName = EventName::new("test::event::handle_error");
        let id = NAME.to_event_id();

        let mut registry = EventHandlerRegistry::new();
        registry.register(NAME, Arc::new(FailingEventHandler)).unwrap();

        with_fresh_processor_state(|state| {
            let err = registry.handle_event(id, state).unwrap_err();
            assert!(
                err.downcast_ref::<HandlerFailed>().is_some(),
                "expected the handler's HandlerFailed to propagate, got {err}"
            );
        });
    }

    #[test]
    fn event_registry_unregister() {
        const NAME: EventName = EventName::new("test::event::unregister");
        let id = NAME.to_event_id();

        let mut registry = EventHandlerRegistry::new();
        registry.register(NAME, Arc::new(NoopEventHandler)).unwrap();

        assert!(registry.unregister(id), "unregistering a known id should return true");
        assert!(registry.resolve_event(id).is_none());
        assert!(!registry.unregister(id), "unregistering again should return false");
    }

    #[test]
    fn event_register_rejects_reserved_namespace() {
        let reserved = SystemEvent::MerkleNodeMerge.event_name();
        let mut registry = EventHandlerRegistry::new();
        let err = registry.register(reserved.clone(), Arc::new(NoopEventHandler)).unwrap_err();
        match err {
            ExecutionError::HostError(HostError::ReservedEventNamespace { event }) => {
                assert_eq!(event, reserved);
            },
            other => panic!("expected ReservedEventNamespace, got {other:?}"),
        }
    }

    #[test]
    fn event_register_rejects_duplicate() {
        const NAME: EventName = EventName::new("test::event::duplicate");
        let mut registry = EventHandlerRegistry::new();
        registry.register(NAME, Arc::new(NoopEventHandler)).unwrap();

        let err = registry.register(NAME, Arc::new(NoopEventHandler)).unwrap_err();
        match err {
            ExecutionError::HostError(HostError::DuplicateEventHandler { event }) => {
                assert_eq!(event, NAME);
            },
            other => panic!("expected DuplicateEventHandler, got {other:?}"),
        }
    }

    #[test]
    fn trace_registry_register_then_resolve() {
        const NAME: EventName = EventName::new("test::trace::register_resolve");
        let id = NAME.to_event_id();

        let mut registry = TraceHandlerRegistry::new();
        assert!(registry.resolve_trace(id).is_none());

        registry.register(NAME, Arc::new(NoopTraceHandler)).unwrap();
        assert_eq!(registry.resolve_trace(id), Some(&NAME));
    }

    #[test]
    fn trace_registry_handle_hit_and_miss() {
        const NAME: EventName = EventName::new("test::trace::handle");
        let id = NAME.to_event_id();

        let mut registry = TraceHandlerRegistry::new();
        registry.register(NAME, Arc::new(NoopTraceHandler)).unwrap();

        with_fresh_processor_state(|state| {
            let handled =
                registry.handle_trace(id, state).expect("registered handler should not error");
            assert_eq!(handled, Some(()), "registered id should be handled");

            let missed = registry
                .handle_trace(EventId::from_u64(999), state)
                .expect("unregistered id should not error");
            assert_eq!(missed, None, "unknown id should not be handled");
        });
    }

    #[test]
    fn trace_registry_handle_propagates_handler_error() {
        const NAME: EventName = EventName::new("test::trace::handle_error");
        let id = NAME.to_event_id();

        let mut registry = TraceHandlerRegistry::new();
        registry.register(NAME, Arc::new(FailingTraceHandler)).unwrap();

        with_fresh_processor_state(|state| {
            let err = registry.handle_trace(id, state).unwrap_err();
            assert!(
                err.downcast_ref::<HandlerFailed>().is_some(),
                "expected the handler's HandlerFailed to propagate, got {err}"
            );
        });
    }

    #[test]
    fn trace_registry_unregister() {
        const NAME: EventName = EventName::new("test::trace::unregister");
        let id = NAME.to_event_id();

        let mut registry = TraceHandlerRegistry::new();
        registry.register(NAME, Arc::new(NoopTraceHandler)).unwrap();

        assert!(registry.unregister(id), "unregistering a known id should return true");
        assert!(registry.resolve_trace(id).is_none());
        assert!(!registry.unregister(id), "unregistering again should return false");
    }

    #[test]
    fn trace_register_rejects_reserved_namespace() {
        // The trace-event system name is reserved, so it cannot be used for a user handler.
        let reserved = SystemEvent::TraceEvent.event_name();
        let mut registry = TraceHandlerRegistry::new();
        let err = registry.register(reserved.clone(), Arc::new(NoopTraceHandler)).unwrap_err();
        match err {
            ExecutionError::HostError(HostError::ReservedTraceNamespace { event }) => {
                assert_eq!(event, reserved);
            },
            other => panic!("expected ReservedTraceNamespace, got {other:?}"),
        }
    }

    #[test]
    fn trace_register_rejects_duplicate() {
        const NAME: EventName = EventName::new("test::trace::duplicate");
        let mut registry = TraceHandlerRegistry::new();
        registry.register(NAME, Arc::new(NoopTraceHandler)).unwrap();

        let err = registry.register(NAME, Arc::new(NoopTraceHandler)).unwrap_err();
        match err {
            ExecutionError::HostError(HostError::DuplicateTraceHandler { event }) => {
                assert_eq!(event, NAME);
            },
            other => panic!("expected DuplicateTraceHandler, got {other:?}"),
        }
    }

    #[test]
    fn default_host_event_handler_lifecycle() {
        const NAME: EventName = EventName::new("test::host::event_lifecycle");
        let id = NAME.to_event_id();
        let mut host = DefaultHost::default();

        // `replace_handler` reports whether a prior handler existed; before any registration it
        // returns false but registers the handler.
        let existed = host.replace_handler(NAME, Arc::new(NoopEventHandler));
        assert!(!existed, "replace before register should report no prior handler");
        assert_eq!(host.resolve_event(id), Some(&NAME));

        // A second replace now observes the prior handler.
        assert!(host.replace_handler(NAME, Arc::new(NoopEventHandler)));

        // Re-registering the same event directly is rejected.
        assert!(matches!(
            host.register_handler(NAME, Arc::new(NoopEventHandler)),
            Err(ExecutionError::HostError(HostError::DuplicateEventHandler { .. }))
        ));

        assert!(host.unregister_handler(id));
        assert!(host.resolve_event(id).is_none());
        assert!(!host.unregister_handler(id));
    }

    #[test]
    fn default_host_trace_handler_lifecycle() {
        const NAME: EventName = EventName::new("test::host::trace_lifecycle");
        let id = NAME.to_event_id();
        let mut host = DefaultHost::default();

        let existed = host.replace_trace_handler(NAME, Arc::new(NoopTraceHandler));
        assert!(!existed, "replace before register should report no prior handler");
        assert_eq!(host.resolve_trace(id), Some(&NAME));

        assert!(host.replace_trace_handler(NAME, Arc::new(NoopTraceHandler)));

        assert!(matches!(
            host.register_trace_handler(NAME, Arc::new(NoopTraceHandler)),
            Err(ExecutionError::HostError(HostError::DuplicateTraceHandler { .. }))
        ));

        assert!(host.unregister_trace_handler(id));
        assert!(host.resolve_trace(id).is_none());
        assert!(!host.unregister_trace_handler(id));
    }
}
