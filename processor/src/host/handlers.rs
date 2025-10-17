use alloc::{
    boxed::Box,
    collections::{BTreeMap, btree_map::Entry},
    sync::Arc,
    vec::Vec,
};
use core::{error::Error, fmt, fmt::Debug};

use miden_core::{DebugOptions, EventId, NamedEvent};

use crate::{AdviceMutation, ExecutionError, ProcessState};

// EVENT HANDLER TRAIT
// ================================================================================================

/// An [`EventHandler`] defines a function that that can be called from the processor which can
/// read the VM state and modify the state of the advice provider.
///
/// A struct implementing this trait can access its own state, but any output it produces must
/// be stored in the process's advice provider.
pub trait EventHandler: Send + Sync + 'static {
    /// Handles the event when triggered.
    fn on_event(&self, process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError>;
}

/// Default implementation for both free functions and closures with signature
/// `fn(&ProcessState) -> Result<(), HandlerError>`
impl<F> EventHandler for F
where
    F: for<'a> Fn(&'a ProcessState) -> Result<Vec<AdviceMutation>, EventError>
        + Send
        + Sync
        + 'static,
{
    fn on_event(&self, process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
        self(process)
    }
}

/// A handler which ignores the process state and leaves the `AdviceProvider` unchanged.
pub struct NoopEventHandler;

impl EventHandler for NoopEventHandler {
    fn on_event(&self, _process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
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
/// fn my_handler(process: &mut ProcessState) -> Result<(), HandlerError> {
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
///         process: &mut ProcessState,
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
    handlers: BTreeMap<EventId, (NamedEvent, Arc<dyn EventHandler>)>,
}

impl EventHandlerRegistry {
    pub fn new() -> Self {
        Self { handlers: BTreeMap::new() }
    }

    /// Registers an [`EventHandler`] with a given named event.
    pub fn register(
        &mut self,
        event: NamedEvent,
        handler: Arc<dyn EventHandler>,
    ) -> Result<(), ExecutionError> {
        let id = event.id();
        if id.is_reserved() {
            return Err(ExecutionError::ReservedEventId { event: event.clone() });
        }
        match self.handlers.entry(id) {
            Entry::Vacant(e) => e.insert((event, handler)),
            Entry::Occupied(_) => return Err(ExecutionError::DuplicateEventHandler { event }),
        };
        Ok(())
    }

    /// Unregisters a handler with the given identifier, returning a flag whether a handler with
    /// that identifier was previously registered.
    pub fn unregister(&mut self, id: EventId) -> bool {
        self.handlers.remove(&id).is_some()
    }

    /// Handles the event if the registry contains a handler with the same identifier.
    ///
    /// Returns an `Option<_>` indicating whether the event was handled, wrapping the named event
    /// and resulting mutations. Returns `None` if the event was not handled, if the event was
    /// handled successfully `Some((event, mutations))` is returned, and if the handler returns
    /// an error, it is propagated to the caller.
    pub fn handle_event(
        &self,
        id: EventId,
        process: &ProcessState,
    ) -> Result<Option<(NamedEvent, Vec<AdviceMutation>)>, EventError> {
        if let Some((named_event, handler)) = self.handlers.get(&id) {
            let mutations = handler.on_event(process)?;
            return Ok(Some((named_event.clone(), mutations)));
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

// DEBUG HANDLER
// ================================================================================================

/// Handler for debug and trace operations
pub trait DebugHandler: Sync {
    /// This function is invoked when the `Debug` decorator is executed.
    fn on_debug(
        &mut self,
        process: &ProcessState,
        options: &DebugOptions,
    ) -> Result<(), ExecutionError> {
        let mut handler = crate::host::debug::DefaultDebugHandler::default();
        handler.on_debug(process, options)
    }

    /// This function is invoked when the `Trace` decorator is executed.
    fn on_trace(&mut self, process: &ProcessState, trace_id: u32) -> Result<(), ExecutionError> {
        let _ = (&process, trace_id);
        #[cfg(feature = "std")]
        std::println!(
            "Trace with id {} emitted at step {} in context {}",
            trace_id,
            process.clk(),
            process.ctx()
        );
        Ok(())
    }
}
