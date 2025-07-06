use alloc::{
    boxed::Box,
    collections::{BTreeMap, btree_map::Entry},
    vec::Vec,
};
use core::{error::Error, fmt, fmt::Debug};

use vm_core::DebugOptions;

use crate::{ErrorContext, ExecutionError, ProcessState};

// EVENT HANDLER TRAIT
// ================================================================================================

/// An [`EventHandler`] defines a function that that can be called from the processor, which can
/// read the current execution state and modify the advice.
///
/// A struct implementing this trait can access its own state, but any output it produces must
/// be stored in the process's advice provider.
pub trait EventHandler: Send + Sync {
    /// Handles the event when triggered.
    fn on_event(&self, process: &mut ProcessState) -> Result<(), EventError>;
}

/// Default implementation for both free functions and closures with signature
/// `fn(&mut ProcessState) -> Result<(), EventError>`
impl<F> EventHandler for F
where
    F: for<'a> Fn(&'a mut ProcessState) -> Result<(), EventError> + 'static + Send + Sync,
{
    fn on_event(&self, process: &mut ProcessState) -> Result<(), EventError> {
        self(process)
    }
}

// EVENT ERROR
// ================================================================================================

/// A generic [`Error`] wrapper allowing handlers to return errors to the [`Host`](crate::Host)
/// caller.
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
/// fn my_handler(process: &mut ProcessState) -> Result<(), EventError> {
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
///         err_ctx: &impl ErrorContext,
///     ) -> Result<(), ExecutionError> {
///         if self.event_handlers.handle_event(event_id, process, err_ctx)? {
///             // the event was handled by the registered event handlers; just return
///             return Ok(())
///         }
///         
///         // implement custom error handling
///         
///         Err(ExecutionError::invalid_event_id_error(event_id, err_ctx))
///     }
/// }
/// ```
#[derive(Default)]
pub struct EventHandlerRegistry {
    handlers: BTreeMap<u32, Box<dyn EventHandler>>,
}

impl EventHandlerRegistry {
    pub fn new() -> Self {
        Self { handlers: BTreeMap::new() }
    }

    /// Registers a boxed [`EventHandler`] with a given identifier.
    pub fn register(
        &mut self,
        id: u32,
        handler: Box<dyn EventHandler>,
    ) -> Result<(), ExecutionError> {
        match self.handlers.entry(id) {
            Entry::Vacant(e) => e.insert(handler),
            Entry::Occupied(_) => return Err(ExecutionError::DuplicateEventHandler { id }),
        };
        Ok(())
    }

    /// Handles the event if the registry contains a handler with the same identifier.
    /// Returns a bool indicating whether the event was handled. If the event was handled but
    /// returned an error, it is propagated to the caller.
    pub fn handle_event(
        &self,
        id: u32,
        process: &mut ProcessState,
        err_ctx: &impl ErrorContext,
    ) -> Result<bool, ExecutionError> {
        if let Some(handler) = self.handlers.get(&id) {
            handler
                .on_event(process)
                .map_err(|err| ExecutionError::event_error(err, err_ctx))?;
            return Ok(true);
        }

        Ok(false)
    }
}

impl Debug for EventHandlerRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keys: Vec<_> = self.handlers.keys().collect();
        f.debug_struct("EventHandlerRegistry").field("handlers", &keys).finish()
    }
}

// DEBUG HANDLER
// ================================================================================================

/// Handler for debug and trace operations
pub trait DebugHandler: Sync {
    /// This function is invoked when the `Debug` decorator is executed.
    fn on_debug(
        &mut self,
        process: &mut ProcessState,
        options: &DebugOptions,
    ) -> Result<(), ExecutionError> {
        let _ = (&process, options);
        #[cfg(feature = "std")]
        crate::host::debug::print_debug_info(process, options);
        Ok(())
    }

    /// This function is invoked when the `Trace` decorator is executed.
    fn on_trace(
        &mut self,
        process: &mut ProcessState,
        trace_id: u32,
    ) -> Result<(), ExecutionError> {
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
