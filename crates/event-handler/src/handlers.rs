use alloc::{boxed::Box, vec::Vec};
use core::error::Error;

use crate::{AdviceMutation, EventContext};

/// A generic error returned by an [`EventHandler`].
pub type EventError = Box<dyn Error + Send + Sync + 'static>;

/// A generic error returned by a [`TraceHandler`].
pub type TraceError = Box<dyn Error + Send + Sync + 'static>;

/// Handles a custom event emitted by the VM.
pub trait EventHandler: Send + Sync + 'static {
    /// Reads the invocation context and returns advice mutations to apply atomically.
    fn on_event(&self, context: &EventContext<'_>) -> Result<Vec<AdviceMutation>, EventError>;
}

impl<F> EventHandler for F
where
    F: for<'a> Fn(&EventContext<'a>) -> Result<Vec<AdviceMutation>, EventError>
        + Send
        + Sync
        + 'static,
{
    fn on_event(&self, context: &EventContext<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        self(context)
    }
}

/// An event handler that leaves advice unchanged.
#[derive(Debug, Default)]
pub struct NoopEventHandler;

impl EventHandler for NoopEventHandler {
    fn on_event(&self, _context: &EventContext<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

/// Handles an optional, read-only trace event emitted by the VM.
pub trait TraceHandler: Send + Sync + 'static {
    /// Reads the trace invocation context.
    fn on_trace(&self, context: &EventContext<'_>) -> Result<(), TraceError>;
}

impl<F> TraceHandler for F
where
    F: for<'a> Fn(&EventContext<'a>) -> Result<(), TraceError> + Send + Sync + 'static,
{
    fn on_trace(&self, context: &EventContext<'_>) -> Result<(), TraceError> {
        self(context)
    }
}

/// A trace handler that ignores every trace.
#[derive(Debug, Default)]
pub struct NoopTraceHandler;

impl TraceHandler for NoopTraceHandler {
    fn on_trace(&self, _context: &EventContext<'_>) -> Result<(), TraceError> {
        Ok(())
    }
}
