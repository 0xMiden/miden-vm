use alloc::boxed::Box;
use core::error::Error;

use crate::{AdviceRecorder, EventContext, InvocationKind};

/// A handler error, preserving concrete errors for downstream downcasting.
pub type EventError = Box<dyn Error + Send + Sync + 'static>;

/// Handles regular events and optional traces through the same portable interface.
pub trait EventHandler: Send + Sync + 'static {
    /// Reads pre-callback state and records pending advice. The engine completes the whole batch
    /// only after the top-level host callback succeeds. Traces must not record advice.
    fn handle(
        &self,
        context: EventContext<'_>,
        advice: &mut AdviceRecorder<'_>,
    ) -> Result<(), EventError>;
}

impl<F> EventHandler for F
where
    F: Fn(EventContext<'_>, &mut AdviceRecorder<'_>) -> Result<(), EventError>
        + Send
        + Sync
        + 'static,
{
    fn handle(
        &self,
        context: EventContext<'_>,
        advice: &mut AdviceRecorder<'_>,
    ) -> Result<(), EventError> {
        self(context, advice)
    }
}

/// A handler that ignores both invocation kinds without recording advice.
#[derive(Debug, Default)]
pub struct NoopHandler;

impl EventHandler for NoopHandler {
    fn handle(
        &self,
        _context: EventContext<'_>,
        _advice: &mut AdviceRecorder<'_>,
    ) -> Result<(), EventError> {
        Ok(())
    }
}

/// A handler was invoked with a kind it does not support.
#[derive(Debug, thiserror::Error)]
#[error("unsupported invocation kind {actual:?}; expected {expected:?}")]
pub struct UnsupportedInvocationKind {
    pub expected: InvocationKind,
    pub actual: InvocationKind,
}

impl InvocationKind {
    /// Checks a handler's supported kind before it performs reads or side effects.
    pub fn require(self, expected: Self) -> Result<(), UnsupportedInvocationKind> {
        if self == expected {
            Ok(())
        } else {
            Err(UnsupportedInvocationKind { expected, actual: self })
        }
    }
}
