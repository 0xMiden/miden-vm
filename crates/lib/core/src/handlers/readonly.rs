//! No-op event handlers that never produce advice mutations and are therefore safe to ignore.
//! Hosts that want to handle these events are expected to replace the no-op handlers.
//!
//! This enables communicating readonly events to hosts importing the core library without having
//! to manually add these no-op handlers. This is a temporary solution. In the long-term, events
//! themselves should be marked as readonly.

use alloc::{sync::Arc, vec, vec::Vec};

use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler, EventName},
};

// EVENT NAMES
// ================================================================================================
//
// Only the debugger cares about `READONLY_MIDEN_DEBUG_*` events.

/// Marks the start of a debug trace frame.
pub const READONLY_MIDEN_DEBUG_FRAME_START: EventName =
    EventName::new("readonly::miden_debug::frame_start");
/// Marks the end of a debug trace frame.
pub const READONLY_MIDEN_DEBUG_FRAME_END: EventName =
    EventName::new("readonly::miden_debug::frame_end");
/// Emitted when an assertion in a debug trace fails.
pub const READONLY_MIDEN_DEBUG_ASSERTION_FAILED: EventName =
    EventName::new("readonly::miden_debug::assertion_failed");
/// Emitted for an unrecognized debug trace event.
pub const READONLY_MIDEN_DEBUG_UNKNOWN: EventName =
    EventName::new("readonly::miden_debug::unknown");
/// Emitted by the Rust sdk's `println`.
pub const READONLY_MIDEN_DEBUG_PRINTLN: EventName =
    EventName::new("readonly::miden_debug::println");

struct ReadonlyNoopHandler;

impl EventHandler for ReadonlyNoopHandler {
    fn on_event(&self, _process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(vec![])
    }
}

/// Returns no-op handlers for all readonly events.
pub fn readonly_noop_handlers() -> Vec<(EventName, Arc<dyn EventHandler>)> {
    let handler: Arc<dyn EventHandler> = Arc::new(ReadonlyNoopHandler);
    vec![
        (READONLY_MIDEN_DEBUG_FRAME_START, handler.clone()),
        (READONLY_MIDEN_DEBUG_FRAME_END, handler.clone()),
        (READONLY_MIDEN_DEBUG_ASSERTION_FAILED, handler.clone()),
        (READONLY_MIDEN_DEBUG_UNKNOWN, handler.clone()),
        (READONLY_MIDEN_DEBUG_PRINTLN, handler),
    ]
}
