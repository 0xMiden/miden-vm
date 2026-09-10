//! Default no-op handlers for debugger observation events.
//! Hosts that want to handle these events are expected to replace the no-op handlers.
//!
//! These defaults accept either invocation kind. A custom handler may perform required host
//! bookkeeping without producing advice; such bookkeeping must remain a regular event.

use alloc::{vec, vec::Vec};

use miden_core::events::EventName;
use miden_event_handler::NoopHandler;
use miden_processor::event::registration;

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

/// Returns no-op handlers for all readonly events.
pub fn readonly_noop_event_handlers() -> Vec<(EventName, registration::EventHandler)> {
    let handler: registration::EventHandler = NoopHandler.into();
    vec![
        (READONLY_MIDEN_DEBUG_FRAME_START, handler.clone()),
        (READONLY_MIDEN_DEBUG_FRAME_END, handler.clone()),
        (READONLY_MIDEN_DEBUG_ASSERTION_FAILED, handler.clone()),
        (READONLY_MIDEN_DEBUG_UNKNOWN, handler.clone()),
        (READONLY_MIDEN_DEBUG_PRINTLN, handler),
    ]
}

/// Legacy event-only handler list; use `readonly_noop_event_handlers` for unified delivery.
pub fn readonly_noop_handlers()
-> Vec<(EventName, alloc::sync::Arc<dyn miden_processor::event::EventHandler>)> {
    super::legacy_handlers(readonly_noop_event_handlers())
}
