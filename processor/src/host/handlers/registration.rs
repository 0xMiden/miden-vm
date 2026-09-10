//! Shared portable handler registrations. Concrete handlers, functions, and typed closures convert
//! automatically; use [`EventHandler::shared`] to reuse an existing `Arc`.

use alloc::sync::Arc;

use miden_event_handler::EventHandler as PortableEventHandler;

/// A shared portable handler for both invocation kinds.
#[derive(Clone)]
pub struct EventHandler(Arc<dyn PortableEventHandler>);

impl EventHandler {
    /// Reuses a shared handler without another allocation.
    pub fn shared(handler: Arc<dyn PortableEventHandler>) -> Self {
        Self(handler)
    }
}

impl AsRef<dyn PortableEventHandler> for EventHandler {
    fn as_ref(&self) -> &(dyn PortableEventHandler + 'static) {
        self.0.as_ref()
    }
}

impl<H: PortableEventHandler> From<H> for EventHandler {
    fn from(handler: H) -> Self {
        Self::shared(Arc::new(handler))
    }
}
