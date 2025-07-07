use alloc::{boxed::Box, sync::Arc, vec::Vec};

use vm_core::mast::MastForest;

use crate::EventHandler;

/// A wrapper trait for a library which also exports a list of handlers for events it supports.
pub trait HostLibrary {
    fn mast_forest(&self) -> Arc<MastForest>;

    fn event_handlers(&self) -> Vec<(u32, Box<dyn EventHandler>)> {
        Vec::default()
    }
}

// Default implementation for a single [`MastForest`] which is interpreted as a library without
// handlers.
impl HostLibrary for Arc<MastForest> {
    fn mast_forest(&self) -> Arc<MastForest> {
        self.clone()
    }
}
