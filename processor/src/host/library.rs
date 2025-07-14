use alloc::{boxed::Box, sync::Arc, vec::Vec};

use miden_core::mast::MastForest;

use crate::EventHandler;

/// A wrapper trait for a [`MastForest`] which also exports a list of handlers for events it
/// supports.
pub trait MastForestSource {
    fn mast_forest(&self) -> Arc<MastForest>;

    fn event_handlers(&self) -> Vec<(u32, Box<dyn EventHandler>)> {
        Vec::default()
    }
}

// Default implementation for a single [`MastForest`] which is interpreted as a library without
// handlers.
impl MastForestSource for Arc<MastForest> {
    fn mast_forest(&self) -> Arc<MastForest> {
        self.clone()
    }
}
