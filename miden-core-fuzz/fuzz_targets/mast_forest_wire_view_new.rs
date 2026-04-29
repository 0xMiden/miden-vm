//! Fuzz target for MastForestWireView trusted wire-backed access.
//!
//! This target focuses on the trusted inspection path exposed by
//! `MastForestWireView::new()`. It exercises layout scanning and cheap random-access helpers
//! without going through full trusted or untrusted materialization.
//!
//! Run with: cargo +nightly fuzz run mast_forest_wire_view_new --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::mast::MastForestWireView;

fuzz_target!(|data: &[u8]| {
    let Ok(view) = MastForestWireView::new(data) else {
        return;
    };

    let _ = view.is_stripped();
    let root_count = view.procedure_root_count();
    let node_count = view.node_count();

    if root_count > 0 {
        let last_root = root_count - 1;
        let _ = view.procedure_root_at(0);
        let _ = view.procedure_root_at(last_root);
    }

    if node_count > 0 {
        let last_node = node_count - 1;
        let _ = view.node_entry_at(0);
        let _ = view.node_entry_at(last_node);
    }
});
