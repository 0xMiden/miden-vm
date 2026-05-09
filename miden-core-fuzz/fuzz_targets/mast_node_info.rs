//! Fuzz target for MastNodeInfo deserialization.
//!
//! MastNodeInfo is a fixed-width structure (8 bytes node entry + 32 bytes digest = 40 bytes).
//! This target exercises `MastNodeEntry` decoding plus `MastNodeInfo` materialization through the
//! serialized-view API.
//!
//! Run with: cargo +nightly fuzz run mast_node_info --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::mast::SerializedMastForest;

fuzz_target!(|data: &[u8]| {
    let Ok(view) = SerializedMastForest::new(data) else {
        return;
    };

    if view.node_count() == 0 {
        return;
    }

    let last = view.node_count() - 1;

    let _ = view.node_entry_at(0);
    let _ = view.node_info_at(0);
    let _ = view.node_digest_at(0);

    let _ = view.node_entry_at(last);
    let _ = view.node_info_at(last);
    let _ = view.node_digest_at(last);
});
