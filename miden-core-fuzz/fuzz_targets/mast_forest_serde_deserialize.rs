//! Fuzz target for MastForest serde deserialization.
//!
//! Run with: cargo +nightly fuzz run mast_forest_serde_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::mast::MastForest;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<MastForest>(data);
    let _ = serde_json::from_slice::<Vec<MastForest>>(data);
    let _ = serde_json::from_slice::<Option<MastForest>>(data);
});
