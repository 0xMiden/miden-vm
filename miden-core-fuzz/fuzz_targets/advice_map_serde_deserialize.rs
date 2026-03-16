//! Fuzz target for AdviceMap serde deserialization.
//!
//! Run with: cargo +nightly fuzz run advice_map_serde_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::advice::AdviceMap;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<AdviceMap>(data);
    let _ = serde_json::from_slice::<Vec<AdviceMap>>(data);
    let _ = serde_json::from_slice::<Option<AdviceMap>>(data);
});
