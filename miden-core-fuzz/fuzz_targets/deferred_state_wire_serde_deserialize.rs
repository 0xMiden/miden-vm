//! Fuzz target for DeferredStateWire serde deserialization.
//!
//! Run with: cargo +nightly fuzz run deferred_state_wire_serde_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::deferred::DeferredStateWire;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<DeferredStateWire>(data);
    let _ = serde_json::from_slice::<Vec<DeferredStateWire>>(data);
    let _ = serde_json::from_slice::<Option<DeferredStateWire>>(data);
});
