//! Fuzz target for DeferredStateWire deserialization.
//!
//! Run with: cargo +nightly fuzz run deferred_state_wire_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{deferred::DeferredStateWire, serde::Deserializable};

fuzz_target!(|data: &[u8]| {
    let _ = DeferredStateWire::read_from_bytes(data);
    let _ = Vec::<DeferredStateWire>::read_from_bytes(data);
    let _ = Option::<DeferredStateWire>::read_from_bytes(data);
});
