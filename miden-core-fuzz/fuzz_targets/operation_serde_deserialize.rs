//! Fuzz target for Operation serde deserialization.
//!
//! Run with: cargo +nightly fuzz run operation_serde_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::operations::Operation;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Operation>(data);
    let _ = serde_json::from_slice::<Vec<Operation>>(data);
    let _ = serde_json::from_slice::<Option<Operation>>(data);
});
