//! Fuzz target for PrecompileRequest serde deserialization.
//!
//! Run with: cargo +nightly fuzz run precompile_request_serde_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::precompile::PrecompileRequest;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<PrecompileRequest>(data);
    let _ = serde_json::from_slice::<Vec<PrecompileRequest>>(data);
    let _ = serde_json::from_slice::<Option<PrecompileRequest>>(data);
});
