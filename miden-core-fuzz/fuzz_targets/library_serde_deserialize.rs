//! Fuzz target for Library serde deserialization.
//!
//! Run with: cargo +nightly fuzz run library_serde_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_assembly_syntax::Library;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Library>(data);
    let _ = serde_json::from_slice::<Vec<Library>>(data);
    let _ = serde_json::from_slice::<Option<Library>>(data);
});
