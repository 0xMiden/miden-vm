//! Fuzz target for Program serde deserialization.
//!
//! Run with: cargo +nightly fuzz run program_serde_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::program::Program;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Program>(data);
    let _ = serde_json::from_slice::<Vec<Program>>(data);
    let _ = serde_json::from_slice::<Option<Program>>(data);
});
