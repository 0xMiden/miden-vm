//! Fuzz target for Kernel serde deserialization.
//!
//! Run with: cargo +nightly fuzz run kernel_serde_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::program::Kernel;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Kernel>(data);
    let _ = serde_json::from_slice::<Vec<Kernel>>(data);
    let _ = serde_json::from_slice::<Option<Kernel>>(data);
});
