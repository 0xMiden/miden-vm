//! Fuzz target for KernelDescriptor serde deserialization.
//!
//! Run with: cargo +nightly fuzz run kernel_serde_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::program::KernelDescriptor;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<KernelDescriptor>(data);
    let _ = serde_json::from_slice::<Vec<KernelDescriptor>>(data);
    let _ = serde_json::from_slice::<Option<KernelDescriptor>>(data);
});
