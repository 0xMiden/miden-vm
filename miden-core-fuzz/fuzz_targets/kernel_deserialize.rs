//! Fuzz target for KernelDescriptor deserialization.
//!
//! Run with: cargo +nightly fuzz run kernel_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{program::KernelDescriptor, serde::Deserializable};

fuzz_target!(|data: &[u8]| {
    let _ = KernelDescriptor::read_from_bytes(data);
    let _ = Vec::<KernelDescriptor>::read_from_bytes(data);
    let _ = Option::<KernelDescriptor>::read_from_bytes(data);
});
