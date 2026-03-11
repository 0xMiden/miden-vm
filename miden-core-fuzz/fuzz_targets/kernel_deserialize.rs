//! Fuzz target for Kernel deserialization.
//!
//! Run with: cargo +nightly fuzz run kernel_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{program::Kernel, serde::Deserializable};

fuzz_target!(|data: &[u8]| {
    let _ = Kernel::read_from_bytes(data);
    let _ = Vec::<Kernel>::read_from_bytes(data);
    let _ = Option::<Kernel>::read_from_bytes(data);
});
