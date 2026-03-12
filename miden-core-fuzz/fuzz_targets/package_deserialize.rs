//! Fuzz target for Package deserialization.
//!
//! Run with: cargo +nightly fuzz run package_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::serde::Deserializable;
use miden_mast_package::Package;

fuzz_target!(|data: &[u8]| {
    let _ = Package::read_from_bytes(data);
    let _ = Vec::<Package>::read_from_bytes(data);
    let _ = Option::<Package>::read_from_bytes(data);
});
