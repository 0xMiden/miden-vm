//! Fuzz target for Package serde deserialization.
//!
//! Run with: cargo +nightly fuzz run package_serde_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_mast_package::Package;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Package>(data);
    let _ = serde_json::from_slice::<Vec<Package>>(data);
    let _ = serde_json::from_slice::<Option<Package>>(data);
});
