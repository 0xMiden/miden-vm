//! Fuzz target for MastForest deserialization.
//!
//! This target feeds arbitrary byte sequences to MastForest::read_from_bytes
//! to find panics, crashes, or undefined behavior in the deserialization path.
//!
//! Run with: cargo +nightly fuzz run mast_forest_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{mast::MastForest, utils::Deserializable};

fuzz_target!(|data: &[u8]| {
    // Primary target: raw MastForest deserialization
    // This should never panic - all errors should be returned as Result::Err
    let _ = MastForest::read_from_bytes(data);

    // Also test Vec<MastForest> deserialization (tests length prefix handling)
    let _ = Vec::<MastForest>::read_from_bytes(data);

    // Test Option<MastForest> deserialization
    let _ = Option::<MastForest>::read_from_bytes(data);
});
