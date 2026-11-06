//! Fuzz target for MastForest deserialization.
//!
//! This target feeds arbitrary byte sequences to MastForest::read_from_bytes
//! to find panics, crashes, or undefined behavior in the deserialization path.
//!
//! Run with: cargo +nightly fuzz run mast_forest_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{mast::MastForest, serde::{Deserializable, Serializable}};

fuzz_target!(|data: &[u8]| {
    let budget = data.len().saturating_mul(64);

    // Primary target: raw MastForest deserialization
    // This should never panic - all errors should be returned as Result::Err
    if let Ok(forest) = MastForest::read_from_bytes(data) {
        // STABILITY ORACLE (upgraded from crash-only): decode -> encode must be
        // BYTE-STABLE — re-decoding the canonical encoding and re-encoding again must
        // reproduce it exactly (MastForest has no PartialEq, so stability is asserted
        // at the byte level). Catches decode-side canonicalization drift.
        let canonical = forest.to_bytes();
        let redecoded =
            MastForest::read_from_bytes(&canonical).expect("canonical encoding must decode");
        let recanonical = redecoded.to_bytes();
        assert_eq!(
            recanonical, canonical,
            "decode -> encode must be byte-stable",
        );
    }

    // Also test Vec<MastForest> deserialization (tests length prefix handling)
    let _ = Vec::<MastForest>::read_from_bytes_with_budget(data, budget);

    // Test Option<MastForest> deserialization
    let _ = Option::<MastForest>::read_from_bytes_with_budget(data, budget);
});
