//! Fuzz target for UntrustedMastForest deserialization and validation.
//!
//! This target tests the full untrusted deserialization pipeline:
//! 1. UntrustedMastForest::read_from_bytes (deserialization)
//! 2. UntrustedMastForest::validate() (structural + hash validation)
//!
//! The validation path should never panic on any input.
//!
//! Run with: cargo +nightly fuzz run mast_forest_validate --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::mast::UntrustedMastForest;

fuzz_target!(|data: &[u8]| {
    // Test the full untrusted deserialization + validation pipeline
    let Ok(untrusted) = UntrustedMastForest::read_from_bytes(data) else {
        return;
    };

    // Validation should never panic, even on malformed forests
    let _ = untrusted.validate();

    // Also test into_inner (the escape hatch) doesn't panic
    let _ = untrusted_clone.into_inner();
});
