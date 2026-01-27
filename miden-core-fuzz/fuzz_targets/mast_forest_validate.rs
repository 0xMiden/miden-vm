//! Fuzz target for UntrustedMastForest deserialization and validation.
//!
//! This target tests the full untrusted deserialization pipeline:
//! 1. UntrustedMastForest::read_from_bytes (budgeted deserialization)
//! 2. UntrustedMastForest::validate() (structural + hash validation)
//! 3. UntrustedMastForest::read_from_bytes_with_budget with small budget
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

    // Test budgeted deserialization with a very small budget
    // This should reject most inputs early without panicking
    let _ = UntrustedMastForest::read_from_bytes_with_budget(data, 64);
});
