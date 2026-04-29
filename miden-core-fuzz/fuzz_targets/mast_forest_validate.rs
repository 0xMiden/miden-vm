//! Fuzz target for UntrustedMastForest deserialization and validation.
//!
//! This target tests the full untrusted deserialization pipeline:
//! 1. UntrustedMastForest::read_from_bytes (budgeted deserialization)
//! 2. UntrustedMastForest::validate() (structural + hash validation)
//! 3. Explicit option-based parsing and validation budgets
//!
//! The validation path should never panic on any input.
//!
//! Run with: cargo +nightly fuzz run mast_forest_validate --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{
    mast::{UntrustedMastForest, UntrustedMastForestReadOptions},
    serde::DeserializationError,
};

fuzz_target!(|data: &[u8]| {
    let validate_untrusted = |result: Result<UntrustedMastForest, DeserializationError>| {
        if let Ok(untrusted) = result {
            let _ = untrusted.validate();
        }
    };
    let small_budget_options =
        UntrustedMastForestReadOptions::new().with_wire_byte_budget(64);
    let explicit_budget_options = UntrustedMastForestReadOptions::new()
        .with_wire_byte_budget(data.len())
        .with_validation_allocation_budget(data.len());

    // Test the full untrusted deserialization + validation pipeline.
    validate_untrusted(UntrustedMastForest::read_from_bytes(data));

    // Test budgeted deserialization with a very small budget
    // This should reject most inputs early without panicking
    validate_untrusted(UntrustedMastForest::read_from_bytes_with_options(
        data,
        small_budget_options,
    ));
    validate_untrusted(UntrustedMastForest::read_from_bytes_with_options(
        data,
        explicit_budget_options,
    ));
});
