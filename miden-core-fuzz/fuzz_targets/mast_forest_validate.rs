//! Fuzz target for UntrustedMastForest deserialization and validation.
//!
//! This target tests the full untrusted deserialization pipeline:
//! 1. UntrustedMastForest::read_from_bytes (budgeted deserialization)
//! 2. UntrustedMastForest::validate() (structural + hash validation)
//! 3. Budgeted parsing-only and parsing+validation entry points
//! 4. Flag-returning variants for callers that need serializer intent bits
//!
//! The validation path should never panic on any input.
//!
//! Run with: cargo +nightly fuzz run mast_forest_validate --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{mast::UntrustedMastForest, serde::DeserializationError};

fuzz_target!(|data: &[u8]| {
    let validate_untrusted = |result: Result<UntrustedMastForest, DeserializationError>| {
        if let Ok(untrusted) = result {
            let _ = untrusted.validate();
        }
    };
    let validate_untrusted_with_flags =
        |result: Result<(UntrustedMastForest, u8), DeserializationError>| {
            if let Ok((untrusted, _flags)) = result {
                let _ = untrusted.validate();
            }
        };

    // Test the full untrusted deserialization + validation pipeline
    let Ok(untrusted) = UntrustedMastForest::read_from_bytes(data) else {
        // Even if the default path rejects early, exercise the explicit-budget variants too.
        validate_untrusted(UntrustedMastForest::read_from_bytes_with_budget(data, 64));
        validate_untrusted_with_flags(UntrustedMastForest::read_from_bytes_with_budget_and_flags(
            data, 64,
        ));
        validate_untrusted(UntrustedMastForest::read_from_bytes_with_budgets(
            data,
            data.len(),
            data.len(),
        ));
        validate_untrusted_with_flags(UntrustedMastForest::read_from_bytes_with_budgets_and_flags(
            data,
            data.len(),
            data.len(),
        ));
        validate_untrusted_with_flags(UntrustedMastForest::read_from_bytes_with_flags(data));
        return;
    };

    // Validation should never panic, even on malformed forests
    let _ = untrusted.validate();

    // Test budgeted deserialization with a very small budget
    // This should reject most inputs early without panicking
    validate_untrusted(UntrustedMastForest::read_from_bytes_with_budget(data, 64));
    validate_untrusted_with_flags(UntrustedMastForest::read_from_bytes_with_budget_and_flags(
        data, 64,
    ));
    validate_untrusted(UntrustedMastForest::read_from_bytes_with_budgets(
        data,
        data.len(),
        data.len(),
    ));
    validate_untrusted_with_flags(UntrustedMastForest::read_from_bytes_with_budgets_and_flags(
        data,
        data.len(),
        data.len(),
    ));
    validate_untrusted_with_flags(UntrustedMastForest::read_from_bytes_with_flags(data));
});
