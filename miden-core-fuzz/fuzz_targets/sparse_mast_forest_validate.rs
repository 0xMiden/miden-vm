//! Fuzz target for sparse MAST deserialization with explicit budgets.
//!
//! Run with: cargo +nightly fuzz run sparse_mast_forest_validate --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::mast::{SparseMastForest, SparseMastForestReadOptions};

fuzz_target!(|data: &[u8]| {
    let small_budget_options = SparseMastForestReadOptions::new().with_wire_byte_budget(64);
    let explicit_budget_options =
        SparseMastForestReadOptions::new().with_wire_byte_budget(data.len());

    let _ = SparseMastForest::read_from_bytes(data);
    let _ = SparseMastForest::read_from_bytes_with_options(data, small_budget_options);
    let _ = SparseMastForest::read_from_bytes_with_options(data, explicit_budget_options);
});
