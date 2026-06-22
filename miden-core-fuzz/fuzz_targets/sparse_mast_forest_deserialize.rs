//! Fuzz target for SparseMastForest deserialization.
//!
//! Run with: cargo +nightly fuzz run sparse_mast_forest_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{mast::SparseMastForest, serde::Deserializable};

fuzz_target!(|data: &[u8]| {
    let budget = data.len().saturating_mul(64);

    let _ = SparseMastForest::read_from_bytes(data);
    let _ = Vec::<SparseMastForest>::read_from_bytes_with_budget(data, budget);
    let _ = Option::<SparseMastForest>::read_from_bytes_with_budget(data, budget);
});
