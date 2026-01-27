//! Fuzz target for BasicBlockData deserialization.
//!
//! BasicBlockData contains operation batches with:
//! - indptr arrays (operation group boundaries)
//! - padding metadata
//! - group data (Felt values)
//!
//! This is exercised through the full MastForest deserialization path.
//!
//! Run with: cargo +nightly fuzz run basic_block_data --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{mast::MastForest, utils::Deserializable};

fuzz_target!(|data: &[u8]| {
    // BasicBlockData is internal, exercised through MastForest deserialization
    // The fuzzer will discover inputs with valid headers that reach BB parsing
    let _ = MastForest::read_from_bytes(data);
});
