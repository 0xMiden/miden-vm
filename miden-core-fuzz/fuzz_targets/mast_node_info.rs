//! Fuzz target for MastNodeInfo deserialization.
//!
//! MastNodeInfo is a fixed-width structure (8 bytes type + 32 bytes digest = 40 bytes).
//! This tests the MastNodeType discriminant parsing and payload extraction.
//!
//! Run with: cargo +nightly fuzz run mast_node_info --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;

// Note: MastNodeInfo is pub(crate), so we test via the full deserialization path
// with crafted inputs that exercise node info parsing specifically.

use miden_core::{mast::MastForest, utils::Deserializable};

fuzz_target!(|data: &[u8]| {
    // MastNodeInfo is internal, but we can exercise it through MastForest
    // The fuzzer will find inputs that reach the node info parsing code
    let _ = MastForest::read_from_bytes(data);
});
