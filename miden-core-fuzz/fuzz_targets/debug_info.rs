//! Fuzz target for DebugInfo deserialization.
//!
//! DebugInfo contains:
//! - Decorator data (variable-length payloads)
//! - String table (deduplicated strings)
//! - Decorator infos
//! - Error codes map
//! - CSR structures (OpToDecoratorIds, NodeToDecoratorIds)
//! - Procedure names map
//!
//! Run with: cargo +nightly fuzz run debug_info --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{mast::MastForest, utils::Deserializable};

fuzz_target!(|data: &[u8]| {
    // DebugInfo is deserialized as part of MastForest (when flags byte is 0x00)
    // The fuzzer will discover paths through the debug info parsing code
    let _ = MastForest::read_from_bytes(data);
});
