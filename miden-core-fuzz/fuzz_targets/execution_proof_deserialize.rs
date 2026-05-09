//! Fuzz target for ExecutionProof deserialization.
//!
//! Run with: cargo +nightly fuzz run execution_proof_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{proof::ExecutionProof, serde::Deserializable};

fuzz_target!(|data: &[u8]| {
    let _ = ExecutionProof::from_bytes(data);
    let _ = ExecutionProof::read_from_bytes(data);
    let _ = Vec::<ExecutionProof>::read_from_bytes(data);
    let _ = Option::<ExecutionProof>::read_from_bytes(data);
});
