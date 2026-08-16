//! Fuzz target for ExecutionProof deserialization.
//!
//! Run with: cargo +nightly fuzz run execution_proof_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::proof::ExecutionProof;

fuzz_target!(|data: &[u8]| {
    let _ = ExecutionProof::read_from_bytes(data);
});
