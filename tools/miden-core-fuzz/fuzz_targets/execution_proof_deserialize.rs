//! Fuzz target for VersionedProof deserialization.
//!
//! Run with: cargo +nightly fuzz run execution_proof_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::proof::VersionedProof;

fuzz_target!(|data: &[u8]| {
    let _ = VersionedProof::read_from_bytes(data);
});
