//! Fuzz target for ExecutionProof deserialization.
//!
//! Run with: cargo +nightly fuzz run execution_proof_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::proof::ExecutionProof;

fuzz_target!(|data: &[u8]| {
    if let Ok(proof) = ExecutionProof::read_from_bytes(data) {
        let encoded = proof.to_bytes();
        assert_eq!(encoded, data);
        assert_eq!(ExecutionProof::read_from_bytes(&encoded), Ok(proof));
    }
});
