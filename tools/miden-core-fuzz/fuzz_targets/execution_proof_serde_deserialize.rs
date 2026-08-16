//! Fuzz target for `ExecutionProof` Serde parser robustness.
//!
//! This target does not establish proof validity or claim allocation-bounded generic Serde.
//! Run with: cargo +nightly fuzz run execution_proof_serde_deserialize --fuzz-dir
//! tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::proof::ExecutionProof;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<ExecutionProof>(data);
    let _ = serde_json::from_slice::<Vec<ExecutionProof>>(data);
    let _ = serde_json::from_slice::<Option<ExecutionProof>>(data);
});
