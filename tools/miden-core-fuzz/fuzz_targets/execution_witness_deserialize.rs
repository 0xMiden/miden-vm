//! Fuzz target for bounded `ExecutionWitness` deserialization.
//!
//! Run with: cargo +nightly fuzz run execution_witness_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_processor::ExecutionWitness;

fuzz_target!(|data: &[u8]| {
    let _ = ExecutionWitness::read_from_bytes(data);
});
