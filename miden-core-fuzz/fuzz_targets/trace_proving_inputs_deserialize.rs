//! Fuzz target for TraceProvingInputs deserialization.
//!
//! This target feeds arbitrary byte sequences to the bounded remote proving input reader. It should
//! reject malformed inputs with errors rather than panicking.
//!
//! Run with: cargo +nightly fuzz run trace_proving_inputs_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_prover::TraceProvingInputs;

fuzz_target!(|data: &[u8]| {
    let explicit_budget = data.len().saturating_mul(64);

    let _ = TraceProvingInputs::read_from_bytes_with_budget(data, 64);
    let _ = TraceProvingInputs::read_from_bytes_with_budget(data, explicit_budget);
});
