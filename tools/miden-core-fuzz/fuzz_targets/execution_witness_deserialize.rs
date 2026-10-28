//! Fuzz target for bounded `ExecutionWitness` deserialization.
//!
//! Run with: cargo +nightly fuzz run execution_witness_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_processor::{serde::Serializable, ExecutionWitness};

fuzz_target!(|data: &[u8]| {
    if let Ok(witness) = ExecutionWitness::read_from_bytes(data) {
        // STABILITY ORACLE (upgraded from crash-only): byte-level, since ExecutionWitness
        // has no PartialEq — decode -> encode -> decode -> encode must reproduce the
        // canonical encoding exactly. Catches encode non-determinism and
        // decode-fails-own-writer (scoped per the two-cycle-oracle rule).
        let canonical = witness.to_bytes();
        let redecoded =
            ExecutionWitness::read_from_bytes(&canonical).expect("canonical encoding must decode");
        let recanonical = redecoded.to_bytes();
        assert_eq!(
            recanonical, canonical,
            "decode -> encode must be byte-stable",
        );
    }
});
