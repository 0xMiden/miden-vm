//! Fuzz target for Program deserialization.
//!
//! Run with: cargo +nightly fuzz run program_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{program::Program, serde::{Deserializable, Serializable}};

fuzz_target!(|data: &[u8]| {
    // STABILITY ORACLE (upgraded from crash-only): Program has Eq, so the oracle is
    // VALUE-level — a successful decode must re-encode and decode again to an EQUAL
    // value. Corpus reachability measured at 28/684 (program::claim scratch,).
    if let Ok(program) = Program::read_from_bytes(data) {
        let canonical = program.to_bytes();
        let redecoded = Program::read_from_bytes(&canonical).expect("canonical encoding must decode");
        assert_eq!(redecoded, program, "canonical re-encoding must decode identically");
    }
    let _ = ();
    let _ = Vec::<Program>::read_from_bytes(data);
    let _ = Option::<Program>::read_from_bytes(data);
});
