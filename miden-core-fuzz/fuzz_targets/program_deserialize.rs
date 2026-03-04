//! Fuzz target for Program deserialization.
//!
//! Run with: cargo +nightly fuzz run program_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{program::Program, serde::Deserializable};

fuzz_target!(|data: &[u8]| {
    let _ = Program::read_from_bytes(data);
    let _ = Vec::<Program>::read_from_bytes(data);
    let _ = Option::<Program>::read_from_bytes(data);
});
