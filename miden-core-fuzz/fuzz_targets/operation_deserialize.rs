//! Fuzz target for Operation deserialization.
//!
//! Run with: cargo +nightly fuzz run operation_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{operations::Operation, serde::Deserializable};

fuzz_target!(|data: &[u8]| {
    let _ = Operation::read_from_bytes(data);
    let _ = Vec::<Operation>::read_from_bytes(data);
    let _ = Option::<Operation>::read_from_bytes(data);
});
