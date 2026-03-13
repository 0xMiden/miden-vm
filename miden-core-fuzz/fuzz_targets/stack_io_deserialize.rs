//! Fuzz target for StackInputs and StackOutputs deserialization.
//!
//! Run with: cargo +nightly fuzz run stack_io_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{program::{StackInputs, StackOutputs}, serde::Deserializable};

fuzz_target!(|data: &[u8]| {
    let _ = StackInputs::read_from_bytes(data);
    let _ = Vec::<StackInputs>::read_from_bytes(data);
    let _ = Option::<StackInputs>::read_from_bytes(data);
    let _ = StackOutputs::read_from_bytes(data);
    let _ = Vec::<StackOutputs>::read_from_bytes(data);
    let _ = Option::<StackOutputs>::read_from_bytes(data);
});
