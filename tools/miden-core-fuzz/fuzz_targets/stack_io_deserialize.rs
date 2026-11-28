//! Fuzz target for StackInputs and StackOutputs deserialization.
//!
//! Run with: cargo +nightly fuzz run stack_io_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{
    program::{StackInputs, StackOutputs},
    serde::{Deserializable, Serializable},
};

fuzz_target!(|data: &[u8]| {
    // STABILITY ORACLE (upgraded from crash-only): both types have Eq, so the oracle is
    // VALUE-level — a successful decode must re-encode and decode again to an EQUAL
    // value. Corpus reachability measured per the reachability rule: 34/67 for EACH type.
    if let Ok(inputs) = StackInputs::read_from_bytes(data) {
        let canonical = inputs.to_bytes();
        let redecoded =
            StackInputs::read_from_bytes(&canonical).expect("canonical encoding must decode");
        assert_eq!(redecoded, inputs, "StackInputs re-encoding must decode identically");
    }
    if let Ok(outputs) = StackOutputs::read_from_bytes(data) {
        let canonical = outputs.to_bytes();
        let redecoded =
            StackOutputs::read_from_bytes(&canonical).expect("canonical encoding must decode");
        assert_eq!(redecoded, outputs, "StackOutputs re-encoding must decode identically");
    }
    let _ = Vec::<StackInputs>::read_from_bytes(data);
    let _ = Option::<StackInputs>::read_from_bytes(data);
    let _ = Vec::<StackOutputs>::read_from_bytes(data);
    let _ = Option::<StackOutputs>::read_from_bytes(data);
});
