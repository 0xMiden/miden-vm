//! Fuzz target for AdviceInputs and AdviceMap deserialization.
//!
//! Run with: cargo +nightly fuzz run advice_inputs_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{advice::{AdviceInputs, AdviceMap}, serde::Deserializable};

fuzz_target!(|data: &[u8]| {
    let _ = AdviceInputs::read_from_bytes(data);
    let _ = Vec::<AdviceInputs>::read_from_bytes(data);
    let _ = Option::<AdviceInputs>::read_from_bytes(data);
    let _ = AdviceMap::read_from_bytes(data);
    let _ = Vec::<AdviceMap>::read_from_bytes(data);
    let _ = Option::<AdviceMap>::read_from_bytes(data);
});
