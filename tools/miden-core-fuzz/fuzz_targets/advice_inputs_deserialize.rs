//! Fuzz target for AdviceInputs and AdviceMap deserialization.
//!
//! Run with: cargo +nightly fuzz run advice_inputs_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{advice::{AdviceInputs, AdviceMap}, serde::{Deserializable, Serializable}};

fuzz_target!(|data: &[u8]| {
    // STABILITY ORACLE (upgraded from crash-only): a successful decode must be stable
    // under canonical re-encoding — re-encode the decoded value, decode again, and the
    // result must equal the first decode. Catches decode-side semantic drift, not just
    // panics/hangs. (AdviceMap duplicate keys are rejected at decode, so decoded maps
    // re-encode canonically.)
    if let Ok(inputs) = AdviceInputs::read_from_bytes(data) {
        let canonical = inputs.to_bytes();
        let redecoded = AdviceInputs::read_from_bytes(&canonical)
            .expect("canonical AdviceInputs encoding must decode");
        assert_eq!(redecoded, inputs, "canonical re-encoding must decode identically");
    }
    let _ = Vec::<AdviceInputs>::read_from_bytes(data);
    let _ = Option::<AdviceInputs>::read_from_bytes(data);
    let _ = AdviceMap::read_from_bytes(data);
    let _ = Vec::<AdviceMap>::read_from_bytes(data);
    let _ = Option::<AdviceMap>::read_from_bytes(data);
});
