//! Fuzz target for KernelDescriptor deserialization.
//!
//! Run with: cargo +nightly fuzz run kernel_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{
    program::KernelDescriptor,
    serde::{Deserializable, Serializable},
};

fuzz_target!(|data: &[u8]| {
    // STABILITY ORACLE (upgraded from crash-only): KernelDescriptor has Eq, so the
    // oracle is VALUE-level — a successful decode must re-encode and decode again to
    // an EQUAL value. Corpus reachability measured per the reachability rule ().
    if let Ok(kernel) = KernelDescriptor::read_from_bytes(data) {
        let canonical = kernel.to_bytes();
        let redecoded =
            KernelDescriptor::read_from_bytes(&canonical).expect("canonical encoding must decode");
        assert_eq!(redecoded, kernel, "canonical re-encoding must decode identically");
    }
    let _ = Vec::<KernelDescriptor>::read_from_bytes(data);
    let _ = Option::<KernelDescriptor>::read_from_bytes(data);
});
