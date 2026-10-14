//! Fuzz target for Package deserialization.
//!
//! Run with: cargo +nightly fuzz run package_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::serde::{Deserializable, Serializable};
use miden_mast_package::Package;

fuzz_target!(|data: &[u8]| {
    let budget = data.len().saturating_mul(64);

    // STABILITY ORACLE (upgraded from crash-only): Package has Eq, so the oracle is
    // VALUE-level — a successful decode must re-encode and decode again to an EQUAL
    // value. Seeded per the reachability rule (18 writer-produced .bin seeds committed).
    if let Ok(package) = Package::read_from_bytes(data) {
        let canonical = package.to_bytes();
        let redecoded =
            Package::read_from_bytes(&canonical).expect("canonical encoding must decode");
        assert_eq!(redecoded, package, "canonical re-encoding must decode identically");
    }
    let _ = Vec::<Package>::read_from_bytes_with_budget(data, budget);
    let _ = Option::<Package>::read_from_bytes_with_budget(data, budget);
});
