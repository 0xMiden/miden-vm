//! Fuzz target for package debug info deserialization.
//!
//! Package-owned debug info contains source/type/function sections and source-keyed MAST
//! occurrence metadata.
//!
//! Run with: cargo +nightly fuzz run debug_info --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::serde::{Deserializable, SliceReader};
use miden_mast_package::{Package, debug_info::PackageDebugInfo};

fuzz_target!(|data: &[u8]| {
    if let Ok(package) = Package::read_from_bytes(data) {
        let _ = package.debug_info();
    }
    if let Ok(package) = Package::read_from_bytes_trusted(data) {
        let _ = package.debug_info();
    }

    let mut reader = SliceReader::new(data);
    let _ = PackageDebugInfo::read_from(&mut reader);
});
