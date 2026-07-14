//! Fuzz target for package debug info deserialization.
//!
//! Package-owned debug info contains source/type/function sections and source-keyed MAST
//! occurrence metadata.
//!
//! Run with: cargo +nightly fuzz run debug_info --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::serde::{Deserializable, SliceReader};
use miden_mast_package::{
    Package,
    debug_info::{
        DebugFunctionsSection, DebugSourceGraphSection, DebugSourceMapSection, DebugSourcesSection,
        DebugTypesSection,
    },
};

fuzz_target!(|data: &[u8]| {
    if let Ok(package) = Package::read_from_bytes(data) {
        let _ = package.debug_info();
    }

    let mut reader = SliceReader::new(data);
    let _ = DebugTypesSection::read_from(&mut reader);
    let mut reader = SliceReader::new(data);
    let _ = DebugSourcesSection::read_from(&mut reader);
    let mut reader = SliceReader::new(data);
    let _ = DebugFunctionsSection::read_from(&mut reader);
    let mut reader = SliceReader::new(data);
    let _ = DebugSourceGraphSection::read_from(&mut reader);
    let mut reader = SliceReader::new(data);
    let _ = DebugSourceMapSection::read_from(&mut reader);
});
