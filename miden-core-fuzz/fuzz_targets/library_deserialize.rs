//! Fuzz target for Library deserialization.
//!
//! Run with: cargo +nightly fuzz run library_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_assembly_syntax::Library;
use miden_core::serde::Deserializable;

fuzz_target!(|data: &[u8]| {
    let _ = Library::read_from_bytes(data);
    let _ = Vec::<Library>::read_from_bytes(data);
    let _ = Option::<Library>::read_from_bytes(data);
});
