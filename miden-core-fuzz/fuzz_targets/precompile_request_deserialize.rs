//! Fuzz target for PrecompileRequest deserialization.
//!
//! Run with: cargo +nightly fuzz run precompile_request_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{precompile::PrecompileRequest, serde::Deserializable};

fuzz_target!(|data: &[u8]| {
    let _ = PrecompileRequest::read_from_bytes(data);
    let _ = Vec::<PrecompileRequest>::read_from_bytes(data);
    let _ = Option::<PrecompileRequest>::read_from_bytes(data);
});
