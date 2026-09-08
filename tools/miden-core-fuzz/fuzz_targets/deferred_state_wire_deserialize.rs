//! Fuzz checked portable precompile-witness decoding and canonical transport.
#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{deferred::PrecompileWitness, serde::Deserializable};

fuzz_target!(|data: &[u8]| {
    let _ = PrecompileWitness::read_from_bytes(data);
    let _ = Vec::<PrecompileWitness>::read_from_bytes(data);
    let _ = Option::<PrecompileWitness>::read_from_bytes(data);
});
