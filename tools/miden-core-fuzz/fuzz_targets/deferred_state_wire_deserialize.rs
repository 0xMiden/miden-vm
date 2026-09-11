//! Fuzz checked portable precompile-witness decoding and canonical transport.
#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{
    deferred::PrecompileWitness,
    serde::{Deserializable, Serializable},
};

fuzz_target!(|data: &[u8]| {
    if let Ok(witness) = PrecompileWitness::read_from_bytes(data) {
        assert_eq!(witness.to_bytes(), data);
        assert_eq!(PrecompileWitness::read_from_bytes(&witness.to_bytes()).unwrap(), witness);
    }
    let _ = Vec::<PrecompileWitness>::read_from_bytes(data);
    let _ = Option::<PrecompileWitness>::read_from_bytes(data);
});
