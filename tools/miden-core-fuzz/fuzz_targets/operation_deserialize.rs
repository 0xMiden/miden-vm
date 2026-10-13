//! Fuzz target for Operation deserialization.
//!
//! Run with: cargo +nightly fuzz run operation_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{
    operations::Operation,
    serde::{Deserializable, Serializable},
};

fuzz_target!(|data: &[u8]| {
    // STABILITY ORACLE (upgraded from crash-only): Operation has Eq, so the oracle is
    // VALUE-level — a successful decode must re-encode and decode again to an EQUAL
    // value. Non-decodable inputs (bare opcodes of data-carrying variants, unassigned
    // opcode space) simply skip the oracle.
    if let Ok(operation) = Operation::read_from_bytes(data) {
        let canonical = operation.to_bytes();
        let redecoded =
            Operation::read_from_bytes(&canonical).expect("canonical encoding must decode");
        assert_eq!(redecoded, operation, "canonical re-encoding must decode identically");
    }
    let _ = Vec::<Operation>::read_from_bytes(data);
    let _ = Option::<Operation>::read_from_bytes(data);
});
