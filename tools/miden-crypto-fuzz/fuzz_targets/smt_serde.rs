#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_crypto::{
    utils::Deserializable,
    merkle::smt::{PartialSmt, Smt},
};

fuzz_target!(|data: &[u8]| {
    // Test Smt deserialization - tests complex tree structure
    let _ = Smt::read_from_bytes(data);

    // Test PartialSmt deserialization
    let _ = PartialSmt::read_from_bytes(data);

    // Test Vec of SMT types
    let _ = Vec::<Smt>::read_from_bytes(data);
    let _ = Vec::<PartialSmt>::read_from_bytes(data);

    // Test Option<Smt>
    let _ = Option::<Smt>::read_from_bytes(data);

    // Test arrays
    let _ = <[Smt; 1]>::read_from_bytes(data);
    let _ = <[PartialSmt; 1]>::read_from_bytes(data);
});
