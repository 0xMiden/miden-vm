#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_crypto::{
    utils::Deserializable,
    merkle::mmr::{PartialMmr, Forest},
};

fuzz_target!(|data: &[u8]| {
    // Test PartialMmr deserialization - complex structure with:
    // - Forest validation (peaks count must match forest bits)
    // - Node index validation (must be valid within forest)
    // - Tracked leaves validation (must be within bounds and have values in nodes)
    let _ = PartialMmr::read_from_bytes(data);

    // Test Vec<PartialMmr>
    let _ = Vec::<PartialMmr>::read_from_bytes(data);

    // Test Option<PartialMmr>
    let _ = Option::<PartialMmr>::read_from_bytes(data);

    // Test Forest deserialization (usize)
    let _ = Forest::read_from_bytes(data);

    // Test arrays of MMR structures
    let _ = <[PartialMmr; 1]>::read_from_bytes(data);
});
