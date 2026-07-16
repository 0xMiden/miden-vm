#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_serde_utils::Deserializable;
use std::collections::{BTreeMap, BTreeSet};

fuzz_target!(|data: &[u8]| {
    // Test Vec with various element types - focus on length prefix handling
    let _ = Vec::<u8>::read_from_bytes(data);
    let _ = Vec::<u64>::read_from_bytes(data);
    let _ = Vec::<u128>::read_from_bytes(data);

    // Test Option which has a bool discriminator
    let _ = Option::<u64>::read_from_bytes(data);
    let _ = Option::<Vec<u8>>::read_from_bytes(data);

    // Test BTreeMap and BTreeSet - these validate ordering and handle allocations
    let _ = BTreeMap::<u64, u64>::read_from_bytes(data);
    let _ = BTreeMap::<u8, u128>::read_from_bytes(data);
    let _ = BTreeSet::<u64>::read_from_bytes(data);

    // Test fixed-size arrays - these should handle exact count requirements
    let _ = <[u8; 1]>::read_from_bytes(data);
    let _ = <[u8; 4]>::read_from_bytes(data);
    let _ = <[u8; 16]>::read_from_bytes(data);
    let _ = <[u8; 32]>::read_from_bytes(data);
    let _ = <[u64; 2]>::read_from_bytes(data);
    let _ = <[u64; 4]>::read_from_bytes(data);

    // Test tuples of various sizes
    let _ = <(u8,)>::read_from_bytes(data);
    let _ = <(u8, u16)>::read_from_bytes(data);
    let _ = <(u8, u16, u32)>::read_from_bytes(data);
    let _ = <(u8, u16, u32, u64)>::read_from_bytes(data);
    let _ = <(u8, u16, u32, u64, u128)>::read_from_bytes(data);
    let _ = <(u8, u16, u32, u64, u128, usize)>::read_from_bytes(data);
});
