#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_serde_utils::{BudgetedReader, ByteReader, Deserializable, SliceReader};
use std::collections::{BTreeMap, BTreeSet};

fuzz_target!(|data: &[u8]| {
    // Use a tight budget to stress-test budget enforcement.
    // The budget is the min of data length and 1KB to keep things fast.
    let budget = data.len().min(1024);

    // Test primitives with budget
    let inner = SliceReader::new(data);
    let mut reader = BudgetedReader::new(inner, budget);
    let _ = reader.read_u8();
    let _ = reader.read_u16();
    let _ = reader.read_u32();
    let _ = reader.read_u64();

    // Test collections with budget via the convenience method
    let _ = Vec::<u8>::read_from_bytes_with_budget(data, budget);
    let _ = Vec::<u64>::read_from_bytes_with_budget(data, budget);
    let _ = BTreeMap::<u64, u64>::read_from_bytes_with_budget(data, budget);
    let _ = BTreeSet::<u64>::read_from_bytes_with_budget(data, budget);
    let _ = String::read_from_bytes_with_budget(data, budget);

    // Test with zero budget (should fail immediately on any read)
    let _ = Vec::<u8>::read_from_bytes_with_budget(data, 0);
    let _ = u64::read_from_bytes_with_budget(data, 0);

    // Test with exact budget for known-size types
    let _ = u32::read_from_bytes_with_budget(data, 4);
    let _ = u64::read_from_bytes_with_budget(data, 8);
    let _ = <[u8; 16]>::read_from_bytes_with_budget(data, 16);

    // Test nested structures
    let _ = Option::<Vec<u8>>::read_from_bytes_with_budget(data, budget);
    let _ = Vec::<Option<u64>>::read_from_bytes_with_budget(data, budget);
});
