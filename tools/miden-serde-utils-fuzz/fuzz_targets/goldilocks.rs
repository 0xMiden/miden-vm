#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_serde_utils::Deserializable;

fuzz_target!(|data: &[u8]| {
    // Test Goldilocks field element deserialization
    // The key validation: value must be < modulus (2^64 - 2^32 + 1)
    // This is defined in p3_goldilocks::Goldilocks::MODULUS
    use p3_goldilocks::Goldilocks;

    let _ = Goldilocks::read_from_bytes(data);

    // Also test via Vec of Goldilocks elements to test multiple reads
    let _ = Vec::<Goldilocks>::read_from_bytes(data);

    // Test arrays of Goldilocks
    let _ = <[Goldilocks; 1]>::read_from_bytes(data);
    let _ = <[Goldilocks; 2]>::read_from_bytes(data);
    let _ = <[Goldilocks; 4]>::read_from_bytes(data);

    // Test tuples containing Goldilocks
    let _ = <(Goldilocks,)>::read_from_bytes(data);
    let _ = <(Goldilocks, Goldilocks)>::read_from_bytes(data);
    let _ = <(Goldilocks, u64, Goldilocks)>::read_from_bytes(data);
});
