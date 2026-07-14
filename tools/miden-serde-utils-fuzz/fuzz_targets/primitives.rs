#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_serde_utils::{ByteReader, Deserializable, SliceReader};

fuzz_target!(|data: &[u8]| {
    // Test all primitive deserializations with raw fuzz input
    // Goal: ensure none of these panic, only return Ok or Err
    let _ = u8::read_from_bytes(data);
    let _ = u16::read_from_bytes(data);
    let _ = u32::read_from_bytes(data);
    let _ = u64::read_from_bytes(data);
    let _ = u128::read_from_bytes(data);
    let _ = usize::read_from_bytes(data);

    // Test read_bool which validates input is 0 or 1
    let mut reader = SliceReader::new(data);
    let _ = reader.read_bool();

    // Test peek_u8 which should handle empty input gracefully
    let reader2 = SliceReader::new(data);
    let _ = reader2.peek_u8();

    // Test check_eor with various lengths
    for len in 0..=16 {
        let reader3 = SliceReader::new(data);
        let _ = reader3.check_eor(len);
    }
});
