#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_serde_utils::{ByteReader, Deserializable, SliceReader};

fuzz_target!(|data: &[u8]| {
    // Test usize deserialization (vint64 encoding)
    // The vint64 format has complex decoding:
    // - Length is determined by trailing zeros in first byte
    // - 9-byte special case when first byte is 0xFF
    // - Bit shifting to extract value
    let _ = usize::read_from_bytes(data);

    // Also test via SliceReader to ensure reader state is consistent
    let mut reader = SliceReader::new(data);
    let _ = reader.read_usize();

    // Test peek + read combination - peek should not consume bytes
    if !data.is_empty() {
        let mut reader2 = SliceReader::new(data);
        let _ = reader2.peek_u8();
        let _ = reader2.read_usize();
    }

    // Test multiple sequential reads to ensure state management
    let mut reader3 = SliceReader::new(data);
    let _ = reader3.read_usize();
    let _ = reader3.read_usize();
    let _ = reader3.read_usize();
});
