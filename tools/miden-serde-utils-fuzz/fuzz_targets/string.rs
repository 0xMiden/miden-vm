#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_serde_utils::Deserializable;

fuzz_target!(|data: &[u8]| {
    let _ = String::read_from_bytes(data);
});
