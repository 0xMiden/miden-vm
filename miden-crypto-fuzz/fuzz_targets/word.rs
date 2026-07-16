#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_crypto::{utils::Deserializable, Word, Felt};

fuzz_target!(|data: &[u8]| {
    // Test Word deserialization - validates each u64 < field modulus
    let _ = Word::read_from_bytes(data);

    // Test Vec<Word> - tests length prefix handling with validation
    let _ = Vec::<Word>::read_from_bytes(data);

    // Test arrays of Words
    let _ = <[Word; 1]>::read_from_bytes(data);
    let _ = <[Word; 2]>::read_from_bytes(data);
    let _ = <[Word; 4]>::read_from_bytes(data);

    // Test Option<Word>
    let _ = Option::<Word>::read_from_bytes(data);

    // Test tuples with Word
    let _ = <(Word,)>::read_from_bytes(data);
    let _ = <(Word, Word)>::read_from_bytes(data);
    let _ = <(Word, u64)>::read_from_bytes(data);

    // Test individual Felt elements
    let _ = Felt::read_from_bytes(data);
    let _ = Vec::<Felt>::read_from_bytes(data);
    let _ = <[Felt; 4]>::read_from_bytes(data);
});
