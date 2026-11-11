use alloc::vec::Vec;

use miden_core::Word;

use super::{
    Felt, FromMidenRepr, RawFelt, ToMidenRepr, bytes_to_words, push_wasm_ty_to_operand_stack,
};

#[test]
fn bool_roundtrip() {
    let encoded = true.to_bytes();
    let decoded = <bool as FromMidenRepr>::from_bytes(&encoded);
    assert!(decoded);

    let encoded = true.to_felts();
    let decoded = <bool as FromMidenRepr>::from_felts(&encoded);
    assert!(decoded);

    let encoded = true.to_words();
    let decoded = <bool as FromMidenRepr>::from_words(&encoded);
    assert!(decoded);

    let mut stack = Vec::default();
    true.push_to_operand_stack(&mut stack);
    assert_eq!(stack.as_slice(), true.to_felts().as_slice());

    stack.reverse();
    let popped = <bool as FromMidenRepr>::pop_from_stack(&mut stack);
    assert!(popped);
}

#[test]
fn u8_roundtrip() {
    let encoded = u8::MAX.to_bytes();
    let decoded = <u8 as FromMidenRepr>::from_bytes(&encoded);
    assert_eq!(decoded, u8::MAX);

    let encoded = u8::MAX.to_felts();
    let decoded = <u8 as FromMidenRepr>::from_felts(&encoded);
    assert_eq!(decoded, u8::MAX);

    let encoded = u8::MAX.to_words();
    let decoded = <u8 as FromMidenRepr>::from_words(&encoded);
    assert_eq!(decoded, u8::MAX);

    let mut stack = Vec::default();
    u8::MAX.push_to_operand_stack(&mut stack);
    assert_eq!(stack.as_slice(), u8::MAX.to_felts().as_slice());

    stack.reverse();
    let popped = <u8 as FromMidenRepr>::pop_from_stack(&mut stack);
    assert_eq!(popped, u8::MAX);
}

#[test]
fn u16_roundtrip() {
    let encoded = u16::MAX.to_bytes();
    let decoded = <u16 as FromMidenRepr>::from_bytes(&encoded);
    assert_eq!(decoded, u16::MAX);

    let encoded = u16::MAX.to_felts();
    let decoded = <u16 as FromMidenRepr>::from_felts(&encoded);
    assert_eq!(decoded, u16::MAX);

    let encoded = u16::MAX.to_words();
    let decoded = <u16 as FromMidenRepr>::from_words(&encoded);
    assert_eq!(decoded, u16::MAX);

    let mut stack = Vec::default();
    u16::MAX.push_to_operand_stack(&mut stack);
    assert_eq!(stack.as_slice(), u16::MAX.to_felts().as_slice());

    stack.reverse();
    let popped = <u16 as FromMidenRepr>::pop_from_stack(&mut stack);
    assert_eq!(popped, u16::MAX);
}

#[test]
fn u32_roundtrip() {
    let encoded = u32::MAX.to_bytes();
    let decoded = <u32 as FromMidenRepr>::from_bytes(&encoded);
    assert_eq!(decoded, u32::MAX);

    let encoded = u32::MAX.to_felts();
    let decoded = <u32 as FromMidenRepr>::from_felts(&encoded);
    assert_eq!(decoded, u32::MAX);

    let encoded = u32::MAX.to_words();
    let decoded = <u32 as FromMidenRepr>::from_words(&encoded);
    assert_eq!(decoded, u32::MAX);

    let mut stack = Vec::default();
    u32::MAX.push_to_operand_stack(&mut stack);
    assert_eq!(stack.as_slice(), u32::MAX.to_felts().as_slice());

    stack.reverse();
    let popped = <u32 as FromMidenRepr>::pop_from_stack(&mut stack);
    assert_eq!(popped, u32::MAX);
}

#[test]
fn u64_roundtrip() {
    let encoded = u64::MAX.to_bytes();
    let decoded = <u64 as FromMidenRepr>::from_bytes(&encoded);
    assert_eq!(decoded, u64::MAX);

    let encoded = u64::MAX.to_felts();
    let decoded = <u64 as FromMidenRepr>::from_felts(&encoded);
    assert_eq!(decoded, u64::MAX);

    let encoded = u64::MAX.to_words();
    let decoded = <u64 as FromMidenRepr>::from_words(&encoded);
    assert_eq!(decoded, u64::MAX);

    let mut stack = Vec::default();
    u64::MAX.push_to_operand_stack(&mut stack);
    assert_eq!(stack.as_slice(), u64::MAX.to_felts().as_slice());

    stack.reverse();
    let popped = <u64 as FromMidenRepr>::pop_from_stack(&mut stack);
    assert_eq!(popped, u64::MAX);
}

#[test]
fn u128_roundtrip() {
    let encoded = u128::MAX.to_bytes();
    let decoded = <u128 as FromMidenRepr>::from_bytes(&encoded);
    assert_eq!(decoded, u128::MAX);

    let encoded = u128::MAX.to_felts();
    let decoded = <u128 as FromMidenRepr>::from_felts(&encoded);
    assert_eq!(decoded, u128::MAX);

    let encoded = u128::MAX.to_words();
    let decoded = <u128 as FromMidenRepr>::from_words(&encoded);
    assert_eq!(decoded, u128::MAX);

    let mut stack = Vec::default();
    u128::MAX.push_to_operand_stack(&mut stack);
    assert_eq!(stack.as_slice(), u128::MAX.to_felts().as_slice());

    stack.reverse();
    let popped = <u128 as FromMidenRepr>::pop_from_stack(&mut stack);
    assert_eq!(popped, u128::MAX);
}

#[test]
fn byte_array_roundtrip() {
    let bytes = [0, 1, 2, 3, 4, 5, 6, 7];

    let encoded = bytes.to_felts();
    let decoded = <[u8; 8] as FromMidenRepr>::from_felts(&encoded);
    assert_eq!(decoded, bytes);

    let encoded = bytes.to_words();
    let decoded = <[u8; 8] as FromMidenRepr>::from_words(&encoded);
    assert_eq!(decoded, bytes);

    let mut stack = Vec::default();
    bytes.push_to_operand_stack(&mut stack);
    assert_eq!(stack.as_slice(), bytes.to_felts().as_slice());

    stack.reverse();
    let popped = <[u8; 8] as FromMidenRepr>::pop_from_stack(&mut stack);
    assert_eq!(popped, bytes);
}

#[test]
fn bytes_to_words_test() {
    let bytes = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let words = bytes_to_words(&bytes);
    assert_eq!(words.len(), 2);
    // Words should be in little-endian order, elements of the word should be in big-endian
    assert_eq!(words[0][3].as_canonical_u64() as u32, u32::from_ne_bytes([1, 2, 3, 4]));
    assert_eq!(words[0][2].as_canonical_u64() as u32, u32::from_ne_bytes([5, 6, 7, 8]));
    assert_eq!(words[0][1].as_canonical_u64() as u32, u32::from_ne_bytes([9, 10, 11, 12]));
    assert_eq!(words[0][0].as_canonical_u64() as u32, u32::from_ne_bytes([13, 14, 15, 16]));

    // Make sure bytes_to_words and to_words agree
    let to_words_output = bytes.to_words();
    assert_eq!(Word::new(words[0]), to_words_output[0]);
}

#[test]
fn bytes_from_words_test() {
    let bytes = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let words_as_bytes = bytes_to_words(&bytes);

    let words = vec![Word::new(words_as_bytes[0]), Word::new(words_as_bytes[1])];

    let out = <[u8; 32] as FromMidenRepr>::from_words(&words);

    assert_eq!(&out, &bytes);
}

#[test]
fn push_wasm_ty_to_operand_stack_test() {
    let mut stack = Vec::default();
    push_wasm_ty_to_operand_stack(i8::MIN, &mut stack);
    push_wasm_ty_to_operand_stack(i16::MIN, &mut stack);
    push_wasm_ty_to_operand_stack(u32::MAX, &mut stack);

    assert_eq!(stack[0].as_canonical_u64(), ((i8::MIN as i32) as u32) as u64);
    assert_eq!(stack[1].as_canonical_u64(), ((i16::MIN as i32) as u32) as u64);
    assert_eq!(stack[2].as_canonical_u64(), u32::MAX as u64);
}

#[test]
fn signed_integer_roundtrips_cover_all_widths() {
    macro_rules! assert_roundtrip {
        ($ty:ty, $value:expr) => {{
            let value: $ty = $value;
            assert_eq!(<$ty as FromMidenRepr>::from_bytes(&value.to_bytes()), value);
            assert_eq!(<$ty as FromMidenRepr>::from_felts(&value.to_felts()), value);
            assert_eq!(<$ty as FromMidenRepr>::from_words(&value.to_words()), value);

            let mut stack = value.to_felts().into_vec();
            stack.reverse();
            assert_eq!(<$ty as FromMidenRepr>::pop_from_stack(&mut stack), value);
        }};
    }

    assert_roundtrip!(i8, -42);
    assert_roundtrip!(i16, -4242);
    assert_roundtrip!(i32, -424242);
    assert_roundtrip!(i64, -4242424242);
    assert_roundtrip!(i128, -424242424242424242);
    assert_roundtrip!(i8, i8::MIN);
    assert_roundtrip!(i8, i8::MAX);
    assert_roundtrip!(i16, i16::MIN);
    assert_roundtrip!(i16, i16::MAX);
    assert_roundtrip!(i32, i32::MIN);
    assert_roundtrip!(i32, i32::MAX);
    assert_roundtrip!(i64, i64::MIN);
    assert_roundtrip!(i64, i64::MAX);
    assert_roundtrip!(i128, i128::MIN);
    assert_roundtrip!(i128, i128::MAX);
    assert_roundtrip!(i128, i128::from(i64::MAX) + 1);
    assert_roundtrip!(i128, i128::from(i64::MIN) - 1);
}

#[test]
fn felt_and_word_representations_roundtrip() {
    let felt = Felt::new(123);
    assert_eq!(<Felt as FromMidenRepr>::from_felts(&felt.to_felts()), felt);
    assert_eq!(<Felt as FromMidenRepr>::from_words(&felt.to_words()), felt);

    let raw = RawFelt::from(456u32);
    assert_eq!(<RawFelt as FromMidenRepr>::from_felts(&raw.to_felts()), raw);
    assert_eq!(<RawFelt as FromMidenRepr>::from_words(&raw.to_words()), raw);

    let raw_word = [
        RawFelt::from(1u32),
        RawFelt::from(2u32),
        RawFelt::from(3u32),
        RawFelt::from(4u32),
    ];
    let word = raw_word.map(Felt);
    assert_eq!(<[Felt; 4] as FromMidenRepr>::from_felts(&raw_word), word);
    assert_eq!(
        <[Felt; 4] as FromMidenRepr>::from_words(&[Word::new([
            raw_word[3],
            raw_word[2],
            raw_word[1],
            raw_word[0],
        ])]),
        word
    );
}
