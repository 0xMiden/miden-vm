use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::cmp::Ordering;

use miden_serde_utils::SliceReader;
use proptest::prelude::*;

use super::{Deserializable, Felt, Serializable, Word};
use crate::word;

// TESTS
// ================================================================================================

/// Returns a strategy which generates a `[u64; 4]` where all values are canonical field elements.
fn any_word_elements_u64_canonical() -> BoxedStrategy<[u64; Word::NUM_ELEMENTS]> {
    prop::array::uniform4(0u64..Felt::ORDER).no_shrink().boxed()
}

proptest! {
    #[test]
    fn word_is_equal_to_itself(word in any::<Word>()) {
        use core::cmp::Ordering;

        prop_assert_eq!(word, word);
        prop_assert_eq!(word.cmp(&word), Ordering::Equal);
        prop_assert_eq!(word.partial_cmp(&word), Some(Ordering::Equal));
    }

    #[test]
    fn word_serialization_roundtrip(word in any::<Word>()) {
        let mut bytes = Vec::new();
        word.write_into(&mut bytes);
        prop_assert_eq!(Word::SERIALIZED_SIZE, bytes.len());
        prop_assert_eq!(bytes.len(), word.get_size_hint());

        let mut reader = SliceReader::new(&bytes);
        let round_trip = Word::read_from(&mut reader).unwrap();

        prop_assert_eq!(word, round_trip);
    }

    #[test]
    fn word_encoding_roundtrip(word in any::<Word>()) {
        let string: String = word.into();
        let round_trip: Word = string.try_into().expect("decoding failed");
        prop_assert_eq!(word, round_trip);
    }

    #[test]
    fn word_bool_conversion_roundtrip(v in any::<[bool; Word::NUM_ELEMENTS]>()) {
        let word: Word = v.into();
        prop_assert_eq!(v, <[bool; Word::NUM_ELEMENTS]>::try_from(word).unwrap());

        let word: Word = (&v).into();
        prop_assert_eq!(v, <[bool; Word::NUM_ELEMENTS]>::try_from(&word).unwrap());
    }

    #[test]
    fn word_u8_conversion_roundtrip(v in any::<[u8; Word::NUM_ELEMENTS]>()) {
        let word: Word = v.into();
        prop_assert_eq!(v, <[u8; Word::NUM_ELEMENTS]>::try_from(word).unwrap());

        let word: Word = (&v).into();
        prop_assert_eq!(v, <[u8; Word::NUM_ELEMENTS]>::try_from(&word).unwrap());
    }

    #[test]
    fn word_u16_conversion_roundtrip(v in any::<[u16; Word::NUM_ELEMENTS]>()) {
        let word: Word = v.into();
        prop_assert_eq!(v, <[u16; Word::NUM_ELEMENTS]>::try_from(word).unwrap());

        let word: Word = (&v).into();
        prop_assert_eq!(v, <[u16; Word::NUM_ELEMENTS]>::try_from(&word).unwrap());
    }

    #[test]
    fn word_u32_conversion_roundtrip(v in any::<[u32; Word::NUM_ELEMENTS]>()) {
        let word: Word = v.into();
        prop_assert_eq!(v, <[u32; Word::NUM_ELEMENTS]>::try_from(word).unwrap());

        let word: Word = (&v).into();
        prop_assert_eq!(v, <[u32; Word::NUM_ELEMENTS]>::try_from(&word).unwrap());
    }

    #[test]
    fn word_u64_conversion_roundtrip(v in any_word_elements_u64_canonical()) {
        let word: Word = v.try_into().unwrap();
        let round_trip: [u64; Word::NUM_ELEMENTS] = word.into();
        prop_assert_eq!(v, round_trip);

        let word: Word = (&v).try_into().unwrap();
        let round_trip: [u64; Word::NUM_ELEMENTS] = (&word).into();
        prop_assert_eq!(v, round_trip);
    }

    #[test]
    fn word_felt_conversion_roundtrip(elements in prop::array::uniform4(any::<u64>())) {
        let elements = elements.map(Felt::new_unchecked);

        let word: Word = elements.into();
        let round_trip: [Felt; Word::NUM_ELEMENTS] = word.into();
        prop_assert_eq!(elements, round_trip);

        let word: Word = (&elements).into();
        let round_trip: [Felt; Word::NUM_ELEMENTS] = (&word).into();
        prop_assert_eq!(elements, round_trip);
    }

    #[test]
    fn word_bytes_conversion_roundtrip(word in any::<Word>()) {
        let bytes: [u8; Word::SERIALIZED_SIZE] = word.into();
        let round_trip: Word = bytes.try_into().unwrap();
        prop_assert_eq!(word, round_trip);

        let bytes: [u8; Word::SERIALIZED_SIZE] = (&word).into();
        let round_trip: Word = (&bytes).try_into().unwrap();
        prop_assert_eq!(word, round_trip);
    }

    #[test]
    fn word_string_conversion_roundtrip(word in any::<Word>()) {
        let string: String = word.into();
        let round_trip: Word = string.try_into().unwrap();
        prop_assert_eq!(word, round_trip);

        let string: String = (&word).into();
        let round_trip: Word = (&string).try_into().unwrap();
        prop_assert_eq!(word, round_trip);
    }

    #[test]
    fn word_reversed_roundtrip(word in any::<Word>()) {
        prop_assert_eq!(word, word.reversed().reversed());
    }
}

#[test]
fn word_elements_array_layout_roundtrip() {
    let mut word = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);

    let elements = word.as_elements_array();
    assert_eq!(
        elements,
        &[
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4)
        ]
    );

    let base = core::ptr::addr_of!(word.a);
    assert_eq!(elements.as_ptr(), base);
    assert_eq!(core::ptr::addr_of!(word.b), unsafe { base.add(1) });
    assert_eq!(core::ptr::addr_of!(word.c), unsafe { base.add(2) });
    assert_eq!(core::ptr::addr_of!(word.d), unsafe { base.add(3) });

    let elements_mut = word.as_elements_array_mut();
    elements_mut[2] = Felt::new_unchecked(42);
    assert_eq!(word.c, Felt::new_unchecked(42));
}

proptest! {
    #[test]
    fn word_index_matches_into_elements(word in any::<Word>()) {
        let elements = word.into_elements();
        for idx in 0..Word::NUM_ELEMENTS {
            prop_assert_eq!(word[idx], elements[idx]);
        }
    }

    #[test]
    fn word_index_mut_updates_all_elements(word in any::<Word>(), values in any::<[u64; Word::NUM_ELEMENTS]>()) {
        let mut word = word;

        let mut expected = word.into_elements();
        for idx in 0..Word::NUM_ELEMENTS {
            let value = values[idx];
            expected[idx] = Felt::new_unchecked(value);
            word[idx] = Felt::new_unchecked(value);
        }
        prop_assert_eq!(word.into_elements(), expected);
    }

    #[test]
    fn word_index_mut_range_updates_slice(word in any::<Word>(), v0 in any::<u64>(), v1 in any::<u64>()) {
        let mut word = word;
        let expected = [Felt::new_unchecked(v0), Felt::new_unchecked(v1)];

        word[1..3].copy_from_slice(&expected);
        prop_assert_eq!(word[1], expected[0]);
        prop_assert_eq!(word[2], expected[1]);
    }
}

#[rstest::rstest]
#[case::missing_prefix("1234")]
#[case::invalid_character("1234567890abcdefg")]
#[case::too_long("0xx00000000000000000000000000000000000000000000000000000000000000001")]
#[case::overflow_felt0("0x01000000ffffffff000000000000000000000000000000000000000000000000")]
#[case::overflow_felt1("0x000000000000000001000000ffffffff00000000000000000000000000000000")]
#[case::overflow_felt2("0x0000000000000000000000000000000001000000ffffffff0000000000000000")]
#[case::overflow_felt3("0x00000000000000000000000000000000000000000000000001000000ffffffff")]
#[should_panic]
fn word_macro_invalid(#[case] bad_input: &str) {
    word!(bad_input);
}

#[rstest::rstest]
#[case::each_digit("0x1234567890abcdef")]
#[case::empty("0x")]
#[case::zero("0x0")]
#[case::zero_full("0x0000000000000000000000000000000000000000000000000000000000000000")]
#[case::one_lsb("0x1")]
#[case::one_msb("0x0000000000000000000000000000000000000000000000000000000000000001")]
#[case::one_partial("0x0001")]
#[case::odd("0x123")]
#[case::even("0x1234")]
#[case::touch_each_felt("0x00000000000123450000000000067890000000000000abcd00000000000000ef")]
#[case::unique_felt("0x111111111111111155555555555555559999999999999999cccccccccccccccc")]
#[case::digits_on_repeat("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")]
fn word_macro(#[case] input: &str) {
    use alloc::format;

    let uut = word!(input);

    // Right pad to 64 hex digits (66 including prefix). This is required by the
    // Word::try_from(String) implementation.
    let padded_input = format!("{input:<66}").replace(" ", "0");
    let expected = crate::Word::try_from(padded_input.as_str()).unwrap();

    assert_eq!(uut, expected);
}

#[rstest::rstest]
#[case::first_nibble("0x1000000000000000000000000000000000000000000000000000000000000000", crate::Word::new([Felt::new_unchecked(16), Felt::new_unchecked(0), Felt::new_unchecked(0), Felt::new_unchecked(0)]))]
#[case::second_nibble("0x0100000000000000000000000000000000000000000000000000000000000000", crate::Word::new([Felt::new_unchecked(1), Felt::new_unchecked(0), Felt::new_unchecked(0), Felt::new_unchecked(0)]))]
#[case::all_first_nibbles("0x1000000000000000100000000000000010000000000000001000000000000000", crate::Word::new([Felt::new_unchecked(16), Felt::new_unchecked(16), Felt::new_unchecked(16), Felt::new_unchecked(16)]))]
#[case::all_first_nibbles_asc("0x1000000000000000200000000000000030000000000000004000000000000000", crate::Word::new([Felt::new_unchecked(16), Felt::new_unchecked(32), Felt::new_unchecked(48), Felt::new_unchecked(64)]))]
fn word_macro_endianness(#[case] input: &str, #[case] expected: crate::Word) {
    let uut = word!(input);
    assert_eq!(uut, expected);
}

proptest! {
    #[test]
    fn word_ord_is_consistent_with_partialeq(a in any::<Word>(), b in any::<Word>()) {
        use core::cmp::Ordering;

        prop_assert_eq!(a == b, a.cmp(&b) == Ordering::Equal);
        prop_assert_eq!(b == a, b.cmp(&a) == Ordering::Equal);
    }

    #[test]
    fn word_ord_supports_btreemap_key_usage(word in any::<Word>()) {
        let mut map: BTreeMap<Word, u64> = BTreeMap::new();
        map.insert(word, 1);

        // Round-trip via bytes to create an equivalent key.
        let bytes: [u8; Word::SERIALIZED_SIZE] = word.into();
        let key2: Word = bytes.try_into().unwrap();
        prop_assert_eq!(word, key2);

        prop_assert!(map.contains_key(&key2));
        prop_assert_eq!(map.get(&key2), Some(&1));

        map.insert(key2, 2);
        prop_assert_eq!(map.len(), 1);
        prop_assert_eq!(map.get(&word), Some(&2));
    }
}

#[test]
fn word_is_ordered_lexicographically() {
    for (expected, key0, key1) in [
        (Ordering::Equal, [0, 0, 0, 0u32], [0, 0, 0, 0u32]),
        (Ordering::Greater, [1, 0, 0, 0u32], [0, 0, 0, 0u32]),
        (Ordering::Greater, [0, 1, 0, 0u32], [0, 0, 0, 0u32]),
        (Ordering::Greater, [0, 0, 1, 0u32], [0, 0, 0, 0u32]),
        (Ordering::Greater, [0, 0, 0, 1u32], [0, 0, 0, 0u32]),
        (Ordering::Less, [0, 0, 0, 0u32], [1, 0, 0, 0u32]),
        (Ordering::Less, [0, 0, 0, 0u32], [0, 1, 0, 0u32]),
        (Ordering::Less, [0, 0, 0, 0u32], [0, 0, 1, 0u32]),
        (Ordering::Less, [0, 0, 0, 0u32], [0, 0, 0, 1u32]),
        (Ordering::Greater, [0, 0, 0, 1u32], [1, 1, 1, 0u32]),
        (Ordering::Greater, [0, 0, 1, 0u32], [1, 1, 0, 0u32]),
        (Ordering::Less, [1, 1, 1, 0u32], [0, 0, 0, 1u32]),
        (Ordering::Less, [1, 1, 0, 0u32], [0, 0, 1, 0u32]),
    ] {
        assert_eq!(
            Word::from(key0.map(Felt::from_u32)).cmp(&Word::from(key1.map(Felt::from_u32))),
            expected
        );
    }
}
