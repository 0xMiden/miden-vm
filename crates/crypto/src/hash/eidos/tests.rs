use alloc::vec::Vec;

use super::{Eidos, encoding::ODD_LANE_MASK, primitive::IV};
use crate::{Felt, Word};

fn felts_seq(n: u32) -> Vec<Felt> {
    (0..n).map(|i| Felt::new_unchecked(i as u64 + 1)).collect()
}

fn word(values: [u64; 4]) -> Word {
    Word::new([
        Felt::new_unchecked(values[0]),
        Felt::new_unchecked(values[1]),
        Felt::new_unchecked(values[2]),
        Felt::new_unchecked(values[3]),
    ])
}

fn assert_digest(actual: Word, expected: [u64; 4]) {
    assert_eq!(actual, word(expected));
}

#[test]
fn frozen_eidos_vectors() {
    assert_digest(
        Eidos::hash_elements::<Felt>(&[]),
        [0x58182f9a6f6bf6cf, 0x6ab51fa2fe31684b, 0x06362caa32f0faa3, 0x4e6ef3f1bb8bf2cc],
    );
    assert_digest(
        Eidos::hash(&[]),
        [0x2864baae4689a79a, 0x3b41d3365c3c8860, 0x07fea97b08976abc, 0x3ac995324799df08],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(3)),
        [0x6094c1fba7782167, 0x57ceece4b9e81091, 0x6b5926909007db6d, 0x5a20f7eb555ab60a],
    );
    assert_digest(
        Eidos::hash(b"abc"),
        [0x365b33e5d73475c7, 0x7842d2a7da672026, 0x080ccab96956c05a, 0x1c431bb11d6f35ee],
    );
    assert_digest(
        Eidos::hash_elements_in_domain(&felts_seq(4), Felt::new_unchecked(42)),
        [0x7558b8333dbd1170, 0x3639afa7f9d43344, 0x72465278063f110c, 0x49c9ee42d233bfd8],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(9)),
        [0x6fdf9529ccb46829, 0x6f08871e0b6b0bfa, 0x23ab0a383a4e6f20, 0x58c16af4021c5dda],
    );
    let bytes: Vec<u8> = (0..65).map(|i| i as u8).collect();
    assert_digest(
        Eidos::hash(&bytes),
        [0x0a3700b1a8d0e65c, 0x389e810e5f3cdab2, 0x36cd639c19ced5e9, 0x4e8a2f58fb01c8ac],
    );
}

#[test]
fn felt_and_byte_constructions_diverge_on_empty_input() {
    assert_ne!(Eidos::hash(&[]), Eidos::hash_elements::<Felt>(&[]));
}

#[test]
fn felt_and_byte_constructions_diverge_on_zero_block() {
    let bytes_digest = Eidos::hash(&[0u8; 64]);
    let felts_digest = Eidos::hash_elements(&[Felt::ZERO; 8]);

    assert_ne!(bytes_digest, felts_digest);
}

#[test]
fn different_lengths_within_same_block_diverge() {
    let one = vec![Felt::new_unchecked(7)];
    let two = vec![Felt::new_unchecked(7), Felt::ZERO];

    assert_ne!(Eidos::hash_elements(&one), Eidos::hash_elements(&two));
}

#[test]
fn block_boundary_lengths_diverge() {
    assert_ne!(Eidos::hash_elements(&felts_seq(8)), Eidos::hash_elements(&felts_seq(9)));
}

#[test]
fn empty_input_is_not_zero_word() {
    assert_ne!(Eidos::hash_elements::<Felt>(&[]), Word::default());
    assert_ne!(Eidos::hash(&[]), Word::default());
}

#[test]
fn different_domains_diverge() {
    let xs = felts_seq(4);
    let d0 = Eidos::hash_elements_in_domain(&xs, Felt::ZERO);
    let d1 = Eidos::hash_elements_in_domain(&xs, Felt::ONE);
    let d2 = Eidos::hash_elements_in_domain(&xs, Felt::new_unchecked(42));

    assert_ne!(d0, d1);
    assert_ne!(d0, d2);
    assert_ne!(d1, d2);
}

#[test]
fn hash_elements_equals_in_domain_zero() {
    let xs = felts_seq(8);

    assert_eq!(Eidos::hash_elements(&xs), Eidos::hash_elements_in_domain(&xs, Felt::ZERO));
}

#[test]
fn domain_uses_the_complete_u32_range() {
    let xs = felts_seq(4);
    let domain = Felt::from_u32(u32::MAX);

    assert_ne!(Eidos::hash_elements_in_domain(&xs, domain), Word::default());
}

#[test]
#[should_panic(expected = "selector must fit in a u32")]
fn domain_equal_to_two_pow_32_is_rejected() {
    let _ = Eidos::hash_elements_in_domain(&felts_seq(4), Felt::new_unchecked(1u64 << 32));
}

#[test]
fn generic_initializer_has_the_exact_lane_layout() {
    let selector = u32::MAX;
    let params = [u32::MAX; 3];
    let cv = Eidos::init_chaining_word_with_params(selector, params);
    let lanes: [u32; 8] = cv
        .as_elements()
        .iter()
        .flat_map(|felt| {
            let packed = felt.as_canonical_u64();
            [packed as u32, (packed >> 32) as u32]
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    assert_eq!(
        lanes,
        [
            selector,
            IV[1] & ODD_LANE_MASK,
            params[0],
            IV[3] & ODD_LANE_MASK,
            params[1],
            IV[5] & ODD_LANE_MASK,
            params[2],
            IV[7] & ODD_LANE_MASK,
        ]
    );
    assert_eq!(
        Eidos::init_chaining_word(selector, params[0]),
        Eidos::init_chaining_word_with_params(selector, [params[0], 0, 0]),
    );
}

#[test]
fn merge_equals_hash_elements_on_eight_felt_concat() {
    let left = word([1, 2, 3, 4]);
    let right = word([5, 6, 7, 8]);
    let concat = vec![left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3]];

    assert_eq!(Eidos::merge(&[left, right]), Eidos::hash_elements(&concat));
}

#[test]
fn merge_in_domain_matches_hash_elements_in_domain() {
    let left = word([10, 20, 30, 40]);
    let right = word([50, 60, 70, 80]);
    let domain = Felt::new_unchecked(7);
    let concat = vec![left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3]];

    assert_eq!(
        Eidos::merge_in_domain(&[left, right], domain),
        Eidos::hash_elements_in_domain(&concat, domain)
    );
}

#[test]
fn merge_many_matches_hash_elements_on_concat() {
    let words = vec![word([1, 2, 3, 4]), word([5, 6, 7, 8]), word([9, 10, 11, 12])];
    let mut concat = Vec::new();
    for w in &words {
        concat.extend_from_slice(w.as_ref());
    }

    assert_eq!(Eidos::merge_many(&words), Eidos::hash_elements(&concat));
}

#[test]
fn felt_construction_block_boundary_lengths() {
    let lengths = [1u32, 4, 8, 9, 17];
    let digests: Vec<Word> = lengths.iter().map(|&n| Eidos::hash_elements(&felts_seq(n))).collect();

    for i in 0..digests.len() {
        for j in (i + 1)..digests.len() {
            assert_ne!(
                digests[i], digests[j],
                "lengths {} and {} collided",
                lengths[i], lengths[j]
            );
        }
    }

    for &n in &lengths {
        assert_eq!(Eidos::hash_elements(&felts_seq(n)), Eidos::hash_elements(&felts_seq(n)));
    }
}

#[test]
fn byte_construction_block_boundary_lengths() {
    let lengths = [0usize, 1, 63, 64, 65, 128];
    let digests: Vec<Word> = lengths
        .iter()
        .map(|&n| {
            let bytes: Vec<u8> = (0..n).map(|i| (i & 0xff) as u8).collect();
            Eidos::hash(&bytes)
        })
        .collect();

    for i in 0..digests.len() {
        for j in (i + 1)..digests.len() {
            assert_ne!(
                digests[i], digests[j],
                "byte lengths {} and {} collided",
                lengths[i], lengths[j]
            );
        }
    }
}

#[test]
fn hash_elements_generic_over_felt_array() {
    assert_ne!(Eidos::hash_elements(&felts_seq(5)), Word::default());
}

#[test]
fn frozen_merge_and_challenger_vectors() {
    use p3_challenger::{CanObserve, CanSample};

    use super::MidenEidosChallenger;

    let merged = Eidos::merge(&[word([1, 2, 3, 4]), word([5, 6, 7, 8])]);
    assert_digest(
        merged,
        [
            676171972051561847,
            7298429885786641107,
            4102849260496494473,
            6437248585445412477,
        ],
    );

    let mut challenger = MidenEidosChallenger::new(word([1, 2, 3, 4]), word([10, 11, 12, 13]));
    for value in 20..=24 {
        challenger.observe(Felt::new_unchecked(value));
    }
    let first = Word::new(core::array::from_fn(|_| CanSample::<Felt>::sample(&mut challenger)));
    let second = Word::new(core::array::from_fn(|_| CanSample::<Felt>::sample(&mut challenger)));
    assert_digest(
        first,
        [
            9064457378334718372,
            5425353699759013086,
            1604522722744930894,
            6404602263707938109,
        ],
    );
    assert_digest(
        second,
        [
            4259844014858609293,
            8079007960973284947,
            8487760873676030018,
            4187353069166526105,
        ],
    );
}

#[test]
fn crypto_selectors_are_distinct() {
    use super::framing::BYTE_STRING_SELECTOR;
    use crate::{
        aead::aead_eidos::{AEAD_CTR_SELECTOR, AEAD_MAC_SELECTOR},
        dsa::falcon512_eidos::FALCON_HASH_TO_POINT_SELECTOR,
        rand::{RANDOM_COIN_OUTPUT_SELECTOR, RANDOM_COIN_STATE_SELECTOR},
    };

    let selectors = [
        BYTE_STRING_SELECTOR,
        FALCON_HASH_TO_POINT_SELECTOR,
        AEAD_CTR_SELECTOR,
        AEAD_MAC_SELECTOR,
        RANDOM_COIN_STATE_SELECTOR,
        RANDOM_COIN_OUTPUT_SELECTOR,
    ];

    for (index, selector) in selectors.iter().enumerate() {
        assert_ne!(*selector, 0);
        assert!(!selectors[..index].contains(selector), "duplicate selector {selector:#010x}");
    }
}
