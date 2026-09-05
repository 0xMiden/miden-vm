use alloc::vec::Vec;

use super::{
    Custom, DomainTag, DomainVersion, Eidos, EidosDomain, FeltSequence,
    domain::namespace,
    domains::{GENERIC_FELT_SEQUENCE, RANDOM_COIN_STATE},
    encoding::ODD_LANE_MASK,
    primitive::IV,
};
use crate::{Felt, Word};

#[derive(Debug, Copy, Clone)]
struct TestFeltDomain;

impl EidosDomain for TestFeltDomain {
    type Encoding = FeltSequence;

    const NAME: &'static str = "TEST_FELT";
    const TAG: DomainTag =
        DomainTag::new(namespace::MIDEN_ECOSYSTEM, 0xfffe, DomainVersion::numbered(1));
}

#[derive(Debug, Copy, Clone)]
struct TestParameterizedDomain;

impl EidosDomain for TestParameterizedDomain {
    type Encoding = Custom;

    const NAME: &'static str = "TEST_PARAMETERIZED";
    const TAG: DomainTag =
        DomainTag::new(namespace::MIDEN_ECOSYSTEM, 0xffff, DomainVersion::numbered(0xff));
}

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
        [0x11a6458b66a84073, 0x4ffff7a2ad92252b, 0x3c84006ce9b051f5, 0x55b4b6847dcdfd93],
    );
    assert_digest(
        Eidos::hash(&[]),
        [0x2864baae4689a79a, 0x3b41d3365c3c8860, 0x07fea97b08976abc, 0x3ac995324799df08],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(3)),
        [0x17cf960fb0322da4, 0x307f9ec74ec5b4d7, 0x798ca1783855c9ec, 0x61909a51c2d68383],
    );
    assert_digest(
        Eidos::hash(b"abc"),
        [0x365b33e5d73475c7, 0x7842d2a7da672026, 0x080ccab96956c05a, 0x1c431bb11d6f35ee],
    );
    assert_digest(
        Eidos::hash_elements_in_domain(&felts_seq(4), RANDOM_COIN_STATE),
        [0x275e1958ad7c08dc, 0x12b8f7731460be11, 0x29718531efa9484b, 0x4e32493e94faf462],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(9)),
        [0x4d59f4c52d792900, 0x79244370f96f6467, 0x748d893146975bd4, 0x3fda88c89a46ce40],
    );
    let bytes: Vec<u8> = (0..65).map(|i| i as u8).collect();
    assert_digest(
        Eidos::hash(&bytes),
        [0x0a3700b1a8d0e65c, 0x389e810e5f3cdab2, 0x36cd639c19ced5e9, 0x4e8a2f58fb01c8ac],
    );
}

#[test]
fn felt_and_byte_constructions_are_separated_at_boundary_inputs() {
    assert_ne!(Eidos::hash(&[]), Eidos::hash_elements::<Felt>(&[]));
    assert_ne!(Eidos::hash(&[1]), Eidos::hash_elements(&[Felt::ONE]));
    assert_ne!(Eidos::hash(&[0u8; 64]), Eidos::hash_elements(&[Felt::ZERO; 8]));
}

#[test]
fn different_lengths_within_same_block_diverge() {
    let one = vec![Felt::new_unchecked(7)];
    let two = vec![Felt::new_unchecked(7), Felt::ZERO];

    assert_ne!(Eidos::hash_elements(&one), Eidos::hash_elements(&two));
}

#[test]
fn empty_input_is_not_zero_word() {
    assert_ne!(Eidos::hash_elements::<Felt>(&[]), Word::default());
    assert_ne!(Eidos::hash(&[]), Word::default());
}

#[test]
fn different_domains_diverge() {
    let xs = felts_seq(4);
    let d0 = Eidos::hash_elements_in_domain(&xs, GENERIC_FELT_SEQUENCE);
    let d1 = Eidos::hash_elements_in_domain(&xs, RANDOM_COIN_STATE);
    let d2 = Eidos::hash_elements_in_domain(&xs, TestFeltDomain);

    assert_ne!(d0, d1);
    assert_ne!(d0, d2);
    assert_ne!(d1, d2);
}

#[test]
fn hash_elements_equals_the_generic_felt_domain() {
    let xs = felts_seq(8);

    assert_eq!(
        Eidos::hash_elements(&xs),
        Eidos::hash_elements_in_domain(&xs, GENERIC_FELT_SEQUENCE)
    );
}

#[test]
fn generic_initializer_has_the_exact_lane_layout() {
    let params = [u32::MAX; 3];
    let cv = Eidos::init_chaining_word_with_params(TestParameterizedDomain, params);
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
            TestParameterizedDomain::TAG.as_u32(),
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
        Eidos::init_chaining_word(TestParameterizedDomain, params[0]),
        Eidos::init_chaining_word_with_params(TestParameterizedDomain, [params[0], 0, 0]),
    );
}

#[test]
fn merge_uses_the_reserved_zero_tuple_not_the_generic_felt_domain() {
    let left = word([1, 2, 3, 4]);
    let right = word([5, 6, 7, 8]);
    let block = [left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3]];

    assert_eq!(
        Eidos::merge(&[left, right]),
        Eidos::compress(Eidos::merkle_node_init_chaining_word(), block)
    );
    assert_ne!(Eidos::merge(&[left, right]), Eidos::hash_elements(&block));
}

#[test]
fn merkle_initializer_has_zero_in_every_injected_lane() {
    let lanes: [u32; 8] = Eidos::merkle_node_init_chaining_word()
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
            0,
            IV[1] & ODD_LANE_MASK,
            0,
            IV[3] & ODD_LANE_MASK,
            0,
            IV[5] & ODD_LANE_MASK,
            0,
            IV[7] & ODD_LANE_MASK,
        ]
    );
}

#[test]
fn hash_two_words_in_domain_matches_hash_elements_in_domain() {
    let left = word([10, 20, 30, 40]);
    let right = word([50, 60, 70, 80]);
    let concat = vec![left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3]];

    assert_eq!(
        Eidos::hash_two_words_in_domain(&[left, right], RANDOM_COIN_STATE),
        Eidos::hash_elements_in_domain(&concat, RANDOM_COIN_STATE)
    );
}

#[test]
fn hash_two_words_matches_generic_felt_hash() {
    let left = word([10, 20, 30, 40]);
    let right = word([50, 60, 70, 80]);
    let concat = vec![left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3]];

    assert_eq!(Eidos::hash_two_words(&[left, right]), Eidos::hash_elements(&concat));
    assert_ne!(Eidos::hash_two_words(&[left, right]), Eidos::merge(&[left, right]));
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
fn frozen_merge_and_challenger_vectors() {
    use p3_challenger::{CanObserve, CanSample};

    use super::MidenEidosChallenger;

    let merged = Eidos::merge(&[word([1, 2, 3, 4]), word([5, 6, 7, 8])]);
    assert_digest(
        merged,
        [0x4d75748c8d801fcb, 0x08777791a35ff853, 0x1b245de8521c0075, 0x24e16f44209db86c],
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
