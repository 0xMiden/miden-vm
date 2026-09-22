use alloc::vec::Vec;

use super::{
    Custom, DomainTag, DomainVersion, Eidos, EidosDomain, FeltSequence,
    domain::namespace,
    domains::{GENERIC_FELT_SEQUENCE, RANDOM_COIN_STATE},
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
        [0xd797d82493c946e7, 0x7ebffc6a929e8a05, 0x16010584c8181053, 0xcf1e8c0aa7223e1e],
    );
    assert_digest(
        Eidos::hash(&[]),
        [0xddd50d531bbb1983, 0xd2cdfac3a28b34e0, 0xb90f9a512419754b, 0x01cc5eec6a1190b7],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(3)),
        [0xd0b97de765f5c3a3, 0x870aec2466e7ebb2, 0xa3dcc5c6b7646454, 0x44a1bbd537d22435],
    );
    assert_digest(
        Eidos::hash(b"abc"),
        [0x11c3eb2d730c8d26, 0x241280e23aec5017, 0xc065fdebf76c7a4e, 0x9f0fbcfe49303be9],
    );
    assert_digest(
        Eidos::hash_elements_in_domain(&felts_seq(4), RANDOM_COIN_STATE),
        [0x46ed35f2fed3b2c0, 0x6901c4915a6eae43, 0xfaebee485c688740, 0x45f439f08633b281],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(9)),
        [0xeff260cce7e01134, 0xf1640e1a9256dae3, 0x7f8c54b883859269, 0x7de7a2a349715543],
    );
    let bytes: Vec<u8> = (0..65).map(|i| i as u8).collect();
    assert_digest(
        Eidos::hash(&bytes),
        [0x711221caef67e3a5, 0x1064bf7504a6166f, 0xb2f4ee115db4ba18, 0x4013d585171a9ef2],
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
            IV[1],
            params[0],
            IV[3],
            params[1],
            IV[5],
            params[2],
            IV[7],
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

    assert_eq!(lanes, [0, IV[1], 0, IV[3], 0, IV[5], 0, IV[7],]);
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
        [0xfe7a59b6012eed49, 0xa2fd18f77489a861, 0x515597f58df3a925, 0x76fc83521d811d94],
    );

    let mut challenger = MidenEidosChallenger::new(word([1, 2, 3, 4]), word([10, 11, 12, 13]));
    for value in 20..=24 {
        challenger.observe(Felt::new_unchecked(value));
    }
    let first = Word::new(core::array::from_fn(|_| CanSample::<Felt>::sample(&mut challenger)));
    let second = Word::new(core::array::from_fn(|_| CanSample::<Felt>::sample(&mut challenger)));
    assert_digest(
        first,
        [0x24afc1417b2c9705, 0xe50ebeda7c4150d5, 0xaa56fdf200cd0931, 0x7644e8ccafb0faab],
    );
    assert_digest(
        second,
        [0xf5e6fcd81b5e2f34, 0x310c14646ccba39c, 0x79caf2002df0472c, 0x2a3dba755f3449c8],
    );
}
