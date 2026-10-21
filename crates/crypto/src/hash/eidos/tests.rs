use alloc::{collections::BTreeSet, vec::Vec};

use proptest::prelude::*;

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
        [0x394b82985c203861, 0x767f9ee738c588d9, 0x4a582bcdcf50b7c6, 0x29d2a973dd12e195],
    );
    assert_digest(
        Eidos::hash(&[]),
        [0x1a1d01f1f53d5a1a, 0x60a2c88bb5ef01fc, 0x579e22074274d2d0, 0x145e42f2d5759c97],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(3)),
        [0x64428385d648baa2, 0x5404c904e97a7f37, 0x7c4cf2c1b0c7ef6a, 0x77d4c8d4ae1ad174],
    );
    assert_digest(
        Eidos::hash(b"abc"),
        [0x07f9536d92a1654f, 0x2e317349ae070f54, 0x5a60f9e1b34e0d3d, 0x60bb248ba9c1794f],
    );
    assert_digest(
        Eidos::hash_elements_in_domain(&felts_seq(4), RANDOM_COIN_STATE),
        [0x0f8c1c7a8568edc8, 0x1a04d832f38ca35a, 0x1a21f18cbe36e475, 0x6aa934b4e4804a28],
    );
    assert_digest(
        Eidos::hash_elements(&felts_seq(9)),
        [0x145da8dc3881a521, 0x6aace1ee7b38c0dd, 0x5e586c8122d16b20, 0x578c44963e7c6146],
    );
    let bytes: Vec<u8> = (0..65).map(|i| i as u8).collect();
    assert_digest(
        Eidos::hash(&bytes),
        [0x4afc15e949880e22, 0x481ee11654cb9add, 0x48f18d9556b4c92c, 0x2fdc84adcdd09358],
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

    assert_eq!(lanes, [0, IV[1], 0, IV[3], 0, IV[5], 0, IV[7]]);
}

#[test]
fn hash_double_word_in_domain_matches_hash_elements_in_domain() {
    let left = word([10, 20, 30, 40]);
    let right = word([50, 60, 70, 80]);
    let concat = vec![left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3]];

    assert_eq!(
        Eidos::hash_double_word_in_domain(&[left, right], RANDOM_COIN_STATE),
        Eidos::hash_elements_in_domain(&concat, RANDOM_COIN_STATE)
    );
}

#[test]
fn hash_double_word_matches_generic_felt_hash() {
    let left = word([10, 20, 30, 40]);
    let right = word([50, 60, 70, 80]);
    let concat = vec![left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3]];

    assert_eq!(Eidos::hash_double_word(&[left, right]), Eidos::hash_elements(&concat));
    assert_ne!(Eidos::hash_double_word(&[left, right]), Eidos::merge(&[left, right]));
}

#[test]
fn hash_words_matches_hash_elements_on_concat() {
    let words = vec![word([1, 2, 3, 4]), word([5, 6, 7, 8]), word([9, 10, 11, 12])];
    let mut concat = Vec::new();
    for w in &words {
        concat.extend_from_slice(w.as_ref());
    }

    assert_eq!(Eidos::hash_words(&words), Eidos::hash_elements(&concat));
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
fn zero_byte_inputs_of_different_lengths_do_not_collide() {
    let zeroes = [0u8; 254];
    let mut hashes = BTreeSet::new();

    for len in 0..=zeroes.len() {
        assert!(hashes.insert(Eidos::hash(&zeroes[..len])), "collision at byte length {len}");
    }
}

proptest! {
    #[test]
    fn eidos_hash_wont_panic_with_arbitrary_input(ref bytes in any::<Vec<u8>>()) {
        Eidos::hash(bytes);
    }
}

#[test]
fn frozen_merge_and_challenger_vectors() {
    use p3_challenger::{CanObserve, CanSample};

    use super::MidenEidosChallenger;

    let merged = Eidos::merge(&[word([1, 2, 3, 4]), word([5, 6, 7, 8])]);
    assert_digest(
        merged,
        [0x6ca4b9f83388bfcd, 0x35f5179a10630d76, 0x258fe3db5ee34599, 0x7709af38e69c9e2b],
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
