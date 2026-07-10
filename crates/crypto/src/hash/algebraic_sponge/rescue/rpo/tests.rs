#![cfg(feature = "std")]
use alloc::{collections::BTreeSet, vec::Vec};

use proptest::prelude::*;

use super::{
    super::{apply_inv_sbox, apply_sbox},
    Felt, Rpo256, STATE_WIDTH,
};

/// S-Box power for Rescue Prime hash function.
const ALPHA: u64 = 7;
/// Inverse S-Box power for Rescue Prime hash function.
const INV_ALPHA: u64 = 10540996611094048183;
use crate::{
    ONE, Word, ZERO,
    hash::algebraic_sponge::{BINARY_CHUNK_SIZE, CAPACITY_RANGE, RATE_RANGE, RATE_WIDTH},
    rand::test_utils::rand_value,
};

#[test]
fn test_sbox() {
    let state = [Felt::new_unchecked(rand_value()); STATE_WIDTH];

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp_const_u64::<ALPHA>());

    let mut actual = state;
    apply_sbox(&mut actual);

    assert_eq!(expected, actual);
}

#[test]
fn test_inv_sbox() {
    let state = [Felt::new_unchecked(rand_value()); STATE_WIDTH];

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp_const_u64::<INV_ALPHA>());

    let mut actual = state;
    apply_inv_sbox(&mut actual);

    assert_eq!(expected, actual);
}

#[test]
fn hash_elements_vs_merge() {
    let elements = [Felt::new_unchecked(rand_value()); 8];

    let digests: [Word; 2] = [
        Word::new(elements[..4].try_into().unwrap()),
        Word::new(elements[4..].try_into().unwrap()),
    ];

    let m_result = Rpo256::merge(&digests);
    let h_result = Rpo256::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn merge_vs_merge_in_domain() {
    let elements = [Felt::new_unchecked(rand_value()); 8];

    let digests: [Word; 2] = [
        Word::new(elements[..4].try_into().unwrap()),
        Word::new(elements[4..].try_into().unwrap()),
    ];
    let merge_result = Rpo256::merge(&digests);

    // ------------- merge with domain = 0 -------------

    // set domain to ZERO. This should not change the result.
    let domain = ZERO;

    let merge_in_domain_result = Rpo256::merge_in_domain(&digests, domain);
    assert_eq!(merge_result, merge_in_domain_result);

    // ------------- merge with domain = 1 -------------

    // set domain to ONE. This should change the result.
    let domain = ONE;

    let merge_in_domain_result = Rpo256::merge_in_domain(&digests, domain);
    assert_ne!(merge_result, merge_in_domain_result);
}

#[test]
fn hash_padding() {
    // adding a zero bytes at the end of a byte string should result in a different hash
    let r1 = Rpo256::hash(&[1_u8, 2, 3]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 0]);
    assert_ne!(r1, r2);

    // same as above but with bigger inputs
    let r1 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 0]);
    assert_ne!(r1, r2);

    // same as above but with input splitting over two elements
    let r1 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0]);
    assert_ne!(r1, r2);

    // same as above but with multiple zeros
    let r1 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0]);
    assert_ne!(r1, r2);
}

#[test]
fn hash_padding_no_extra_permutation_call() {
    use crate::hash::algebraic_sponge::DIGEST_RANGE;

    // Implementation
    let num_bytes = BINARY_CHUNK_SIZE * RATE_WIDTH;
    let mut buffer = vec![0_u8; num_bytes];
    *buffer.last_mut().unwrap() = 97;
    let r1 = Rpo256::hash(&buffer);

    // Expected
    let final_chunk = [0_u8, 0, 0, 0, 0, 0, 97, 1];
    let mut state = [ZERO; STATE_WIDTH];
    // padding when hashing bytes
    state[CAPACITY_RANGE.start] = Felt::from_u8(RATE_WIDTH as u8);
    // place the final padded chunk into the last rate element
    state[RATE_RANGE.end - 1] = Felt::new_unchecked(u64::from_le_bytes(final_chunk));
    Rpo256::apply_permutation(&mut state);

    assert_eq!(&r1[0..4], &state[DIGEST_RANGE]);
}

#[test]
fn hash_elements_padding() {
    let e1 = [Felt::new_unchecked(rand_value()); 2];
    let e2 = [e1[0], e1[1], ZERO];

    let r1 = Rpo256::hash_elements(&e1);
    let r2 = Rpo256::hash_elements(&e2);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements() {
    let elements = [
        ZERO,
        ONE,
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
    ];

    let digests: [Word; 2] = [
        Word::new(elements[..4].try_into().unwrap()),
        Word::new(elements[4..8].try_into().unwrap()),
    ];

    let m_result = Rpo256::merge(&digests);
    let h_result = Rpo256::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn hash_elements_vs_hash_elements_in_domain() {
    let input16 = [
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
        Felt::new_unchecked(9),
        Felt::new_unchecked(10),
        Felt::new_unchecked(11),
        Felt::new_unchecked(12),
        Felt::new_unchecked(13),
        Felt::new_unchecked(14),
        Felt::new_unchecked(15),
        Felt::new_unchecked(16),
    ];

    // hash_elements and hash_elements_in_domain should be identical if the domain is set to zero.
    assert_eq!(
        Rpo256::hash_elements(&input16),
        Rpo256::hash_elements_in_domain(&input16, Felt::ZERO)
    );

    // With a non-zero domain set in the latter, the results should differ.
    assert_ne!(
        Rpo256::hash_elements(&input16),
        Rpo256::hash_elements_in_domain(&input16, Felt::ONE)
    );
}

#[test]
fn hash_empty_elements_in_domain() {
    let elements: &[Felt] = &[];

    let plain = Rpo256::hash_elements(elements);
    let zero_domain = Rpo256::hash_elements_in_domain(elements, ZERO);
    let one_domain = Rpo256::hash_elements_in_domain(elements, ONE);

    assert_eq!(plain, zero_domain);
    assert_ne!(plain, one_domain);
}

#[test]
fn hash_empty() {
    let elements: Vec<Felt> = vec![];

    let zero_digest = Word::default();
    let h_result = Rpo256::hash_elements(&elements);
    assert_eq!(zero_digest, h_result);
}

#[test]
fn hash_empty_bytes() {
    let bytes: &[u8] = &[];
    let elements: &[Felt] = &[];

    let h_result = Rpo256::hash(bytes);
    assert_ne!(Word::default(), h_result);
    assert_ne!(Rpo256::hash_elements(elements), h_result);
}

#[test]
fn hash_test_vectors() {
    let elements = [
        ZERO,
        ONE,
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
        Felt::new_unchecked(9),
        Felt::new_unchecked(10),
        Felt::new_unchecked(11),
        Felt::new_unchecked(12),
        Felt::new_unchecked(13),
        Felt::new_unchecked(14),
        Felt::new_unchecked(15),
        Felt::new_unchecked(16),
        Felt::new_unchecked(17),
        Felt::new_unchecked(18),
    ];

    for (i, expected) in EXPECTED.iter().enumerate() {
        let result = Rpo256::hash_elements(&elements[..(i + 1)]);
        assert_eq!(result, *expected);
    }
}

#[test]
fn sponge_bytes_with_remainder_length_wont_panic() {
    // this test targets to assert that no panic will happen with the edge case of having an inputs
    // with length that is not divisible by the used binary chunk size. 113 is a non-negligible
    // input length that is prime; hence guaranteed to not be divisible by any choice of chunk
    // size.
    //
    // this is a preliminary test to the fuzzy-stress of proptest.
    Rpo256::hash(&[0; 113]);
}

#[test]
fn sponge_collision_for_wrapped_field_element() {
    let a = Rpo256::hash(&[0; 8]);
    let b = Rpo256::hash(&Felt::ORDER.to_le_bytes());
    assert_ne!(a, b);
}

#[test]
fn sponge_zeroes_collision() {
    let mut zeroes = Vec::with_capacity(255);
    let mut set = BTreeSet::new();
    (0..255).for_each(|_| {
        let hash = Rpo256::hash(&zeroes);
        zeroes.push(0);
        // panic if a collision was found
        assert!(set.insert(hash));
    });
}

proptest! {
    #[test]
    fn rpo256_wont_panic_with_arbitrary_input(ref bytes in any::<Vec<u8>>()) {
        Rpo256::hash(bytes);
    }
}

/// Expected hash outputs for RPO with the state layout `[RATE0, RATE1, CAPACITY]`.
///
/// These test vectors have been cross-checked against a Python reference implementation adapted
/// from the original specification at <https://github.com/ASDiscreteMathematics/rpo>. The
/// reference uses the same permutation (MDS matrix, round constants, S-Box) but with the
/// original layout `[CAPACITY, RATE0, RATE1]`. This script adapts it to use the current layout
/// `[RATE0, RATE1, CAPACITY]` and verifies all 19 vectors match.
///
/// The verification script is located at `generate_test_vectors.py` in this directory.
const EXPECTED: [Word; 19] = [
    Word::new([
        Felt::new_unchecked(8563248028282119176),
        Felt::new_unchecked(14757918088501470722),
        Felt::new_unchecked(14042820149444308297),
        Felt::new_unchecked(7607140247535155355),
    ]),
    Word::new([
        Felt::new_unchecked(8762449007102993687),
        Felt::new_unchecked(4386081033660325954),
        Felt::new_unchecked(5000814629424193749),
        Felt::new_unchecked(8171580292230495897),
    ]),
    Word::new([
        Felt::new_unchecked(16710087681096729759),
        Felt::new_unchecked(10808706421914121430),
        Felt::new_unchecked(14661356949236585983),
        Felt::new_unchecked(5683478730832134441),
    ]),
    Word::new([
        Felt::new_unchecked(5309818427047650994),
        Felt::new_unchecked(17172251659920546244),
        Felt::new_unchecked(8288476618870804357),
        Felt::new_unchecked(18080473279382182941),
    ]),
    Word::new([
        Felt::new_unchecked(3647545403045515695),
        Felt::new_unchecked(3358383208908083302),
        Felt::new_unchecked(8797161010298072910),
        Felt::new_unchecked(2412100201132087248),
    ]),
    Word::new([
        Felt::new_unchecked(8409780526028662686),
        Felt::new_unchecked(214479528340808320),
        Felt::new_unchecked(13626616722984122219),
        Felt::new_unchecked(13991752159726061594),
    ]),
    Word::new([
        Felt::new_unchecked(4800410126693035096),
        Felt::new_unchecked(8293686005479024958),
        Felt::new_unchecked(16849389505608627981),
        Felt::new_unchecked(12129312715917897796),
    ]),
    Word::new([
        Felt::new_unchecked(5421234586123900205),
        Felt::new_unchecked(9738602082989433872),
        Felt::new_unchecked(7017816005734536787),
        Felt::new_unchecked(8635896173743411073),
    ]),
    Word::new([
        Felt::new_unchecked(11707446879505873182),
        Felt::new_unchecked(7588005580730590001),
        Felt::new_unchecked(4664404372972250366),
        Felt::new_unchecked(17613162115550587316),
    ]),
    Word::new([
        Felt::new_unchecked(6991094187713033844),
        Felt::new_unchecked(10140064581418506488),
        Felt::new_unchecked(1235093741254112241),
        Felt::new_unchecked(16755357411831959519),
    ]),
    Word::new([
        Felt::new_unchecked(18007834547781860956),
        Felt::new_unchecked(5262789089508245576),
        Felt::new_unchecked(4752286606024269423),
        Felt::new_unchecked(15626544383301396533),
    ]),
    Word::new([
        Felt::new_unchecked(5419895278045886802),
        Felt::new_unchecked(10747737918518643252),
        Felt::new_unchecked(14861255521757514163),
        Felt::new_unchecked(3291029997369465426),
    ]),
    Word::new([
        Felt::new_unchecked(16916426112258580265),
        Felt::new_unchecked(8714377345140065340),
        Felt::new_unchecked(14207246102129706649),
        Felt::new_unchecked(6226142825442954311),
    ]),
    Word::new([
        Felt::new_unchecked(7320977330193495928),
        Felt::new_unchecked(15630435616748408136),
        Felt::new_unchecked(10194509925259146809),
        Felt::new_unchecked(15938750299626487367),
    ]),
    Word::new([
        Felt::new_unchecked(9872217233988117092),
        Felt::new_unchecked(5336302253150565952),
        Felt::new_unchecked(9650742686075483437),
        Felt::new_unchecked(8725445618118634861),
    ]),
    Word::new([
        Felt::new_unchecked(12539853708112793207),
        Felt::new_unchecked(10831674032088582545),
        Felt::new_unchecked(11090804155187202889),
        Felt::new_unchecked(105068293543772992),
    ]),
    Word::new([
        Felt::new_unchecked(7287113073032114129),
        Felt::new_unchecked(6373434548664566745),
        Felt::new_unchecked(8097061424355177769),
        Felt::new_unchecked(14780666619112596652),
    ]),
    Word::new([
        Felt::new_unchecked(17147873541222871127),
        Felt::new_unchecked(17350918081193545524),
        Felt::new_unchecked(5785390176806607444),
        Felt::new_unchecked(12480094913955467088),
    ]),
    Word::new([
        Felt::new_unchecked(17273934282489765074),
        Felt::new_unchecked(8007352780590012415),
        Felt::new_unchecked(16690624932024962846),
        Felt::new_unchecked(8137543572359747206),
    ]),
];

// PLONKY3 INTEGRATION TESTS
// ================================================================================================

mod p3_tests {
    use p3_symmetric::{CryptographicHasher, Permutation, PseudoCompressionFunction};

    use super::*;
    use crate::hash::algebraic_sponge::rescue::rpo::{
        RpoCompression, RpoHasher, RpoPermutation256,
    };

    #[test]
    fn test_rpo_permutation_basic() {
        let mut state = [Felt::new_unchecked(0); STATE_WIDTH];

        // Apply permutation
        let perm = RpoPermutation256;
        perm.permute_mut(&mut state);

        // State should be different from all zeros after permutation
        assert_ne!(state, [Felt::new_unchecked(0); STATE_WIDTH]);
    }

    #[test]
    fn test_rpo_permutation_consistency() {
        let mut state1 = [Felt::new_unchecked(0); STATE_WIDTH];
        let mut state2 = [Felt::new_unchecked(0); STATE_WIDTH];

        // Apply permutation using the trait
        let perm = RpoPermutation256;
        perm.permute_mut(&mut state1);

        // Apply permutation directly
        RpoPermutation256::apply_permutation(&mut state2);

        // Both should produce the same result
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_rpo_permutation_deterministic() {
        let input = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
            Felt::new_unchecked(9),
            Felt::new_unchecked(10),
            Felt::new_unchecked(11),
            Felt::new_unchecked(12),
        ];

        let mut state1 = input;
        let mut state2 = input;

        let perm = RpoPermutation256;
        perm.permute_mut(&mut state1);
        perm.permute_mut(&mut state2);

        // Same input should produce same output
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_rpo_hasher_vs_hash_elements() {
        let hasher = RpoHasher::new(RpoPermutation256);

        // Test with 8 elements (one rate)
        let input12 = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ];
        let expected: [Felt; 4] = Rpo256::hash_elements(&input12).into();
        let result = hasher.hash_iter(input12);
        assert_eq!(result, expected, "12 elements should produce same digest");

        // Test with 16 elements (two rates)
        let input16 = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
            Felt::new_unchecked(9),
            Felt::new_unchecked(10),
            Felt::new_unchecked(11),
            Felt::new_unchecked(12),
            Felt::new_unchecked(13),
            Felt::new_unchecked(14),
            Felt::new_unchecked(15),
            Felt::new_unchecked(16),
        ];
        let expected: [Felt; 4] = Rpo256::hash_elements(&input16).into();
        let result = hasher.hash_iter(input16);
        assert_eq!(result, expected, "16 elements (two rates) should produce same digest");
    }

    #[test]
    fn test_rpo_compression_vs_merge() {
        let digest1 = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ];
        let digest2 = [
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ];

        // Rpo256::merge expects &[Word; 2]
        let expected: [Felt; 4] = Rpo256::merge(&[digest1.into(), digest2.into()]).into();

        // RpoCompression expects [[Felt; 4]; 2]
        let compress = RpoCompression::new(RpoPermutation256);
        let result = compress.compress([digest1, digest2]);

        assert_eq!(result, expected, "RpoCompression should match Rpo256::merge");
    }
}
