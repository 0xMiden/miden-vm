#![cfg(feature = "std")]
use alloc::{collections::BTreeSet, vec::Vec};

use proptest::prelude::*;

use super::{Felt, Rpx256};
use crate::{ONE, Word, ZERO, rand::test_utils::rand_value};

// The number of iterations to run the `ext_round_matches_reference_many` test.
#[cfg(all(
    target_arch = "x86_64",
    any(
        target_feature = "avx2",
        all(target_feature = "avx512f", target_feature = "avx512dq")
    )
))]
const EXT_ROUND_TEST_ITERS: usize = 5_000_000;

#[test]
fn hash_elements_vs_merge() {
    let elements = [Felt::new_unchecked(rand_value()); 8];

    let digests: [Word; 2] = [
        Word::new(elements[..4].try_into().unwrap()),
        Word::new(elements[4..].try_into().unwrap()),
    ];

    let m_result = Rpx256::merge(&digests);
    let h_result = Rpx256::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn merge_vs_merge_in_domain() {
    let elements = [Felt::new_unchecked(rand_value()); 8];

    let digests: [Word; 2] = [
        Word::new(elements[..4].try_into().unwrap()),
        Word::new(elements[4..].try_into().unwrap()),
    ];
    let merge_result = Rpx256::merge(&digests);

    // ----- merge with domain = 0 ----------------------------------------------------------------

    // set domain to ZERO. This should not change the result.
    let domain = ZERO;

    let merge_in_domain_result = Rpx256::merge_in_domain(&digests, domain);
    assert_eq!(merge_result, merge_in_domain_result);

    // ----- merge with domain = 1 ----------------------------------------------------------------

    // set domain to ONE. This should change the result.
    let domain = ONE;

    let merge_in_domain_result = Rpx256::merge_in_domain(&digests, domain);
    assert_ne!(merge_result, merge_in_domain_result);
}

#[test]
fn hash_padding() {
    // adding a zero bytes at the end of a byte string should result in a different hash
    let r1 = Rpx256::hash(&[1_u8, 2, 3]);
    let r2 = Rpx256::hash(&[1_u8, 2, 3, 0]);
    assert_ne!(r1, r2);

    // same as above but with bigger inputs
    let r1 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6]);
    let r2 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6, 0]);
    assert_ne!(r1, r2);

    // same as above but with input splitting over two elements
    let r1 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6, 7]);
    let r2 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0]);
    assert_ne!(r1, r2);

    // same as above but with multiple zeros
    let r1 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0]);
    let r2 = Rpx256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0]);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements_padding() {
    let e1 = [Felt::new_unchecked(rand_value()); 2];
    let e2 = [e1[0], e1[1], ZERO];

    let r1 = Rpx256::hash_elements(&e1);
    let r2 = Rpx256::hash_elements(&e2);
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

    let m_result = Rpx256::merge(&digests);
    let h_result = Rpx256::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn hash_empty() {
    let elements: Vec<Felt> = vec![];

    let zero_digest = Word::default();
    let h_result = Rpx256::hash_elements(&elements);
    assert_eq!(zero_digest, h_result);
}

#[test]
fn hash_empty_bytes() {
    let bytes: Vec<u8> = vec![];

    let zero_digest = Word::default();
    let h_result = Rpx256::hash(&bytes);
    assert_eq!(zero_digest, h_result);
}

#[test]
fn sponge_bytes_with_remainder_length_wont_panic() {
    // this test targets to assert that no panic will happen with the edge case of having an inputs
    // with length that is not divisible by the used binary chunk size. 113 is a non-negligible
    // input length that is prime; hence guaranteed to not be divisible by any choice of chunk
    // size.
    //
    // this is a preliminary test to the fuzzy-stress of proptest.
    Rpx256::hash(&[0; 113]);
}

#[test]
fn sponge_collision_for_wrapped_field_element() {
    let a = Rpx256::hash(&[0; 8]);
    let b = Rpx256::hash(&Felt::ORDER.to_le_bytes());
    assert_ne!(a, b);
}

#[test]
fn sponge_zeroes_collision() {
    let mut zeroes = Vec::with_capacity(255);
    let mut set = BTreeSet::new();
    (0..255).for_each(|_| {
        let hash = Rpx256::hash(&zeroes);
        zeroes.push(0);
        // panic if a collision was found
        assert!(set.insert(hash));
    });
}

/// Verifies that the optimized RPX (E) round (SIMD path) matches the
/// scalar reference implementation across many random states.
///
/// Compiles and runs only when we build an x86_64 target with AVX2 or AVX-512 enabled.
/// At runtime, if the host CPU lacks the compiled feature, the test returns early.
#[cfg(all(
    target_arch = "x86_64",
    any(
        target_feature = "avx2",
        all(target_feature = "avx512f", target_feature = "avx512dq")
    )
))]
#[test]
fn ext_round_matches_reference_many() {
    for i in 0..EXT_ROUND_TEST_ITERS {
        let mut state = core::array::from_fn(|_| Felt::new_unchecked(rand_value()));

        for round in 0..7 {
            let mut got = state;
            let mut want = state;

            // Optimized path (AVX2 or AVX-512 depending on build).
            Rpx256::apply_ext_round(&mut got, round);
            // Scalar reference path.
            Rpx256::apply_ext_round_ref(&mut want, round);

            assert_eq!(got, want, "mismatch at round {round} (iteration {i})");
            state = got; // advance to catch chaining issues
        }
    }
}

proptest! {
    #[test]
    fn rpo256_wont_panic_with_arbitrary_input(ref bytes in any::<Vec<u8>>()) {
        Rpx256::hash(bytes);
    }
}

// PLONKY3 INTEGRATION TESTS
// ================================================================================================

mod p3_tests {
    use p3_symmetric::{CryptographicHasher, Permutation, PseudoCompressionFunction};

    use super::*;
    use crate::hash::algebraic_sponge::rescue::rpx::{
        RpxCompression, RpxHasher, RpxPermutation256, STATE_WIDTH, cubic_ext,
    };

    #[test]
    fn test_cubic_ext_power7() {
        use cubic_ext::*;

        // Test with a simple element [1, 0, 0]
        let x = [Felt::new_unchecked(1), Felt::new_unchecked(0), Felt::new_unchecked(0)];
        let x7 = power7(x);
        assert_eq!(x7, x, "1^7 should equal 1");

        // Test with [0, 1, 0] (just φ)
        let phi = [Felt::new_unchecked(0), Felt::new_unchecked(1), Felt::new_unchecked(0)];
        let phi7 = power7(phi);
        // φ^7 should be some combination - verify it's computed correctly
        assert_ne!(phi7, phi, "φ^7 should not equal φ");

        // Test with [1, 1, 1]
        let x = [Felt::new_unchecked(1), Felt::new_unchecked(1), Felt::new_unchecked(1)];
        let x7 = power7(x);
        assert_ne!(x7, x, "(1+φ+φ²)^7 should not equal 1+φ+φ²");

        // Verify power7 is consistent
        let x = [Felt::new_unchecked(42), Felt::new_unchecked(17), Felt::new_unchecked(99)];
        let x7_a = power7(x);
        let x7_b = power7(x);
        assert_eq!(x7_a, x7_b, "power7 should be deterministic");
    }

    #[test]
    fn test_rpx_permutation_basic() {
        let mut state = [Felt::new_unchecked(0); STATE_WIDTH];

        // Apply permutation
        let perm = RpxPermutation256;
        perm.permute_mut(&mut state);

        // State should be different from all zeros after permutation
        assert_ne!(state, [Felt::new_unchecked(0); STATE_WIDTH]);
    }

    #[test]
    fn test_rpx_permutation_consistency() {
        let mut state1 = [Felt::new_unchecked(0); STATE_WIDTH];
        let mut state2 = [Felt::new_unchecked(0); STATE_WIDTH];

        // Apply permutation using the trait
        let perm = RpxPermutation256;
        perm.permute_mut(&mut state1);

        // Apply permutation directly
        RpxPermutation256::apply_permutation(&mut state2);

        // Both should produce the same result
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_rpx_permutation_deterministic() {
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

        let perm = RpxPermutation256;
        perm.permute_mut(&mut state1);
        perm.permute_mut(&mut state2);

        // Same input should produce same output
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_rpx_hasher_vs_hash_elements() {
        let hasher = RpxHasher::new(RpxPermutation256);

        // Test with 8 elements (exactly one rate)
        let input8 = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ];
        let expected: [Felt; 4] = Rpx256::hash_elements(&input8).into();
        let result = hasher.hash_iter(input8);
        assert_eq!(result, expected, "8 elements (one rate) should produce same digest");

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
        let expected: [Felt; 4] = Rpx256::hash_elements(&input16).into();
        let result = hasher.hash_iter(input16);
        assert_eq!(result, expected, "16 elements (two rates) should produce same digest");
    }

    #[test]
    fn test_rpx_compression_vs_merge() {
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

        // Rpx256::merge expects &[Word; 2]
        let expected: [Felt; 4] = Rpx256::merge(&[digest1.into(), digest2.into()]).into();

        // RpxCompression expects [[Felt; 4]; 2]
        let compress = RpxCompression::new(RpxPermutation256);
        let result = compress.compress([digest1, digest2]);

        assert_eq!(result, expected, "RpxCompression should match Rpx256::merge");
    }
}
