//! Mock implementations for testing stateful hashers.
//!
//! This module provides mock permutations and hashers for testing adapter behavior
//! without real cryptographic primitives. All mocks use position-weighted sums
//! (`sum(input[i] * (i + 1))`) to detect position-related bugs.

use core::{array, marker::PhantomData};

use p3_symmetric::{CryptographicHasher, CryptographicPermutation, Permutation};

// =============================================================================
// MockBinaryPermutation
// =============================================================================

/// A position-sensitive mock permutation for binary types.
///
/// Computes `sum(state[i] * (i + 1))` using wrapping arithmetic, making the result
/// dependent on WHERE values appear, not just WHAT values appear. This catches bugs
/// where values are in wrong positions.
#[derive(Clone, Debug)]
pub struct MockBinaryPermutation<T, const N: usize>(PhantomData<[T; N]>);

impl<T, const N: usize> Default for MockBinaryPermutation<T, N> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T, const N: usize> MockBinaryPermutation<T, N> {
    pub fn new() -> Self {
        Self::default()
    }
}

// Binary type implementations (using wrapping arithmetic)
macro_rules! impl_mock_binary_permutation {
    ($($t:ty),*) => {$(
        impl<const N: usize> Permutation<[$t; N]> for MockBinaryPermutation<$t, N> {
            fn permute_mut(&self, input: &mut [$t; N]) {
                // Compute position-weighted sum: sum(input[i] * (i + 1))
                let weighted_sum: $t = input
                    .iter()
                    .enumerate()
                    .fold(0, |acc, (i, &val)| {
                        acc.wrapping_add(val.wrapping_mul((i as $t).wrapping_add(1)))
                    });
                *input = [weighted_sum; N];
            }
        }
        impl<const N: usize> CryptographicPermutation<[$t; N]> for MockBinaryPermutation<$t, N> {}
    )*};
}

impl_mock_binary_permutation!(u8, u16, u32, u64);

// =============================================================================
// MockBinaryHasher
// =============================================================================

/// A position-sensitive mock hasher for binary types.
///
/// Computes `sum(input[i] * (i + 1))` using wrapping arithmetic, consistent with
/// [`MockBinaryPermutation`]. This catches bugs where values end up in wrong positions.
///
/// Supports both scalar hashing (`T -> [T; N]`) and parallel hashing (`[T; M] -> [[T; M]; N]`).
#[derive(Clone, Debug, Default)]
pub struct MockBinaryHasher;

// Scalar hashing: T -> [T; N]
macro_rules! impl_mock_binary_hasher_scalar {
    ($($t:ty),*) => {$(
        impl<const N: usize> CryptographicHasher<$t, [$t; N]> for MockBinaryHasher {
            fn hash_iter<I: IntoIterator<Item = $t>>(&self, iter: I) -> [$t; N] {
                // Position-weighted sum: sum(input[i] * (i + 1))
                let weighted_sum: $t = iter
                    .into_iter()
                    .enumerate()
                    .fold(0, |acc, (i, val)| {
                        acc.wrapping_add(val.wrapping_mul((i as $t).wrapping_add(1)))
                    });
                [weighted_sum; N]
            }
        }
    )*};
}

impl_mock_binary_hasher_scalar!(u8, u16, u32, u64);

// Parallel hashing: [T; M] -> [[T; M]; N]
// Each lane is hashed independently with position-weighting.
macro_rules! impl_mock_binary_hasher_parallel {
    ($($t:ty),*) => {$(
        impl<const N: usize, const M: usize> CryptographicHasher<[$t; M], [[$t; M]; N]> for MockBinaryHasher {
            fn hash_iter<I: IntoIterator<Item = [$t; M]>>(&self, iter: I) -> [[$t; M]; N] {
                // Position-weighted sum per lane: sum(input[i][lane] * (i + 1))
                let weighted_sum: [$t; M] = iter
                    .into_iter()
                    .enumerate()
                    .fold([0; M], |acc, (i, vals)| {
                        let multiplier = (i as $t).wrapping_add(1);
                        array::from_fn(|lane| {
                            acc[lane].wrapping_add(vals[lane].wrapping_mul(multiplier))
                        })
                    });
                [weighted_sum; N]
            }
        }
    )*};
}

impl_mock_binary_hasher_parallel!(u8, u16, u32, u64);
