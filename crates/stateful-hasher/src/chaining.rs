//! Chaining-mode stateful hasher.
//!
//! This module provides [`ChainingHasher`] which wraps a regular hasher and
//! implements stateful hashing via chaining: `H(state || input)`.

use p3_field::Field;
use p3_symmetric::CryptographicHasher;

use crate::{Alignable, StatefulHasher};

/// An adapter that chains state with new input, hashing `state || encode(input)`.
///
/// This mirrors `SerializingHasher`'s conversions from fields to bytes/u32/u64 streams,
/// but implements the `StatefulHasher` interface where the state is the digest itself.
///
/// Unlike `SerializingStatefulSponge` (which preserves proper sponge semantics),
/// this adapter uses chaining mode where each absorption computes `H(state || input)`.
#[derive(Copy, Clone, Debug)]
pub struct ChainingHasher<Inner> {
    inner: Inner,
}

impl<Inner> ChainingHasher<Inner> {
    pub const fn new(inner: Inner) -> Self {
        Self { inner }
    }
}

// -----------------------------------------------------------------------------
// Scalar implementations: F -> [T; N]
// For ChainingHasher, State = Digest since the state IS the digest.
// -----------------------------------------------------------------------------

// Scalar field -> byte digest
impl<F, Inner, const N: usize> StatefulHasher<F, [u8; N]> for ChainingHasher<Inner>
where
    F: Field,
    Inner: CryptographicHasher<u8, [u8; N]>,
    [u8; N]: Default,
{
    type State = [u8; N];

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = F>) {
        let prev = *state;
        *state = self.inner.hash_iter(prev.into_iter().chain(F::into_byte_stream(input)));
    }

    fn squeeze(&self, state: &Self::State) -> [u8; N] {
        *state
    }
}

// Scalar field -> u32 digest
impl<F, Inner, const N: usize> StatefulHasher<F, [u32; N]> for ChainingHasher<Inner>
where
    F: Field,
    Inner: CryptographicHasher<u32, [u32; N]>,
    [u32; N]: Default,
{
    type State = [u32; N];

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = F>) {
        let prev = *state;
        *state = self.inner.hash_iter(prev.into_iter().chain(F::into_u32_stream(input)));
    }

    fn squeeze(&self, state: &Self::State) -> [u32; N] {
        *state
    }
}

// Scalar field -> u64 digest
impl<F, Inner, const N: usize> StatefulHasher<F, [u64; N]> for ChainingHasher<Inner>
where
    F: Field,
    Inner: CryptographicHasher<u64, [u64; N]>,
    [u64; N]: Default,
{
    type State = [u64; N];

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = F>) {
        let prev = *state;
        *state = self.inner.hash_iter(prev.into_iter().chain(F::into_u64_stream(input)));
    }

    fn squeeze(&self, state: &Self::State) -> [u64; N] {
        *state
    }
}

// -----------------------------------------------------------------------------
// Parallel implementations: [F; M] -> [[T; M]; OUT]
// For ChainingHasher, State = Digest since the state IS the digest.
// -----------------------------------------------------------------------------

// Parallel lanes (array-based) implemented via per-lane scalar hashing.
impl<F, Inner, const OUT: usize, const M: usize> StatefulHasher<[F; M], [[u8; M]; OUT]>
    for ChainingHasher<Inner>
where
    F: Field,
    Inner: CryptographicHasher<[u8; M], [[u8; M]; OUT]>,
    [[u8; M]; OUT]: Default,
{
    type State = [[u8; M]; OUT];

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = [F; M]>) {
        let prev = *state;
        *state = self
            .inner
            .hash_iter(prev.into_iter().chain(F::into_parallel_byte_streams(input)));
    }

    fn squeeze(&self, state: &Self::State) -> [[u8; M]; OUT] {
        *state
    }
}

impl<F, Inner, const OUT: usize, const M: usize> StatefulHasher<[F; M], [[u32; M]; OUT]>
    for ChainingHasher<Inner>
where
    F: Field,
    Inner: CryptographicHasher<[u32; M], [[u32; M]; OUT]>,
    [[u32; M]; OUT]: Default,
{
    type State = [[u32; M]; OUT];

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = [F; M]>) {
        let prev = *state;
        *state = self
            .inner
            .hash_iter(prev.into_iter().chain(F::into_parallel_u32_streams(input)));
    }

    fn squeeze(&self, state: &Self::State) -> [[u32; M]; OUT] {
        *state
    }
}

impl<F, Inner, const OUT: usize, const M: usize> StatefulHasher<[F; M], [[u64; M]; OUT]>
    for ChainingHasher<Inner>
where
    F: Field,
    Inner: CryptographicHasher<[u64; M], [[u64; M]; OUT]>,
    [[u64; M]; OUT]: Default,
{
    type State = [[u64; M]; OUT];

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = [F; M]>) {
        let prev = *state;
        *state = self
            .inner
            .hash_iter(prev.into_iter().chain(F::into_parallel_u64_streams(input)));
    }

    fn squeeze(&self, state: &Self::State) -> [[u64; M]; OUT] {
        *state
    }
}

// -----------------------------------------------------------------------------
// Alignable implementations for ChainingHasher
// Chaining mode has no padding, so alignment is always 1.
// -----------------------------------------------------------------------------

// For any Input and Target, ChainingHasher has alignment 1 (no padding).
// We use a blanket impl with no bounds since alignment doesn't depend on types.
impl<Input, Target, Inner> Alignable<Input, Target> for ChainingHasher<Inner> {
    const ALIGNMENT: usize = 1;
}

#[cfg(test)]
mod tests {
    use core::array;

    use p3_bn254::Bn254;
    use p3_field::{Field, RawDataSerializable};
    use p3_goldilocks::Goldilocks;
    use p3_mersenne_31::Mersenne31;

    use super::*;
    use crate::testing::MockBinaryHasher;

    /// Verifies ChainingHasher produces same result as manual H(state || input) chaining.
    fn test_scalar_matches_manual<F: Field + RawDataSerializable>() {
        let hasher = ChainingHasher::new(MockBinaryHasher);
        let inputs: [F; 17] = array::from_fn(|i| F::from_usize(i * 7 + 3));
        let segments: &[core::ops::Range<usize>] = &[0..3, 3..5, 5..9, 9..17];

        // Test via adapter
        let mut state_adapter = [0u64; 4];
        for seg in segments {
            StatefulHasher::<F, [u64; 4]>::absorb_into(
                &hasher,
                &mut state_adapter,
                inputs[seg.clone()].iter().copied(),
            );
        }

        // Test via manual chaining
        let mut state_manual = [0u64; 4];
        for seg in segments {
            let prefix = state_manual.into_iter();
            let words = F::into_u64_stream(inputs[seg.clone()].iter().copied());
            state_manual = MockBinaryHasher.hash_iter(prefix.chain(words));
        }

        assert_eq!(state_adapter, state_manual);
    }

    #[test]
    fn scalar_matches_manual() {
        test_scalar_matches_manual::<Mersenne31>(); // 4 bytes
        test_scalar_matches_manual::<Goldilocks>(); // 8 bytes
        test_scalar_matches_manual::<Bn254>(); // 32 bytes
    }

    /// Verifies parallel hashing matches per-lane scalar hashing.
    fn test_parallel_matches_scalar<F: Field>() {
        let hasher = ChainingHasher::new(MockBinaryHasher);
        let input: [F; 64] = array::from_fn(|i| F::from_usize(i * 7 + 3));

        let parallel_input: [[F; 4]; 16] = array::from_fn(|i| array::from_fn(|j| input[i * 4 + j]));
        let unzipped_input: [[F; 16]; 4] = array::from_fn(|i| parallel_input.map(|x| x[i]));

        let mut state_parallel = [[0u64; 4]; 4];
        StatefulHasher::<[F; 4], [[u64; 4]; 4]>::absorb_into(
            &hasher,
            &mut state_parallel,
            parallel_input,
        );

        let per_lane: [[u64; 4]; 4] = array::from_fn(|lane| {
            let mut s = [0u64; 4];
            StatefulHasher::<F, [u64; 4]>::absorb_into(&hasher, &mut s, unzipped_input[lane]);
            s
        });
        let per_lane_transposed: [[u64; 4]; 4] = array::from_fn(|i| per_lane.map(|x| x[i]));

        assert_eq!(state_parallel, per_lane_transposed);
    }

    #[test]
    fn parallel_matches_scalar() {
        test_parallel_matches_scalar::<Mersenne31>(); // 4 bytes
        test_parallel_matches_scalar::<Goldilocks>(); // 8 bytes
        test_parallel_matches_scalar::<Bn254>(); // 32 bytes
    }
}
