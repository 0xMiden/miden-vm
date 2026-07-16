//! Field-based stateful sponge.
//!
//! This module provides [`StatefulSponge`] which wraps a cryptographic permutation
//! and implements proper sponge absorption semantics.

use p3_symmetric::CryptographicPermutation;

use crate::{Alignable, StatefulHasher};

/// A stateful sponge wrapper around a cryptographic permutation.
///
/// This implements proper sponge absorption semantics where the state evolves
/// with each absorption. Unlike `PaddingFreeSponge` (which implements `CryptographicHasher`),
/// this struct only implements `StatefulHasher`.
///
/// `WIDTH` is the sponge's rate plus capacity.
/// `RATE` is the number of elements absorbed per permutation.
/// `OUT` is the number of elements squeezed from the state.
#[derive(Copy, Clone, Debug)]
pub struct StatefulSponge<P, const WIDTH: usize, const RATE: usize, const OUT: usize> {
    permutation: P,
}

impl<P, const WIDTH: usize, const RATE: usize, const OUT: usize>
    StatefulSponge<P, WIDTH, RATE, OUT>
{
    pub const fn new(permutation: P) -> Self {
        Self { permutation }
    }
}

impl<P, T, const WIDTH: usize, const RATE: usize, const OUT: usize> StatefulHasher<T, [T; OUT]>
    for StatefulSponge<P, WIDTH, RATE, OUT>
where
    T: Default + Clone,
    P: CryptographicPermutation<[T; WIDTH]>,
    [T; WIDTH]: Default,
{
    type State = [T; WIDTH];

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = T>) {
        const { assert!(OUT < WIDTH) }
        let mut input = input.into_iter();

        'outer: loop {
            for i in 0..RATE {
                if let Some(x) = input.next() {
                    state[i] = x;
                } else {
                    if i != 0 {
                        state[i..RATE].fill(T::default());
                        self.permutation.permute_mut(state);
                    }
                    break 'outer;
                }
            }
            self.permutation.permute_mut(state);
        }
    }

    fn squeeze(&self, state: &Self::State) -> [T; OUT] {
        const { assert!(OUT < WIDTH) }
        core::array::from_fn(|i| state[i].clone())
    }
}

impl<P, T, const WIDTH: usize, const RATE: usize, const OUT: usize> Alignable<T, T>
    for StatefulSponge<P, WIDTH, RATE, OUT>
{
    const ALIGNMENT: usize = RATE;
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::testing::MockBinaryPermutation;

    #[test]
    fn basic() {
        const WIDTH: usize = 4;
        const RATE: usize = 2;
        const OUT: usize = 2;

        let sponge = StatefulSponge::<_, WIDTH, RATE, OUT>::new(
            MockBinaryPermutation::<u64, WIDTH>::default(),
        );

        let input = [1u64, 2, 3, 4, 5];
        let mut state = [0u64; WIDTH];
        sponge.absorb_into(&mut state, input);
        let output: [u64; OUT] = sponge.squeeze(&state);

        // StatefulSponge pads partial blocks to rate boundary (proper sponge semantics):
        // MockPermutation computes: sum(state[i] * (i + 1))
        //
        // Initial state: [0, 0, 0, 0]
        // First input chunk [1, 2] overwrites positions 0,1: [1, 2, 0, 0]
        // Permute: 1*1 + 2*2 + 0*3 + 0*4 = 5 -> [5, 5, 5, 5]
        // Second input chunk [3, 4] overwrites positions 0,1: [3, 4, 5, 5]
        // Permute: 3*1 + 4*2 + 5*3 + 5*4 = 46 -> [46, 46, 46, 46]
        // Third input chunk [5] overwrites position 0: [5, 46, 46, 46]
        // Pad position 1 with 0: [5, 0, 46, 46]
        // Permute: 5*1 + 0*2 + 46*3 + 46*4 = 327 -> [327, 327, 327, 327]
        assert_eq!(output, [327; OUT]);
    }

    /// Verifies implicit zero-padding equals explicit zeros.
    fn test_alignment_semantic<const WIDTH: usize, const RATE: usize, const OUT: usize>()
    where
        [u64; WIDTH]: Default,
    {
        let sponge = StatefulSponge::<_, WIDTH, RATE, OUT>::new(
            MockBinaryPermutation::<u64, WIDTH>::default(),
        );

        for input_len in 1..=(RATE * 3) {
            let input: Vec<u64> = (1..=input_len as u64).collect();

            let mut state_unpadded = [0u64; WIDTH];
            sponge.absorb_into(&mut state_unpadded, input.iter().copied());
            let output_unpadded: [u64; OUT] = sponge.squeeze(&state_unpadded);

            let remainder = input_len % RATE;
            let zeros_needed = if remainder == 0 { 0 } else { RATE - remainder };
            let mut padded_input = input.clone();
            padded_input.extend(core::iter::repeat_n(0u64, zeros_needed));

            let mut state_padded = [0u64; WIDTH];
            sponge.absorb_into(&mut state_padded, padded_input.iter().copied());
            let output_padded: [u64; OUT] = sponge.squeeze(&state_padded);

            assert_eq!(output_unpadded, output_padded);
        }
    }

    #[test]
    fn alignment_semantic() {
        test_alignment_semantic::<4, 2, 2>();
        test_alignment_semantic::<6, 3, 2>();
        test_alignment_semantic::<8, 4, 2>();
    }
}
