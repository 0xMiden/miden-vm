//! Packed-state permutation impls for the algebraic sponges.
//!
//! `DuplexChallenger`'s `GrindingChallenger` impl requires the permutation to also work over
//! `[Felt::Packing; STATE_WIDTH]` so that proof-of-work grinding can test one witness candidate
//! per SIMD lane. Poseidon2 delegates to Plonky3's vectorized packed-Goldilocks permutation.
//! RPO and RPX have no vectorized implementation, so their impls apply the scalar permutation
//! to each lane independently: throughput matches the scalar path.

use miden_field::{PackedFelt, PackedValue};
use p3_symmetric::{CryptographicPermutation, Permutation};

use super::{
    Felt, STATE_WIDTH,
    poseidon2::{Poseidon2Permutation256, p3_permute_packed},
    rescue::{rpo::RpoPermutation256, rpx::RpxPermutation256},
};

/// Applies a scalar permutation independently to each SIMD lane of a packed sponge state.
fn permute_lanes(state: &mut [PackedFelt; STATE_WIDTH], permute: fn(&mut [Felt; STATE_WIDTH])) {
    let mut scalars = [Felt::ZERO; STATE_WIDTH];
    for lane in 0..PackedFelt::WIDTH {
        for (scalar, packed) in scalars.iter_mut().zip(state.iter()) {
            *scalar = packed.as_slice()[lane];
        }
        permute(&mut scalars);
        for (packed, scalar) in state.iter_mut().zip(scalars) {
            packed.as_slice_mut()[lane] = scalar;
        }
    }
}

impl Permutation<[PackedFelt; STATE_WIDTH]> for RpoPermutation256 {
    fn permute_mut(&self, state: &mut [PackedFelt; STATE_WIDTH]) {
        permute_lanes(state, Self::apply_permutation);
    }
}

impl CryptographicPermutation<[PackedFelt; STATE_WIDTH]> for RpoPermutation256 {}

impl Permutation<[PackedFelt; STATE_WIDTH]> for RpxPermutation256 {
    fn permute_mut(&self, state: &mut [PackedFelt; STATE_WIDTH]) {
        permute_lanes(state, Self::apply_permutation);
    }
}

impl CryptographicPermutation<[PackedFelt; STATE_WIDTH]> for RpxPermutation256 {}

impl Permutation<[PackedFelt; STATE_WIDTH]> for Poseidon2Permutation256 {
    fn permute_mut(&self, state: &mut [PackedFelt; STATE_WIDTH]) {
        p3_permute_packed(state);
    }
}

impl CryptographicPermutation<[PackedFelt; STATE_WIDTH]> for Poseidon2Permutation256 {}

#[cfg(test)]
mod tests {
    use miden_field::PrimeCharacteristicRing;

    use super::*;

    const LANES: usize = PackedFelt::WIDTH;

    /// Checks that permuting a packed state equals permuting each lane's scalar state.
    fn check(
        scalar_permute: fn(&mut [Felt; STATE_WIDTH]),
        packed_permute: impl Fn(&mut [PackedFelt; STATE_WIDTH]),
    ) {
        let mut packed = [PackedFelt::ZERO; STATE_WIDTH];
        let mut scalar_states = [[Felt::ZERO; STATE_WIDTH]; LANES];
        for (lane, scalar_state) in scalar_states.iter_mut().enumerate() {
            for (i, (packed_elem, scalar)) in
                packed.iter_mut().zip(scalar_state.iter_mut()).enumerate()
            {
                let value = Felt::new_unchecked((1 + i * LANES + lane) as u64);
                packed_elem.as_slice_mut()[lane] = value;
                *scalar = value;
            }
        }

        packed_permute(&mut packed);

        for (lane, scalar_state) in scalar_states.iter_mut().enumerate() {
            scalar_permute(scalar_state);
            for i in 0..STATE_WIDTH {
                assert_eq!(packed[i].as_slice()[lane], scalar_state[i]);
            }
        }
    }

    #[test]
    fn rpo_packed_permutation_matches_scalar() {
        check(RpoPermutation256::apply_permutation, |s| RpoPermutation256.permute_mut(s));
    }

    #[test]
    fn rpx_packed_permutation_matches_scalar() {
        check(RpxPermutation256::apply_permutation, |s| RpxPermutation256.permute_mut(s));
    }

    #[test]
    fn poseidon2_packed_permutation_matches_scalar() {
        check(Poseidon2Permutation256::apply_permutation, |s| {
            Poseidon2Permutation256.permute_mut(s)
        });
    }
}
