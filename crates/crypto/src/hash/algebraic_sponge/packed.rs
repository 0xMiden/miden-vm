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

    /// Checks that permuting a packed state equals permuting each lane's scalar state,
    /// with element `i` of lane `lane` set to `value(i, lane)`.
    fn check_with(
        scalar_permute: fn(&mut [Felt; STATE_WIDTH]),
        packed_permute: impl Fn(&mut [PackedFelt; STATE_WIDTH]),
        value: impl Fn(usize, usize) -> Felt,
    ) {
        let mut packed = [PackedFelt::ZERO; STATE_WIDTH];
        let mut scalar_states = [[Felt::ZERO; STATE_WIDTH]; LANES];
        for (lane, scalar_state) in scalar_states.iter_mut().enumerate() {
            for (i, (packed_elem, scalar)) in
                packed.iter_mut().zip(scalar_state.iter_mut()).enumerate()
            {
                let value = value(i, lane);
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

    /// Checks that permuting a packed state equals permuting each lane's scalar state.
    fn check(
        scalar_permute: fn(&mut [Felt; STATE_WIDTH]),
        packed_permute: impl Fn(&mut [PackedFelt; STATE_WIDTH]),
    ) {
        check_with(scalar_permute, packed_permute, |i, lane| {
            Felt::new_unchecked((1 + i * LANES + lane) as u64)
        });
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

    /// Canonical values that stress the wraparound corrections in vectorized
    /// kernels: field extremes and the 2^32 epsilon window.
    ///
    /// Entry values must be canonical: the vectorized permutations (Plonky3's
    /// NEON path and the SVE2 kernel that mirrors it) use single-correction
    /// modular ops whose input contract all production `Felt` constructors
    /// satisfy. Non-canonical entries diverge from the scalar path even on
    /// unmodified upstream Plonky3.
    const EDGE_VALS: [u64; 6] = [0, 1, (1 << 32) - 1, 1 << 32, 1 << 63, Felt::ORDER - 1];

    #[test]
    fn poseidon2_packed_permutation_edge_values() {
        for rotation in 0..EDGE_VALS.len() {
            check_with(
                Poseidon2Permutation256::apply_permutation,
                |s| Poseidon2Permutation256.permute_mut(s),
                |i, lane| {
                    Felt::new_unchecked(EDGE_VALS[(i + 3 * lane + rotation) % EDGE_VALS.len()])
                },
            );
        }
    }

    #[test]
    fn poseidon2_packed_permutation_random_sweep() {
        let mut seed = 0x243f_6a88_85a3_08d3u64; // deterministic; digits of pi
        let mut next = move || {
            // splitmix64
            seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        for _ in 0..256 {
            let state: [[Felt; STATE_WIDTH]; LANES] = core::array::from_fn(|_| {
                core::array::from_fn(|_| Felt::new_unchecked(next() % Felt::ORDER))
            });
            check_with(
                Poseidon2Permutation256::apply_permutation,
                |s| Poseidon2Permutation256.permute_mut(s),
                |i, lane| state[lane][i],
            );
        }
    }
}
