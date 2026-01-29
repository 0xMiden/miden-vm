//! TODO: add docs
use miden_crypto::{Word as Digest, field::PrimeCharacteristicRing};

use super::Felt;
pub use crate::crypto::hash::Poseidon2 as Hasher;

/// Number of field element needed to represent the sponge state for the hash function.
///
/// This value is set to 12: 8 elements are reserved for rate and the remaining 4 elements are
/// reserved for capacity. This configuration enables computation of 2-to-1 hash in a single
/// permutation.
pub const STATE_WIDTH: usize = Hasher::STATE_WIDTH;

/// Number of field elements in the rate portion of the hasher's state.
pub const RATE_LEN: usize = 8;

/// Number of "round steps" used by the hasher chiplet per permutation.
///
/// For Poseidon2, we model the permutation as 31 step transitions. This corresponds to an
/// initial external linear layer, 4 initial external (partial) rounds, 22 internal (full) rounds,
/// and 4 terminal external (partial) rounds:
/// - step 0: initial external linear layer
/// - steps 1..=4: initial external rounds
/// - steps 5..=26: internal rounds
/// - steps 27..=30: terminal external rounds
///
/// This yields a 32-row hasher cycle (input row + 31 steps).
pub const NUM_ROUNDS: usize = 31;

// PASS-THROUGH FUNCTIONS
// ================================================================================================

/// Returns a hash of two digests. This method is intended for use in construction of Merkle trees.
#[inline(always)]
pub fn merge(values: &[Digest; 2]) -> Digest {
    Hasher::merge(values)
}

/// Returns a hash of two digests with a specified domain.
#[inline(always)]
pub fn merge_in_domain(values: &[Digest; 2], domain: Felt) -> Digest {
    Hasher::merge_in_domain(values, domain)
}

/// Returns a hash of the provided list of field elements.
#[inline(always)]
pub fn hash_elements(elements: &[Felt]) -> Digest {
    Hasher::hash_elements(elements)
}

/// Applies a single Poseidon2 "step" to the provided state.
///
/// The step number must be specified via `round` parameter, which must be between 0 and 30
/// (both inclusive).
#[inline(always)]
pub fn apply_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
    apply_poseidon2_step(state, round)
}

/// Applies the Poseidon2 permutation to the provided state.
#[inline(always)]
pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
    Hasher::apply_permutation(state)
}

// POSEIDON2 STEP IMPLEMENTATION
// ================================================================================================

/// Applies a single Poseidon2 permutation step to the state.
///
/// The step number maps to the hasher chiplet trace rows:
/// - step 0: initial external linear layer
/// - steps 1..=4: initial external rounds
/// - steps 5..=26: internal rounds
/// - steps 27..=30: terminal external rounds
#[inline(always)]
fn apply_poseidon2_step(state: &mut [Felt; STATE_WIDTH], step: usize) {
    match step {
        0 => {
            // Initial external linear layer.
            Hasher::apply_matmul_external(state);
        },
        1..=4 => {
            // Initial external partial rounds.
            Hasher::add_rc(state, &Hasher::ARK_EXT_INITIAL[step - 1]);
            Hasher::apply_sbox(state);
            Hasher::apply_matmul_external(state);
        },
        5..=26 => {
            // Internal full rounds.
            state[0] += Hasher::ARK_INT[step - 5];
            state[0] = state[0].exp_const_u64::<7>();
            Hasher::matmul_internal(state, Hasher::MAT_DIAG);
        },
        27..=30 => {
            // Terminal external partial rounds.
            Hasher::add_rc(state, &Hasher::ARK_EXT_TERMINAL[step - 27]);
            Hasher::apply_sbox(state);
            Hasher::apply_matmul_external(state);
        },
        _ => panic!("invalid poseidon2 step {step}, expected 0..30"),
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that applying all 31 steps produces the same result as `apply_permutation`.
    #[test]
    fn apply_round_matches_permutation() {
        // Test with zeros
        let mut state_stepwise = [Felt::ZERO; STATE_WIDTH];
        let mut state_permutation = [Felt::ZERO; STATE_WIDTH];

        for i in 0..NUM_ROUNDS {
            apply_round(&mut state_stepwise, i);
        }
        apply_permutation(&mut state_permutation);

        assert_eq!(state_stepwise, state_permutation, "mismatch with zero state");

        // Test with sequential values
        let mut state_stepwise: [Felt; STATE_WIDTH] = core::array::from_fn(|i| Felt::new(i as u64));
        let mut state_permutation = state_stepwise;

        for i in 0..NUM_ROUNDS {
            apply_round(&mut state_stepwise, i);
        }
        apply_permutation(&mut state_permutation);

        assert_eq!(state_stepwise, state_permutation, "mismatch with sequential state");

        // Test with arbitrary values
        let mut state_stepwise: [Felt; STATE_WIDTH] = [
            Felt::new(0x123456789abcdef0_u64),
            Felt::new(0xfedcba9876543210_u64),
            Felt::new(0x0011223344556677_u64),
            Felt::new(0x8899aabbccddeeff_u64),
            Felt::new(0xdeadbeefcafebabe_u64),
            Felt::new(0x1234567890abcdef_u64),
            Felt::new(0x1234567890abcdef_u64),
            Felt::new(0x0badc0debadf00d0_u64),
            Felt::new(0x1111111111111111_u64),
            Felt::new(0x2222222222222222_u64),
            Felt::new(0x3333333333333333_u64),
            Felt::new(0x4444444444444444_u64),
        ];
        let mut state_permutation = state_stepwise;

        for i in 0..NUM_ROUNDS {
            apply_round(&mut state_stepwise, i);
        }
        apply_permutation(&mut state_permutation);

        assert_eq!(state_stepwise, state_permutation, "mismatch with random state");
    }

    /// Verifies that intermediate steps are computed correctly by checking that two
    /// half-permutations produce the same result as a full permutation.
    #[test]
    fn apply_round_intermediate_states() {
        let init_state: [Felt; STATE_WIDTH] = core::array::from_fn(|i| Felt::new((i + 1) as u64));

        // Apply first half of rounds
        let mut state_half1 = init_state;
        for i in 0..15 {
            apply_round(&mut state_half1, i);
        }

        // Apply second half of rounds
        let mut state_half2 = state_half1;
        for i in 15..NUM_ROUNDS {
            apply_round(&mut state_half2, i);
        }

        // Compare with full permutation
        let mut state_full = init_state;
        apply_permutation(&mut state_full);

        assert_eq!(state_half2, state_full, "split application doesn't match full permutation");
    }
}
