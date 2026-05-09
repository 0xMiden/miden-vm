//! Low-level Poseidon2 hasher functions and constants.
//!
//! This module provides core hashing primitives for the Poseidon2 hash function, including:
//! - Constants defining the hasher state layout (STATE_WIDTH, RATE_LEN, NUM_ROUNDS)
//! - Pass-through functions for common hash operations (merge, hash_elements)
//! - Step-by-step permutation functions for fine-grained control (apply_round, apply_permutation)
//!
//! This module serves as a thin wrapper around `miden_crypto::hash::Poseidon2`, providing
//! a consistent interface for the Miden VM's hashing needs. For higher-level hasher chiplet
//! functionality, see the trace and processor modules.

use miden_crypto::Word as Digest;

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

/// Number of Poseidon2 step transitions used by the hasher reference schedule.
///
/// For Poseidon2, we model the permutation as 31 step transitions. This corresponds to an
/// initial external linear layer, 4 initial external rounds, 22 internal rounds, and 4 terminal
/// external rounds:
/// - step 0: initial external linear layer
/// - steps 1..=4: initial external rounds
/// - steps 5..=26: internal rounds
/// - steps 27..=30: terminal external rounds
///
/// The hasher chiplet packs this 31-step schedule into a 16-row permutation cycle, but the
/// stepwise reference API keeps the original 31-step numbering because it is convenient for tests
/// and cross-checking against the uncompressed permutation schedule.
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
        let mut state_stepwise: [Felt; STATE_WIDTH] =
            core::array::from_fn(|i| Felt::new_unchecked(i as u64));
        let mut state_permutation = state_stepwise;

        for i in 0..NUM_ROUNDS {
            apply_round(&mut state_stepwise, i);
        }
        apply_permutation(&mut state_permutation);

        assert_eq!(state_stepwise, state_permutation, "mismatch with sequential state");

        // Test with arbitrary values
        let mut state_stepwise: [Felt; STATE_WIDTH] = [
            Felt::new_unchecked(0x123456789abcdef0_u64),
            Felt::new_unchecked(0xfedcba9876543210_u64),
            Felt::new_unchecked(0x0011223344556677_u64),
            Felt::new_unchecked(0x8899aabbccddeeff_u64),
            Felt::new_unchecked(0xdeadbeefcafebabe_u64),
            Felt::new_unchecked(0x1234567890abcdef_u64),
            Felt::new_unchecked(0x1234567890abcdef_u64),
            Felt::new_unchecked(0x0badc0debadf00d0_u64),
            Felt::new_unchecked(0x1111111111111111_u64),
            Felt::new_unchecked(0x2222222222222222_u64),
            Felt::new_unchecked(0x3333333333333333_u64),
            Felt::new_unchecked(0x4444444444444444_u64),
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
        let init_state: [Felt; STATE_WIDTH] =
            core::array::from_fn(|i| Felt::new_unchecked((i + 1) as u64));

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

    /// Verifies that the 16-row packed permutation schedule produces the same result
    /// as the reference `apply_permutation`.
    ///
    /// The packed schedule:
    /// - init + ext1 (merged)
    /// - ext2, ext3, ext4
    /// - 7 x (3 packed internal rounds)
    /// - int22 + ext5 (merged)
    /// - ext6, ext7, ext8
    #[test]
    fn packed_16row_matches_permutation() {
        let test_states: [_; 3] = [
            [Felt::ZERO; STATE_WIDTH],
            core::array::from_fn(|i| Felt::new_unchecked(i as u64)),
            [
                Felt::new_unchecked(0x123456789abcdef0),
                Felt::new_unchecked(0xfedcba9876543210),
                Felt::new_unchecked(0x0011223344556677),
                Felt::new_unchecked(0x8899aabbccddeeff),
                Felt::new_unchecked(0xdeadbeefcafebabe),
                Felt::new_unchecked(0x1234567890abcdef),
                Felt::new_unchecked(0x1234567890abcdef),
                Felt::new_unchecked(0x0badc0debadf00d0),
                Felt::new_unchecked(0x1111111111111111),
                Felt::new_unchecked(0x2222222222222222),
                Felt::new_unchecked(0x3333333333333333),
                Felt::new_unchecked(0x4444444444444444),
            ],
        ];

        for (idx, init_state) in test_states.iter().enumerate() {
            let mut state = *init_state;

            // Init + ext1 (merged)
            Hasher::apply_matmul_external(&mut state);
            Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[0]);
            Hasher::apply_sbox(&mut state);
            Hasher::apply_matmul_external(&mut state);

            // Ext2, ext3, ext4
            for r in 1..=3 {
                Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[r]);
                Hasher::apply_sbox(&mut state);
                Hasher::apply_matmul_external(&mut state);
            }

            // 7 x (3 packed internal rounds)
            for triple in 0..7_usize {
                let base = triple * 3;
                for k in 0..3 {
                    state[0] += Hasher::ARK_INT[base + k];
                    state[0] = state[0].exp_const_u64::<7>();
                    Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
                }
            }

            // Int22 + ext5 (merged)
            state[0] += Hasher::ARK_INT[21];
            state[0] = state[0].exp_const_u64::<7>();
            Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
            Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[0]);
            Hasher::apply_sbox(&mut state);
            Hasher::apply_matmul_external(&mut state);

            // Ext6, ext7, ext8
            for r in 1..=3 {
                Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[r]);
                Hasher::apply_sbox(&mut state);
                Hasher::apply_matmul_external(&mut state);
            }

            // Compare with reference
            let mut reference = *init_state;
            apply_permutation(&mut reference);

            assert_eq!(state, reference, "packed schedule mismatch for test state {idx}");
        }
    }
}
