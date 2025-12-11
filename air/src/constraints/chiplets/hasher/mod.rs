use alloc::vec::Vec;

use super::{EvaluationFrame, Felt, FieldElement, TransitionConstraintDegree};
use crate::{
    ONE, ZERO,
    trace::chiplets::{
        HASHER_NODE_INDEX_COL_IDX, HASHER_SELECTOR_COL_RANGE, HASHER_STATE_COL_RANGE,
        hasher::{
            CAPACITY_LEN, DIGEST_LEN, DIGEST_RANGE, HASH_CYCLE_LEN, Hasher, NUM_SELECTORS,
            STATE_WIDTH,
        },
    },
    utils::{EvaluationResult, are_equal, binary_not, is_binary},
};

#[cfg(test)]
mod tests;

// CONSTANTs
// ================================================================================================
/// The number of constraints on the management of the hash chiplet.
pub const NUM_CONSTRAINTS: usize = 30;

/// The number of periodic columns which are used as selectors to specify a particular row or rows
/// within the hash cycle.
pub const NUM_PERIODIC_SELECTOR_COLUMNS: usize = 3;
/// The total number of periodic columns used by the hasher chiplet, which is the sum of the number
/// of periodic selector columns plus the columns of round constants for the Rescue Prime Optimized
/// hash permutation.
pub const NUM_PERIODIC_COLUMNS: usize = STATE_WIDTH * 2 + NUM_PERIODIC_SELECTOR_COLUMNS;

// PERIODIC COLUMNS
// ================================================================================================

/// Returns the set of periodic columns required by the hasher chiplet.
///
/// The columns consist of:
/// - k0 column, which has a repeating pattern of 7 zeros followed by a single one.
/// - k1 column, which has a repeating pattern of 6 zeros, a single 1, and a final zero.
/// - k2 column, which has a repeating pattern of a single one followed by 7 zeros.
/// - the round constants for the Rescue Prime Optimized permutation.
pub fn get_periodic_column_values() -> Vec<Vec<Felt>> {
    let mut result = vec![HASH_K0_MASK.to_vec(), HASH_K1_MASK.to_vec(), HASH_K2_MASK.to_vec()];
    result.append(&mut get_round_constants());
    result
}

// HASH CHIPLET TRANSITION CONSTRAINTS
// ================================================================================================

/// Builds the transition constraint degrees for the hash chiplet.
pub fn get_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    let degrees: [TransitionConstraintDegree; NUM_CONSTRAINTS] = [
        // Ensure selector columns are binary.
        TransitionConstraintDegree::new(3),
        TransitionConstraintDegree::new(3),
        TransitionConstraintDegree::new(3),
        // Enforce the selector values depending on the value of f_out.
        TransitionConstraintDegree::with_cycles(6, vec![HASH_CYCLE_LEN; 2]),
        TransitionConstraintDegree::with_cycles(6, vec![HASH_CYCLE_LEN; 2]),
        TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
        // Enforce all flag combinations are valid.
        TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
        // Enforce the node index is set properly at the start and end of computations and when
        // absorbing a new node.
        TransitionConstraintDegree::with_cycles(4, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(6, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
        // Apply RPO rounds.
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(8, vec![HASH_CYCLE_LEN]),
        // When the absorption flag is set, copy the capacity portion to the next row.
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
        // Enforce correct node absorption during Merkle path computation.
        TransitionConstraintDegree::with_cycles(6, vec![HASH_CYCLE_LEN; 2]),
        TransitionConstraintDegree::with_cycles(6, vec![HASH_CYCLE_LEN; 2]),
        TransitionConstraintDegree::with_cycles(6, vec![HASH_CYCLE_LEN; 2]),
        TransitionConstraintDegree::with_cycles(6, vec![HASH_CYCLE_LEN; 2]),
    ];

    degrees.into()
}

/// Returns the number of transition constraints for the hash chiplet.
pub fn get_transition_constraint_count() -> usize {
    NUM_CONSTRAINTS
}

/// Enforces constraints for the hasher chiplet.
///
/// - The `hasher_flag` determines if the hasher chiplet is currently enabled. It should be computed
///   by the caller and set to `Felt::ONE`
/// - The `transition_flag` indicates whether this is the last row this chiplet's execution trace,
///   and therefore the constraints should not be enforced.
pub fn enforce_constraints<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    periodic_values: &[E],
    result: &mut [E],
    hasher_flag: E,
) {
    let mut index = 0;
    index += enforce_hasher_selectors(frame, periodic_values, &mut result[index..], hasher_flag);

    index += enforce_node_index(frame, periodic_values, &mut result[index..], hasher_flag);

    enforce_hasher_state(frame, periodic_values, &mut result[index..], hasher_flag);
}

// TRANSITION CONSTRAINT HELPERS
// ================================================================================================

/// Enforces validity of the internal selectors of the hasher chiplet.
///
/// - All selectors must contain binary values.
/// - s1 and s2 must be copied to the next row unless f_out is set in the current or next row.
/// - When a cycle ends by absorbing more elements or a Merkle path node, ensure the next value of
///   s0 is always zero. Otherwise, s0 should be unconstrained.
/// - Prevent an invalid combination of flags where s_0 = 0 and s_1 = 1.
fn enforce_hasher_selectors<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    periodic_values: &[E],
    result: &mut [E],
    hasher_flag: E,
) -> usize {
    // Ensure the selectors are all binary values.
    for (idx, result) in result.iter_mut().take(NUM_SELECTORS).enumerate() {
        *result = hasher_flag * is_binary(frame.s(idx));
    }
    let mut constraint_offset = NUM_SELECTORS;

    // Ensure the values in s1 and s2 in the current row are copied to the next row when f_out != 1
    // and f_out' != 1.
    let copy_selectors_flag = hasher_flag
        * binary_not(frame.f_out(periodic_values))
        * binary_not(frame.f_out_next(periodic_values));
    result[constraint_offset] = copy_selectors_flag * (frame.s_next(1) - frame.s(1));
    constraint_offset += 1;

    result[constraint_offset] = copy_selectors_flag * (frame.s_next(2) - frame.s(2));
    constraint_offset += 1;

    // s0 should be unconstrained except in the last row of the cycle if any of f_abp, f_mpa, f_mva,
    // or f_mua are 1, in which case the next value of s0 must be zero.
    result[constraint_offset] = hasher_flag
        * periodic_values[0]
        * frame.s_next(0)
        * (frame.f_abp() + frame.f_mpa() + frame.f_mva() + frame.f_mua());
    constraint_offset += 1;

    // Prevent an invalid combinations of flags.
    result[constraint_offset] =
        hasher_flag * periodic_values[0] * binary_not(frame.s(0)) * frame.s(1);
    constraint_offset += 1;

    constraint_offset
}

/// Enforces that the node index value is always set correctly. It is only needed during Merkle path
/// verification and root update computations, but constraints are enforced in all cases for
/// simplicity.
///
/// The constraints enforce the following:
/// - Ensure `i` is zero at the end of the computation.
/// - Ensure `i` is shifted one bit to the right when a new node is absorbed into the hasher state.
/// - Otherwise, ensure the value of `i` is copied to the next row.
fn enforce_node_index<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    periodic_values: &[E],
    result: &mut [E],
    hasher_flag: E,
) -> usize {
    let mut constraint_offset = 0;

    // Enforce that the node index is 0 when a computation is finished.
    result[constraint_offset] = hasher_flag * frame.f_out(periodic_values) * frame.i();
    constraint_offset += 1;

    // When a new node is being absorbed into the hasher state, ensure that the shift to the right
    // was performed correctly by enforcing that the discarded bit is a binary value.
    result[constraint_offset] = hasher_flag * frame.f_an(periodic_values) * is_binary(frame.b());
    constraint_offset += 1;

    // When we are not absorbing a new row and the computation is not finished, make sure the value
    // of i is copied to the next row.
    result[constraint_offset] = hasher_flag
        * (E::ONE - frame.f_an(periodic_values) - frame.f_out(periodic_values))
        * (frame.i_next() - frame.i());
    constraint_offset += 1;

    constraint_offset
}

/// Enforces constraints on the correct update of the hasher state. For all rounds in the cycle
/// except the last, the constraints for the RPO round computation are applied.
///
/// For the last row in the cycle, the hash state update depends on the selector flags as follows.
/// - When absorbing a new set of elements during linear hash computation, the capacity portion is
///   copied to the next row.
/// - When absorbing a new node during Merkle path computation, the result of the previous hash (the
///   digest) is copied to the next row in the position specified by the bit shifted out of the node
///   index.
fn enforce_hasher_state<E: FieldElement + From<Felt>>(
    frame: &EvaluationFrame<E>,
    periodic_values: &[E],
    result: &mut [E],
    hasher_flag: E,
) -> usize {
    let mut constraint_offset = 0;

    // Get the constraint flags and the RPO round constants from the periodic values.
    let hash_flag = hasher_flag * binary_not(periodic_values[0]);
    let last_row = hasher_flag * periodic_values[0];
    let ark = &periodic_values[NUM_PERIODIC_SELECTOR_COLUMNS..];

    // Enforce the RPO round constraints.
    enforce_rpo_round(frame, result, ark, hash_flag);
    constraint_offset += STATE_WIDTH;

    // When absorbing the next set of elements into the state during linear hash computation,
    // the first 4 elements (the capacity portion) is carried over to the next row.
    let hash_abp_flag = last_row * frame.f_abp();
    for (idx, result) in result[constraint_offset..].iter_mut().take(CAPACITY_LEN).enumerate() {
        *result = hash_abp_flag * (frame.h_next(idx) - frame.h(idx))
    }
    constraint_offset += CAPACITY_LEN;

    // When absorbing the next node during Merkle path computation, the result of the previous
    // hash (h4,...,h7) is copied over either to (h′4,...,h′7) or to (h′8,...,h′11) depending
    // on the value of b.
    let mp_abp_flag = last_row
        * (frame.f_mp(periodic_values) + frame.f_mv(periodic_values) + frame.f_mu(periodic_values));
    for (idx, result) in result[constraint_offset..].iter_mut().take(DIGEST_LEN).enumerate() {
        let digest_idx = DIGEST_RANGE.start + idx;
        let h_copy_down = frame.h_next(digest_idx) - frame.h(digest_idx);
        let h_copy_over = frame.h_next(DIGEST_LEN + digest_idx) - frame.h(digest_idx);

        *result = mp_abp_flag * (binary_not(frame.b()) * h_copy_down + frame.b() * h_copy_over);
    }
    constraint_offset += DIGEST_LEN;

    constraint_offset
}

/// Enforces constraints for a single round of the Rescue Prime Optimized hash functions when
/// flag = 1 using the provided round constants.
pub fn enforce_rpo_round<E: FieldElement + From<Felt>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    ark: &[E],
    flag: E,
) {
    // compute the state that should result from applying the first 5 operations of the RPO round to
    // the current hash state.
    let mut step1 = [E::ZERO; STATE_WIDTH];
    step1.copy_from_slice(frame.hash_state());
    apply_mds(&mut step1);
    // add constants
    for i in 0..STATE_WIDTH {
        step1[i] += ark[i];
    }
    apply_sbox(&mut step1);
    apply_mds(&mut step1);
    // add constants
    for i in 0..STATE_WIDTH {
        step1[i] += ark[STATE_WIDTH + i];
    }

    // compute the state that should result from applying the inverse of the last operation of the
    // RPO round to the next step of the computation.
    let mut step2 = [E::ZERO; STATE_WIDTH];
    step2.copy_from_slice(frame.hash_state_next());
    apply_sbox(&mut step2);

    // make sure that the results are equal.
    for i in 0..STATE_WIDTH {
        result.agg_constraint(i, flag, are_equal(step2[i], step1[i]));
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
fn apply_sbox<E: FieldElement + From<Felt>>(state: &mut [E; STATE_WIDTH]) {
    state.iter_mut().for_each(|v| {
        let t2 = v.square();
        let t4 = t2.square();
        *v *= t2 * t4;
    });
}

#[inline(always)]
fn apply_mds<E: FieldElement + From<Felt>>(state: &mut [E; STATE_WIDTH]) {
    let mut result = [E::ZERO; STATE_WIDTH];
    result.iter_mut().zip(Hasher::MDS).for_each(|(r, mds_row)| {
        state.iter().zip(mds_row).for_each(|(&s, m)| {
            *r += E::from(m) * s;
        });
    });
    *state = result
}

// HASHER FRAME EXTENSION TRAIT
// ================================================================================================

/// Trait to allow easy access to column values and intermediate variables used in constraint
/// calculations for the hash chiplet.
trait EvaluationFrameExt<E: FieldElement> {
    // --- Column accessors -----------------------------------------------------------------------

    /// Gets the value of the selector column at the specified index in the current row.
    fn s(&self, idx: usize) -> E;
    /// Gets the value of the selector column at the specified index in the next row.
    fn s_next(&self, idx: usize) -> E;
    /// Gets the full hasher state in the current row.
    fn hash_state(&self) -> &[E];
    /// Gets the full hasher state in the next row.
    fn hash_state_next(&self) -> &[E];
    /// Gets the value of the specified index of the hasher state in the current row.
    fn h(&self, idx: usize) -> E;
    /// Gets the value of the specified index of the hasher state in the next row.
    fn h_next(&self, idx: usize) -> E;
    /// Gets the value of the node index in the current row.
    fn i(&self) -> E;
    /// Gets the value of the node index in the next row.
    fn i_next(&self) -> E;

    // --- Intermediate variables & helpers -------------------------------------------------------

    /// The value of the bit which is discarded when the node index is shifted by one bit to the
    /// right.
    fn b(&self) -> E;

    // --- Flags ----------------------------------------------------------------------------------

    /// Set to 1 on the first 7 steps of every 8-step cycle. This flag is degree 1.
    #[expect(dead_code)]
    fn f_rpr(&self, k: &[E]) -> E;
    /// Set to 1 when selector flags are (1,0,0) on rows which are multiples of 8. This flag is
    /// degree 4.
    #[expect(dead_code)]
    fn f_bp(&self, k: &[E]) -> E;
    /// Set to 1 when selector flags are (1,0,1) on rows which are multiples of 8. This flag is
    /// degree 4.
    fn f_mp(&self, k: &[E]) -> E;
    /// Set to 1 when selector flags are (1,1,0) on rows which are multiples of 8. This flag is
    /// degree 4.
    fn f_mv(&self, k: &[E]) -> E;
    /// Set to 1 when selector flags are (1,1,1) on rows which are multiples of 8. This flag is
    /// degree 4.
    fn f_mu(&self, k: &[E]) -> E;
    /// Set to 1 when selector flags are (0,0,0) on rows which are 1 less than a multiple of 8. This
    /// flag is degree 4.
    #[expect(dead_code)]
    fn f_hout(&self, k: &[E]) -> E;
    /// Set to 1 when selector flags are (0,0,1) on rows which are 1 less than a multiple of 8. This
    /// flag is degree 4.
    #[expect(dead_code)]
    fn f_sout(&self, k: &[E]) -> E;
    /// This flag will be set to 1 when either f_hout=1 or f_sout=1 in the current row. This flag is
    /// degree 3.
    fn f_out(&self, k: &[E]) -> E;
    /// This flag will be set to 1 when either f_hout=1 or f_sout=1 in the next row. This flag is
    /// degree 3.
    fn f_out_next(&self, k: &[E]) -> E;
    /// Set to 1 when selector flags are (1,0,0). It should only be used on rows which are 1 less
    /// than a multiple of 8 (where k0 = 1). `k0` has been excluded from the flag computation for
    /// optimization purposes. This flag is degree 4 when combined with k0.
    fn f_abp(&self) -> E;
    /// Set to 1 when selector flags are (1,0,1). It should only be used on rows which are 1 less
    /// than a multiple of 8 (where k0 = 1). `k0` has been excluded from the flag computation for
    /// optimization purposes. This flag is degree 4 when combined with k0.
    fn f_mpa(&self) -> E;
    /// Set to 1 when selector flags are (1,1,0). It should only be used on rows which are 1 less
    /// than a multiple of 8 (where k0 = 1). `k0` has been excluded from the flag computation for
    /// optimization purposes. This flag is degree 4 when combined with k0.
    fn f_mva(&self) -> E;
    /// Set to 1 when selector flags are (1,1,1). It should only be used on rows which are 1 less
    /// than a multiple of 8 (where k0 = 1). `k0` has been excluded from the flag computation for
    /// optimization purposes. This flag is degree 4 when combined with k0.
    fn f_mua(&self) -> E;
    /// Gets a flag indicating that a new node is absorbed into the hasher state. This flag is
    /// degree 4.
    fn f_an(&self, k: &[E]) -> E;
}

impl<E: FieldElement> EvaluationFrameExt<E> for &EvaluationFrame<E> {
    // --- Column accessors -----------------------------------------------------------------------

    #[inline(always)]
    fn s(&self, idx: usize) -> E {
        self.current()[HASHER_SELECTOR_COL_RANGE.start + idx]
    }

    #[inline(always)]
    fn s_next(&self, idx: usize) -> E {
        self.next()[HASHER_SELECTOR_COL_RANGE.start + idx]
    }

    #[inline(always)]
    fn hash_state(&self) -> &[E] {
        &self.current()[HASHER_STATE_COL_RANGE]
    }

    #[inline(always)]
    fn hash_state_next(&self) -> &[E] {
        &self.next()[HASHER_STATE_COL_RANGE]
    }

    #[inline(always)]
    fn h(&self, idx: usize) -> E {
        self.current()[HASHER_STATE_COL_RANGE.start + idx]
    }

    #[inline(always)]
    fn h_next(&self, idx: usize) -> E {
        self.next()[HASHER_STATE_COL_RANGE.start + idx]
    }

    #[inline(always)]
    fn i(&self) -> E {
        self.current()[HASHER_NODE_INDEX_COL_IDX]
    }

    #[inline(always)]
    fn i_next(&self) -> E {
        self.next()[HASHER_NODE_INDEX_COL_IDX]
    }

    // --- Intermediate variables & helpers -------------------------------------------------------

    #[inline(always)]
    fn b(&self) -> E {
        self.i() - E::from(2_u8) * self.i_next()
    }

    // --- Flags ----------------------------------------------------------------------------------

    #[inline(always)]
    fn f_rpr(&self, k: &[E]) -> E {
        binary_not(k[0])
    }

    #[inline(always)]
    fn f_bp(&self, k: &[E]) -> E {
        k[2] * self.s(0) * binary_not(self.s(1)) * binary_not(self.s(2))
    }

    #[inline(always)]
    fn f_mp(&self, k: &[E]) -> E {
        k[2] * self.s(0) * binary_not(self.s(1)) * self.s(2)
    }

    #[inline(always)]
    fn f_mv(&self, k: &[E]) -> E {
        k[2] * self.s(0) * self.s(1) * binary_not(self.s(2))
    }

    #[inline(always)]
    fn f_mu(&self, k: &[E]) -> E {
        k[2] * self.s(0) * self.s(1) * self.s(2)
    }

    #[inline(always)]
    fn f_hout(&self, k: &[E]) -> E {
        k[0] * binary_not(self.s(0)) * binary_not(self.s(1)) * binary_not(self.s(2))
    }

    #[inline(always)]
    fn f_sout(&self, k: &[E]) -> E {
        k[0] * binary_not(self.s(0)) * binary_not(self.s(1)) * self.s(2)
    }

    #[inline(always)]
    fn f_out(&self, k: &[E]) -> E {
        k[0] * binary_not(self.s(0)) * binary_not(self.s(1))
    }

    #[inline(always)]
    fn f_out_next(&self, k: &[E]) -> E {
        k[1] * binary_not(self.s_next(0)) * binary_not(self.s_next(1))
    }

    #[inline(always)]
    fn f_abp(&self) -> E {
        self.s(0) * binary_not(self.s(1)) * binary_not(self.s(2))
    }

    #[inline(always)]
    fn f_mpa(&self) -> E {
        self.s(0) * binary_not(self.s(1)) * self.s(2)
    }

    #[inline(always)]
    fn f_mva(&self) -> E {
        self.s(0) * self.s(1) * binary_not(self.s(2))
    }

    #[inline(always)]
    fn f_mua(&self) -> E {
        self.s(0) * self.s(1) * self.s(2)
    }

    #[inline(always)]
    fn f_an(&self, k: &[E]) -> E {
        self.f_mp(k)
            + self.f_mv(k)
            + self.f_mu(k)
            + k[0] * (self.f_mpa() + self.f_mva() + self.f_mua())
    }
}

// CYCLE MASKS
// ================================================================================================

/// Periodic column mask used to indicate the last row of a cycle.
pub const HASH_K0_MASK: [Felt; HASH_CYCLE_LEN] = [ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ONE];

/// Periodic column mask used to indicate when the next row will be the last row of a cycle.
pub const HASH_K1_MASK: [Felt; HASH_CYCLE_LEN] = [ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ONE, ZERO];

/// Periodic column mask used to identify the first row of a cycle.
pub const HASH_K2_MASK: [Felt; HASH_CYCLE_LEN] = [ONE, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];

// ROUND CONSTANTS
// ================================================================================================

/// Returns RPO round constants arranged in column-major form.
pub fn get_round_constants() -> Vec<Vec<Felt>> {
    let mut constants = Vec::new();
    for _ in 0..(STATE_WIDTH * 2) {
        constants.push(vec![ZERO; HASH_CYCLE_LEN]);
    }

    #[expect(clippy::needless_range_loop)]
    for i in 0..HASH_CYCLE_LEN - 1 {
        for j in 0..STATE_WIDTH {
            constants[j][i] = Hasher::ARK1[i][j];
            constants[j + STATE_WIDTH][i] = Hasher::ARK2[i][j];
        }
    }

    constants
}
