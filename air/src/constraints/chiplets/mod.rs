use alloc::vec::Vec;

use super::super::{
    CHIPLETS_OFFSET, EvaluationFrame, Felt, FieldElement, TransitionConstraintDegree,
};
use crate::{
    Assertion, AuxRandElements, Word,
    trace::{CHIPLETS_BUS_AUX_TRACE_OFFSET, chiplets::kernel_rom::KERNEL_PROC_INIT_LABEL},
    utils::{are_equal, binary_not, is_binary},
};

mod bitwise;
mod hasher;
mod memory;

// CONSTANTS
// ================================================================================================
/// The number of constraints on the management of the Chiplets module. This does not include
/// constraints for the individual chiplet components.
pub const NUM_CONSTRAINTS: usize = 6;
/// The degrees of constraints on the management of the Chiplets module. This does not include
/// constraint degrees for the individual chiplet components.
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    2, 3, 4, // Selector flags must be binary.
    2, 3, 4, // Selector flags can only change from 0 -> 1.
];

// PERIODIC COLUMNS
// ================================================================================================

/// Returns the set of periodic columns required by chiplets in the Chiplets module.
pub fn get_periodic_column_values() -> Vec<Vec<Felt>> {
    let mut result = hasher::get_periodic_column_values();
    result.append(&mut bitwise::get_periodic_column_values());
    result
}

// CHIPLETS BOUNDARY CONSTRAINTS
// ================================================================================================

/// Adds chiplets' boundary assertions for auxiliary columns at the first step.
pub fn get_aux_assertions_first_step<E>(
    result: &mut Vec<Assertion<E>>,
    kernel_digests: &[Word],
    aux_rand_elements: &AuxRandElements<E>,
) where
    E: FieldElement<BaseField = Felt>,
{
    let reduced_kernel_digests = reduce_kernel_digests(kernel_digests, aux_rand_elements);
    result.push(Assertion::single(
        CHIPLETS_BUS_AUX_TRACE_OFFSET,
        0,
        reduced_kernel_digests.inv(),
    ));
}

// CHIPLETS TRANSITION CONSTRAINTS
// ================================================================================================

/// Builds the transition constraint degrees for the chiplets module and all chiplet components.
pub fn get_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    let mut degrees: Vec<TransitionConstraintDegree> = CONSTRAINT_DEGREES
        .iter()
        .map(|&degree| TransitionConstraintDegree::new(degree))
        .collect();

    degrees.append(&mut hasher::get_transition_constraint_degrees());

    degrees.append(&mut bitwise::get_transition_constraint_degrees());

    degrees.append(&mut memory::get_transition_constraint_degrees());

    degrees
}

/// Returns the number of transition constraints for the chiplets.
pub fn get_transition_constraint_count() -> usize {
    NUM_CONSTRAINTS
        + hasher::get_transition_constraint_count()
        + bitwise::get_transition_constraint_count()
        + memory::get_transition_constraint_count()
}

/// Enforces constraints for the chiplets module and all chiplet components.
pub fn enforce_constraints<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    periodic_values: &[E],
    result: &mut [E],
) {
    // chiplets transition constraints
    enforce_selectors(frame, result);
    let mut constraint_offset = NUM_CONSTRAINTS;

    // hasher transition constraints
    hasher::enforce_constraints(
        frame,
        &periodic_values[..hasher::NUM_PERIODIC_COLUMNS],
        &mut result[constraint_offset..],
        frame.hasher_flag(),
    );
    constraint_offset += hasher::get_transition_constraint_count();

    // bitwise transition constraints
    bitwise::enforce_constraints(
        frame,
        &periodic_values[hasher::NUM_PERIODIC_COLUMNS..],
        &mut result[constraint_offset..],
        frame.bitwise_flag(),
    );
    constraint_offset += bitwise::get_transition_constraint_count();

    // memory transition constraints
    memory::enforce_constraints(
        frame,
        &mut result[constraint_offset..],
        frame.memory_flag(),
        frame.memory_flag_not_last_row(),
        frame.memory_flag_first_row(),
    );
}

// TRANSITION CONSTRAINT HELPERS
// ================================================================================================

/// Constraint evaluation function to enforce that the Chiplets module's selector columns must be
/// binary during the portion of the trace when they're being used as selectors.
fn enforce_selectors<E: FieldElement>(frame: &EvaluationFrame<E>, result: &mut [E]) {
    // --- Selector flags must be binary ----------------------------------------------------------

    // Selector flag s0 must be binary for the entire trace.
    result[0] = is_binary(frame.s(0));

    // When s0 is set, selector s1 is binary.
    result[1] = frame.s(0) * is_binary(frame.s(1));

    // When selectors s0 and s1 are set, s2 is binary.
    result[2] = frame.s(0) * frame.s(1) * is_binary(frame.s(2));

    // --- Selector flags can only stay the same or change from 0 -> 1 ----------------------------

    // Selector flag s0 must either be 0 in the current row or 1 in both rows.
    result[3] = frame.s(0) * are_equal(frame.s(0), frame.s_next(0));

    // When s0 is set, selector flag s1 must either be 0 in the current row or 1 in both rows.
    result[4] = frame.s(0) * frame.s(1) * are_equal(frame.s(1), frame.s_next(1));

    // When selectors s0 and s1 are set, s2 must either be 0 in the current row or 1 in both rows.
    result[5] = frame.s(0) * frame.s(1) * frame.s(2) * are_equal(frame.s(2), frame.s_next(2));
}

// CHIPLETS FRAME EXTENSION TRAIT
// ================================================================================================

/// Trait to allow easy access to column values and intermediate variables used in constraint
/// calculations for the Chiplets module and its Hasher, Bitwise, and Memory chiplets.
trait EvaluationFrameExt<E: FieldElement> {
    // --- Column accessors -----------------------------------------------------------------------

    /// Returns the current value of the specified selector column. It assumes that the index is a
    /// valid selector index.
    fn s(&self, idx: usize) -> E;

    /// Returns the value of the specified selector column at the next row. It assumes that the
    /// index is a valid selector index.
    fn s_next(&self, idx: usize) -> E;

    // --- Chiplet selector flags -----------------------------------------------------------------

    /// Flag to indicate whether the frame is in the hasher portion of the Chiplets trace.
    fn hasher_flag(&self) -> E;

    /// Flag to indicate whether the frame is in the bitwise portion of the Chiplets trace.
    fn bitwise_flag(&self) -> E;

    /// Flag to indicate whether the current row of the frame is in the memory portion of the
    /// Chiplets trace.
    fn memory_flag(&self) -> E;

    /// Flag to indicate whether the current row of the frame is in the memory portion of the
    /// Chiplets trace, except for the last memory chiplet row.
    fn memory_flag_not_last_row(&self) -> E;

    /// Flag to indicate whether the next row of the frame is in the memory portion of the Chiplets
    /// trace.
    fn memory_flag_next(&self) -> E;

    /// Flag to indicate whether the next row of the frame is the first row of the memory portion of
    /// the Chiplets trace.
    fn memory_flag_first_row(&self) -> E;
}

impl<E: FieldElement> EvaluationFrameExt<E> for &EvaluationFrame<E> {
    // --- Column accessors -----------------------------------------------------------------------

    fn s(&self, idx: usize) -> E {
        self.current()[CHIPLETS_OFFSET + idx]
    }

    fn s_next(&self, idx: usize) -> E {
        self.next()[CHIPLETS_OFFSET + idx]
    }

    // --- Chiplet selector flags -----------------------------------------------------------------

    #[inline(always)]
    fn hasher_flag(&self) -> E {
        binary_not(self.s(0))
    }

    #[inline(always)]
    fn bitwise_flag(&self) -> E {
        self.s(0) * binary_not(self.s_next(1))
    }

    #[inline(always)]
    fn memory_flag(&self) -> E {
        self.s(0) * self.s(1) * binary_not(self.s(2))
    }

    #[inline(always)]
    fn memory_flag_not_last_row(&self) -> E {
        self.s(0) * self.s(1) * binary_not(self.s_next(2))
    }

    #[inline(always)]
    fn memory_flag_next(&self) -> E {
        self.s_next(0) * self.s_next(1) * binary_not(self.s_next(2))
    }

    #[inline(always)]
    fn memory_flag_first_row(&self) -> E {
        self.hasher_flag() * self.memory_flag_next()
    }
}

// EXTERNAL ACCESSORS
// ================================================================================================

/// Trait to allow other processors to easily access the chiplet values they need for constraint
/// calculations.
pub trait ChipletsFrameExt<E: FieldElement> {
    /// Flag to indicate whether the frame is in the memory chiplet.
    fn chiplets_memory_flag(&self) -> E;
}

impl<E: FieldElement> ChipletsFrameExt<E> for &EvaluationFrame<E> {
    #[inline(always)]
    fn chiplets_memory_flag(&self) -> E {
        self.memory_flag()
    }
}

// HELPERS
// ================================================================================================

/// Reduces kernel procedures digests using auxiliary randomness.
fn reduce_kernel_digests<E>(kernel_digests: &[Word], aux_rand_elements: &AuxRandElements<E>) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let alphas = aux_rand_elements.rand_elements();
    kernel_digests.iter().fold(E::ONE, |acc, digest: &Word| {
        let digest = digest.to_vec();
        let affine_term = alphas[0] + KERNEL_PROC_INIT_LABEL.into();
        let cur = alphas
            .iter()
            .skip(2)
            .zip(digest.iter())
            .map(|(alpha, coef)| alpha.mul_base(*coef))
            .fold(affine_term, |acc, term| acc + term);

        acc * cur
    })
}
