use alloc::vec::Vec;

use miden_core::{ExtensionOf, ZERO};

use crate::{
    Assertion, EvaluationFrame, Felt, FieldElement, TransitionConstraintDegree,
    chiplets::ChipletsFrameExt,
    constraints::MainFrameExt,
    trace::range::{B_RANGE_COL_IDX, M_COL_IDX, V_COL_IDX},
    utils::are_equal,
};

// CONSTANTS
// ================================================================================================

// --- Main constraints ---------------------------------------------------------------------------

/// The number of boundary constraints required by the Range Checker
pub const NUM_ASSERTIONS: usize = 2;
/// The number of transition constraints required by the Range Checker.
pub const NUM_CONSTRAINTS: usize = 1;
/// The degrees of the range checker's constraints, in the order they'll be added to the the result
/// array when a transition is evaluated.
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    9, // Enforce values of column v transition.
];

// --- Auxiliary column constraints for multiset checks -------------------------------------------

/// The number of auxiliary assertions for multiset checks.
pub const NUM_AUX_ASSERTIONS: usize = 2;
/// The number of transition constraints required by multiset checks for the Range Checker.
pub const NUM_AUX_CONSTRAINTS: usize = 1;
/// The degrees of the Range Checker's auxiliary column constraints, used for multiset checks.
pub const AUX_CONSTRAINT_DEGREES: [usize; NUM_AUX_CONSTRAINTS] = [9];

// BOUNDARY CONSTRAINTS
// ================================================================================================

// --- MAIN TRACE ---------------------------------------------------------------------------------

/// Returns the range checker's boundary assertions for the main trace at the first step.
pub fn get_assertions_first_step(result: &mut Vec<Assertion<Felt>>) {
    let step = 0;
    result.push(Assertion::single(V_COL_IDX, step, ZERO));
}

/// Returns the range checker's boundary assertions for the main trace at the last step.
pub fn get_assertions_last_step(result: &mut Vec<Assertion<Felt>>, step: usize) {
    result.push(Assertion::single(V_COL_IDX, step, Felt::new(65535)));
}

// --- AUXILIARY COLUMNS (FOR LOGUP) --------------------------------------------------------------

/// Returns the range checker's boundary assertions for auxiliary columns at the first step.
pub fn get_aux_assertions_first_step<E: FieldElement>(result: &mut Vec<Assertion<E>>) {
    let step = 0;
    result.push(Assertion::single(B_RANGE_COL_IDX, step, E::ZERO));
}

/// Returns the range checker's boundary assertions for auxiliary columns at the last step.
pub fn get_aux_assertions_last_step<E: FieldElement>(result: &mut Vec<Assertion<E>>, step: usize) {
    result.push(Assertion::single(B_RANGE_COL_IDX, step, E::ZERO));
}

// TRANSITION CONSTRAINTS
// ================================================================================================

// --- MAIN TRACE ---------------------------------------------------------------------------------

/// Builds the transition constraint degrees for the range checker.
pub fn get_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    CONSTRAINT_DEGREES
        .iter()
        .map(|&degree| TransitionConstraintDegree::new(degree))
        .collect()
}

/// Returns the number of transition constraints for the range checker.
pub fn get_transition_constraint_count() -> usize {
    NUM_CONSTRAINTS
}

/// Enforces constraints for the range checker.
pub fn enforce_constraints<E: FieldElement>(frame: &EvaluationFrame<E>, result: &mut [E]) {
    // Constrain the transition of the value column between rows in the range checker table.
    result[0] = frame.change(V_COL_IDX)
        * (frame.change(V_COL_IDX) - E::ONE)
        * (frame.change(V_COL_IDX) - E::from(3_u8))
        * (frame.change(V_COL_IDX) - E::from(9_u8))
        * (frame.change(V_COL_IDX) - E::from(27_u8))
        * (frame.change(V_COL_IDX) - E::from(81_u8))
        * (frame.change(V_COL_IDX) - E::from(243_u8))
        * (frame.change(V_COL_IDX) - E::from(729_u16))
        * (frame.change(V_COL_IDX) - E::from(2187_u16));
}

// --- AUXILIARY COLUMNS (FOR MULTISET CHECKS) ----------------------------------------------------

/// Returns the transition constraint degrees for the range checker's auxiliary columns, used for
/// multiset checks.
pub fn get_aux_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    AUX_CONSTRAINT_DEGREES
        .iter()
        .map(|&degree| TransitionConstraintDegree::new(degree))
        .collect()
}

/// Enforces constraints on the range checker's auxiliary columns.
pub fn enforce_aux_constraints<F, E>(
    main_frame: &EvaluationFrame<F>,
    aux_frame: &EvaluationFrame<E>,
    aux_rand_elements: &[E],
    result: &mut [E],
) where
    F: FieldElement<BaseField = Felt>,
    E: FieldElement<BaseField = Felt> + ExtensionOf<F>,
{
    // Get the first random element for this segment.
    let alpha = aux_rand_elements[0];

    // Enforce b_range.
    enforce_b_range(main_frame, aux_frame, alpha, result);
}

// TRANSITION CONSTRAINT HELPERS
// ================================================================================================

// --- AUXILIARY COLUMNS (FOR MULTISET CHECKS) ----------------------------------------------------

/// Ensures that the range checker bus is computed correctly. It enforces an implementation of the
/// LogUp lookup as a running sum "bus" column. All values in the range checker trace are saved
/// with their lookup multiplicity and the logarithmic derivatives are added to b_range. Values
/// for which lookups are requested from the stack and memory are each looked up with multiplicity
/// one, and the logarithmic derivatives are subtracted from b_range.
///
/// Define the following variables:
/// - rc_value: the range checker value
/// - rc_multiplicity: the range checker multiplicity value
/// - flag_s: boolean flag indicating a stack operation with range checks. This flag is degree 3.
/// - sv0-sv3: stack value 0-3, the 4 values range-checked from the stack
/// - flag_m: boolean flag indicating the memory chiplet is active (i.e. range checks are required).
///   This flag is degree 3.
/// - mv0-mv1: memory value 0-1, the 2 values range-checked from the memory chiplet
///
/// The constraint expression looks as follows:
/// b' = b + rc_multiplicity / (alpha + rc_value)
///        - flag_s / (alpha + sv0) - flag_s / (alpha + sv1)
///        - flag_s / (alpha + sv2) - flag_s / (alpha + sv3)
///        - flag_m / (alpha + mv0) - flag_m / (alpha + mv1)
///
/// However, to enforce the constraint, all denominators are multiplied so that no divisions are
/// included in the actual constraint expression.
///
/// Constraint degree: 9
fn enforce_b_range<E, F>(
    main_frame: &EvaluationFrame<F>,
    aux_frame: &EvaluationFrame<E>,
    alpha: E,
    result: &mut [E],
) where
    F: FieldElement<BaseField = Felt>,
    E: FieldElement<BaseField = Felt> + ExtensionOf<F>,
{
    // The denominator values for the LogUp lookup.
    let mv0: E = main_frame.lookup_mv0(alpha);
    let mv1: E = main_frame.lookup_mv1(alpha);
    let sv0: E = main_frame.lookup_sv0(alpha);
    let sv1: E = main_frame.lookup_sv1(alpha);
    let sv2: E = main_frame.lookup_sv2(alpha);
    let sv3: E = main_frame.lookup_sv3(alpha);
    let range_check: E = alpha + main_frame.v().into();
    let memory_lookups: E = mv0.mul(mv1); // degree 2
    let stack_lookups: E = sv0.mul(sv1).mul(sv2).mul(sv3); // degree 4
    let lookups = range_check.mul(stack_lookups).mul(memory_lookups); // degree 7

    // An intermediate value required by all stack terms that includes the flag indicating a stack
    // operation with range checks. This value has degree 6.
    let sflag_rc_mem: E = range_check
        .mul(memory_lookups)
        .mul_base(<EvaluationFrame<F> as MainFrameExt<F, E>>::u32_rc_op(main_frame));
    // An intermediate value required by all memory terms that includes the flag indicating the
    // memory portion of the chiplets trace. This value has degree 8.
    let mflag_rc_stack: E =
        range_check.mul(stack_lookups).mul_base(main_frame.chiplets_memory_flag());

    // The terms for the LogUp check after all denominators have been multiplied in.
    let b_next_term = aux_frame.b_range_next().mul(lookups); // degree 8
    let b_term = aux_frame.b_range().mul(lookups); // degree 8
    let rc_term = stack_lookups.mul(memory_lookups).mul_base(main_frame.multiplicity()); // degree 7
    let s0_term = sflag_rc_mem.mul(sv1).mul(sv2).mul(sv3); // degree 9
    let s1_term = sflag_rc_mem.mul(sv0).mul(sv2).mul(sv3); // degree 9
    let s2_term = sflag_rc_mem.mul(sv0).mul(sv1).mul(sv3); // degree 9
    let s3_term = sflag_rc_mem.mul(sv0).mul(sv1).mul(sv2); // degree 9
    let m0_term = mflag_rc_stack.mul(mv1); // degree 9
    let m1_term = mflag_rc_stack.mul(mv0); // degree 9

    result[0] = are_equal(
        b_term + rc_term - s0_term - s1_term - s2_term - s3_term - m0_term - m1_term,
        b_next_term,
    );
}

// RANGE CHECKER FRAME EXTENSION TRAIT
// ================================================================================================

/// Trait to allow easy access to column values and intermediate variables used in constraint
/// calculations for the Range Checker.
trait EvaluationFrameExt<E: FieldElement> {
    // --- Column accessors -----------------------------------------------------------------------

    /// The current value in the lookup multiplicity column.
    fn multiplicity(&self) -> E;
    /// The current value in column V.
    fn v(&self) -> E;
    /// The current value in auxiliary column b_range.
    fn b_range(&self) -> E;
    /// The next value in auxiliary column b_range.
    fn b_range_next(&self) -> E;

    // --- Intermediate variables & helpers -------------------------------------------------------

    /// The change between the current value in the specified column and the next value, calculated
    /// as `next - current`.
    fn change(&self, column: usize) -> E;
}

impl<E: FieldElement> EvaluationFrameExt<E> for &EvaluationFrame<E> {
    // --- Column accessors -----------------------------------------------------------------------

    #[inline(always)]
    fn multiplicity(&self) -> E {
        self.current()[M_COL_IDX]
    }

    #[inline(always)]
    fn v(&self) -> E {
        self.current()[V_COL_IDX]
    }

    #[inline(always)]
    fn b_range(&self) -> E {
        self.current()[B_RANGE_COL_IDX]
    }

    #[inline(always)]
    fn b_range_next(&self) -> E {
        self.next()[B_RANGE_COL_IDX]
    }

    // --- Intermediate variables & helpers -------------------------------------------------------

    #[inline(always)]
    fn change(&self, column: usize) -> E {
        self.next()[column] - self.current()[column]
    }
}
