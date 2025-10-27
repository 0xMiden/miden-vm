use alloc::vec::Vec;

use super::{EvaluationFrame, FieldElement, TransitionConstraintDegree, op_flags::OpFlags};
use crate::{stack::EvaluationFrameExt, utils::are_equal};

#[cfg(test)]
pub mod tests;

// CONSTANTS
// ================================================================================================

/// The number of unique transition constraints in the system operations.
pub const NUM_CONSTRAINTS: usize = 1;

/// The degrees of constraints in the individual constraints of the system ops.
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    // Given it is a degree 7 operation, 7 is added to all the individual constraints
    // degree.
    8, // constraint for ASSERT operation.
];

// SYSTEM OPERATIONS TRANSITION CONSTRAINTS
// ================================================================================================

/// Builds the transition constraint degrees of all the system operations.
pub fn get_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    CONSTRAINT_DEGREES
        .iter()
        .map(|&degree| TransitionConstraintDegree::new(degree))
        .collect()
}

/// Returns the number of transition constraints required in all the system operations.
pub fn get_transition_constraint_count() -> usize {
    NUM_CONSTRAINTS
}

/// Enforces constraints of all the system operations.
pub fn enforce_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    let mut index = 0;

    // enforces assert operation constraints.
    index += enforce_assert_constraints(frame, result, op_flag.assert());

    index
}

// TRANSITION CONSTRAINT HELPERS
// ================================================================================================

/// Enforces unique constraints of the ASSERT operation. The ASSERT operation asserts the top
/// element in the stack to ONE. Therefore, the following constraints are enforced:
/// - The first element in the current frame should be ONE. s0 = 1.
pub fn enforce_assert_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    // Enforces the first element in the current frame to ONE.
    result[0] = op_flag * are_equal(frame.stack_item(0), E::ONE);

    1
}

/// Enforces constraints of the CLK operation.
///
/// The CLK operation pushes the current cycle number to the stack. Therefore, the following
/// constraints are enforced:
/// - The first element in the next frame should be equal to the current cycle number. s0' - (cycle)
///   = 0.
pub fn enforce_clk_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    // Enforces the first element in the next frame is equal to the current clock cycle number.
    result[0] = op_flag * are_equal(frame.stack_item_next(0), frame.clk());

    1
}
