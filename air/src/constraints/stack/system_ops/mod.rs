use alloc::vec::Vec;

use super::{EvaluationFrame,  TransitionConstraintDegree, op_flags::OpFlags};
use crate::{stack::EvaluationFrameExt, utils::are_equal};

#[cfg(test)]
//pub mod tests;

// CONSTANTS
// ================================================================================================

/// The number of unique transition constraints in the system operations.
pub const NUM_CONSTRAINTS: usize = 3;

/// The degrees of constraints in the individual constraints of the system ops.
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    // Given it is a degree 7 operation, 7 is added to all the individual constraints
    // degree.
    8, // constraint for ASSERT operation.
    8, // constraint for FMPADD operation.
    8, // constraint for FMPUPDATE operation.
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

    // enforces fmpadd operation constraints.
    index += enforce_fmpadd_constraints(frame, &mut result[index..], op_flag.fmpadd());

    // enforces fmpupdate operation constraints.
    index += enforce_fmpupdate_constraints(frame, &mut result[index..], op_flag.fmpupdate());

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

/// Enforces unique constraints of the FMPADD operation.
///
/// The FMPADD operation increments the top element in the stack by `fmp` register value. Therefore,
/// the following constraints are enforced:
/// - The first element in the next frame should be equal to the addition of the first element in
///   the current frame and the fmp value. s0` - (s0 + fmp) = 0
pub fn enforce_fmpadd_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    // Enforces the first element in the next frame is incremented by fmp value.
    result[0] = op_flag * are_equal(frame.stack_item(0) + frame.fmp(), frame.stack_item_next(0));

    1
}

/// Enforces constraints of the FMPUPDATE operation.
///
/// The FMPUPDATE operation increments the fmp register value by the first element value in the
/// current trace. Therefore, the following constraints are enforced:
/// - The fmp register value in the next frame should be equal to the sum of the fmp register value
///   and the top stack element in the current frame. fmp` - (s0 + fmp) = 0.
pub fn enforce_fmpupdate_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    // Enforces the fmp register value is incremented by the first element value in current frame.
    result[0] = op_flag * are_equal(frame.fmp() + frame.stack_item(0), frame.fmp_next());

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
