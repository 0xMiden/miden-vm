use alloc::vec::Vec;

use super::{EvaluationFrame,  TransitionConstraintDegree, op_flags::OpFlags};
use crate::{stack::EvaluationFrameExt, utils::are_equal};

#[cfg(test)]
//pub mod tests;

// CONSTANTS
// ================================================================================================

/// The number of unique transition constraints in the input/output operations.
pub const NUM_CONSTRAINTS: usize = 1;

/// The degrees of constraints in the individual constraints of the input/output ops.
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    // Given it is a degree 7 operation, 7 is added to all the individual constraints
    // degree.
    8, // constraint for SDEPTH operation.
];

// INPUT/OUTPUT OPERATIONS TRANSITION CONSTRAINTS
// ================================================================================================

/// Builds the transition constraint degrees for the input/output operations.
pub fn get_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    CONSTRAINT_DEGREES
        .iter()
        .map(|&degree| TransitionConstraintDegree::new(degree))
        .collect()
}

/// Returns the number of transition constraints for the input/output operations.
pub fn get_transition_constraint_count() -> usize {
    NUM_CONSTRAINTS
}

/// Enforces constraints for the input/output operations.
pub fn enforce_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    let mut index = 0;

    index += enforce_sdepth_constraint(frame, result, op_flag.sdepth());

    index
}

/// Enforces constraints of the SDEPTH operation. The SDEPTH operation pushes the depth of
/// the stack onto the stack. Therefore, the following constraints are enforced:
/// - The depth of the stack should be equal to the top element in the next frame.
pub fn enforce_sdepth_constraint<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    // Enforces the depth of the stack is equal to the top element in the next frame.
    result[0] = op_flag * are_equal(frame.stack_item_next(0), frame.stack_depth());

    1
}
