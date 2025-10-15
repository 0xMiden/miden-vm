use alloc::vec::Vec;

use super::{EvaluationFrame,  TransitionConstraintDegree, op_flags::OpFlags};
use crate::stack::EvaluationFrameExt;

#[cfg(test)]
//pub mod tests;

// CONSTANTS
// ================================================================================================

/// The number of transition constraints in all the field operations.
pub const NUM_CONSTRAINTS: usize = 4;

/// The degrees of constraints in individual stack operations of the field operations.
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    7, // constraint for stack depth, b0.
    3, // constraint for stack overflow flag, h0.
    7, 8, // constraint for stack overflow bookkeeping index, b1.
];

// STACK OVERFLOW TRANSITION CONSTRAINTS
// ================================================================================================

/// Builds the transition constraint degrees stack overflow.
pub fn get_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    CONSTRAINT_DEGREES
        .iter()
        .map(|&degree| TransitionConstraintDegree::new(degree))
        .collect()
}

/// Returns the number of transition constraints for stack overflow.
pub fn get_transition_constraint_count() -> usize {
    NUM_CONSTRAINTS
}

/// Enforces constraints for the stack overflow.
pub fn enforce_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    let mut index = 0;

    // Enforce constraints of the stack depth transition.
    index += enforce_stack_depth_constraints(frame, result, op_flag);

    // Enforce constraints of the overflow flag constraints.
    index += enforce_overflow_flag_constraints(frame, &mut result[index..], op_flag);

    // Enforce constraints of the stack bookkeeping b1 item.
    index += enforce_overflow_index_constraints(frame, &mut result[index..], op_flag);

    index
}

// TRANSITION CONSTRAINT HELPERS
// ================================================================================================

/// Enforces transition constraints for the stack depth updates during operations. Therefore, the
/// following constraints are enforced:
/// - If the operation is a no shift op, then, depth wouldn't change.
/// - If the operation is a right shift op, then, depth should increment by 1.
/// - If the operation is a left shift op, then, depth should be decreased by 1 provided the
///   existing depth of the stack is not 16. In the case of depth being 16, depth will not be
///   updated.
/// - If the current op being executed is `CALL`, `SYSCALL` or `DYNCALL`, then the depth should be
///   reset to 16.
///
/// TODO: This skips the operation when `END` is exiting for a `CALL` or a `SYSCALL` block. It
/// should be handled later in multiset constraints.
pub fn enforce_stack_depth_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    let depth = frame.stack_depth();
    let depth_next = frame.stack_depth_next();

    let call_or_dyncall_or_syscall = op_flag.call() + op_flag.dyncall() + op_flag.syscall();
    let call_or_dyncall_or_syscall_end =
        op_flag.end() * (frame.is_call_or_dyncall_end() + frame.is_syscall_end());

    let no_shift_part = (depth_next - depth)
        * (E::ONE - call_or_dyncall_or_syscall - call_or_dyncall_or_syscall_end);
    let left_shift_part = op_flag.left_shift() * op_flag.overflow();
    let right_shift_part = op_flag.right_shift();
    let call_part = call_or_dyncall_or_syscall * (depth_next - E::from(16u32));

    // Enforces constraints of the transition of depth of the stack.
    result[0] = no_shift_part + left_shift_part - right_shift_part + call_part;

    1
}

/// Enforces constraints on the overflow flag h0. Therefore, the following constraints
/// are enforced:
/// - If overflow table has values, then, h0 should be set to ONE, otherwise it should be ZERO.
pub fn enforce_overflow_flag_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    // Enforces that overflow flag is set correctly when there are values in overflow table
    // which can only happen when the depth of the stack is more than 16.
    result[0] = (E::ONE - op_flag.overflow()) * (frame.stack_depth() - E::from(16u32));

    1
}

/// Enforces constraints on the bookkeeping index `b1`. The following constraints are enforced:
/// - In the case of a right shift operation, the next b1 index should be updated with current `clk`
///   value.
/// - In the case of a left shift operation, the last stack item should be set to ZERO when the
///   depth of the stack is 16.
pub fn enforce_overflow_index_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    let overflow_next = frame.stack_overflow_addr_next();
    let last_stack_item_next = frame.stack_item_next(15);

    // enforces that the bookkeeping index b1 is set to the current clk value.
    result[0] = (overflow_next - frame.clk()) * op_flag.right_shift();

    // enforces that the last stack item in the next frame has been updated with z ZERO when the
    // depth of the stack is 16 and the current operation being executed is a left shift op.
    result[1] = (E::ONE - op_flag.overflow()) * op_flag.left_shift() * last_stack_item_next;

    1
}
