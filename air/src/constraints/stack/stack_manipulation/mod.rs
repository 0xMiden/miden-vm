use alloc::vec::Vec;

use super::{EvaluationFrame, FieldElement, TransitionConstraintDegree, op_flags::OpFlags};
use crate::{
    stack::EvaluationFrameExt,
    utils::{are_equal, binary_not},
};

#[cfg(test)]
pub mod tests;

// CONSTANTS
// ================================================================================================

/// The number of unique transition constraints in stack manipulation operations.
pub const NUM_CONSTRAINTS: usize = 49;

/// The degrees of constraints in individual stack manipulation operations.
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    // Given it is a degree 7 operation, 7 is added to all the individual constraints
    // degree.
    8, // 1 constraint for PAD operation
    8, 8, 8, 7, 7, 8, 7, 8, 8, 8, 8, 8, 8, // 13 constraints for DUPn and MOVUPn operations
    8, 8, // 2 constraints in SWAP operations
    8, 8, 8, 8, 8, 8, 8,
    8, // 8 constraints for SWAPWX operations including 8 constraints of SWAPDW operation
    8, 8, 8, 8, 8, 8, 8, 8, // 8 constraints for SWAPDW operations
    8, 8, 8, 8, 8, 8, 8, // 7 constraints for MOVDNn operations
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, // 10 constraints for CSWAP and CSWAPW operations
];

// STACK MANIPULATION OPERATIONS TRANSITION CONSTRAINTS
// ================================================================================================

/// Builds the transition constraint degrees for the stack manipulation operations.
pub fn get_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    CONSTRAINT_DEGREES
        .iter()
        .map(|&degree| TransitionConstraintDegree::new(degree))
        .collect()
}

/// Returns the number of transition constraints for the stack manipulation operations.
pub fn get_transition_constraint_count() -> usize {
    NUM_CONSTRAINTS
}

/// Enforces constraints for the stack manipulation operations.
pub fn enforce_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    let mut index = 0;

    // Enforce constaints of the PAD operations.
    index += enforce_pad_constraints(frame, result, op_flag.pad());

    // Enforce constaints of the DUP(n) and MOVUP(n) operations.
    index += enforce_dup_movup_n_constraints(frame, &mut result[index..], op_flag);

    // Enforce constaints of the SWAP operations.
    index += enforce_swap_constraints(frame, &mut result[index..], op_flag.swap());

    // Enforce constaints of all the SWAP{W, W2, W3, DW} operations.
    index += enforce_swapwx_constraints(frame, &mut result[index..], op_flag);

    // Enforce constaints of the MOVDN(n) operations.
    index += enforce_movdnn_constraints(frame, &mut result[index..], op_flag);

    // Enforce constaints of the CSWAP and CSWAPW operations.
    index += enforce_cswapx_constraints(frame, &mut result[index..], op_flag);

    index
}

// TRANSITION CONSTRAINT HELPERS
// ================================================================================================

/// Enforces constraints of the PAD operation.
///
/// The PAD operation pushes a ZERO onto the stack. Therefore, the following constraints are
/// enforced:
/// - The top element in the next frame should be ZERO. s0` = 0.
pub fn enforce_pad_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    // Enforces the top element in the next frame is ZERO.
    result[0] = op_flag * are_equal(frame.stack_item_next(0), E::ZERO);

    1
}

/// Enforces constraints of the DUPn and MOVUPn operations.
///
/// The DUPn operation copies the element at depth n in the stack and pushes the copy onto the
/// stack, whereas MOVUPn opearation moves the element at depth n to the top of the stack.
/// Therefore, the following constraints are enforced:
/// - The top element in the next frame should be equal to the element at depth n in the current
///   frame. s0` - sn = 0.
pub fn enforce_dup_movup_n_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    // combined flag of respective movupn and dupn operation.
    let dup_movup_2 = op_flag.movup2() + op_flag.dup2();
    let dup_movup_3 = op_flag.movup3() + op_flag.dup3();
    let dup_movup_4 = op_flag.movup4() + op_flag.dup4();
    let dup_movup_5 = op_flag.movup5() + op_flag.dup5();
    let dup_movup_6 = op_flag.movup6() + op_flag.dup6();
    let dup_movup_7 = op_flag.movup7() + op_flag.dup7();

    // Enforces the top element in the next frame is equal to the 1st element in the current
    // frame.
    result[0] = op_flag.dup() * are_equal(frame.stack_item_next(0), frame.stack_item(0));

    // Enforces the top element in the next frame is equal to the 2nd element in the current
    // frame.
    result[1] = op_flag.dup1() * are_equal(frame.stack_item_next(0), frame.stack_item(1));

    // Enforces the top element in the next frame is equal to the 3rd element in the current
    // frame.
    result[2] = dup_movup_2 * are_equal(frame.stack_item_next(0), frame.stack_item(2));

    // Enforces the top element in the next frame is equal to the 4th element in the current
    // frame.
    result[3] = dup_movup_3 * are_equal(frame.stack_item_next(0), frame.stack_item(3));

    // Enforces the top element in the next frame is equal to the 5th element in the current
    // frame.
    result[4] = dup_movup_4 * are_equal(frame.stack_item_next(0), frame.stack_item(4));

    // Enforces the top element in the next frame is equal to the 6th element in the current
    // frame.
    result[5] = dup_movup_5 * are_equal(frame.stack_item_next(0), frame.stack_item(5));

    // Enforces the top element in the next frame is equal to the 7th element in the current
    // frame.
    result[6] = dup_movup_6 * are_equal(frame.stack_item_next(0), frame.stack_item(6));

    // Enforces the top element in the next frame is equal to the 8th element in the current
    // frame.
    result[7] = dup_movup_7 * are_equal(frame.stack_item_next(0), frame.stack_item(7));

    // Enforces the top element in the next frame is equal to the 8th element in the current
    // frame.
    result[8] = op_flag.movup8() * are_equal(frame.stack_item_next(0), frame.stack_item(8));

    // Enforces the top element in the next frame is equal to the 10th element in the current
    // frame.
    result[9] = op_flag.dup9() * are_equal(frame.stack_item_next(0), frame.stack_item(9));

    // Enforces the top element in the next frame is equal to the 12th element in the current
    // frame.
    result[10] = op_flag.dup11() * are_equal(frame.stack_item_next(0), frame.stack_item(11));

    // Enforces the top element in the next frame is equal to the 14th element in the current
    // frame.
    result[11] = op_flag.dup13() * are_equal(frame.stack_item_next(0), frame.stack_item(13));

    // Enforces the top element in the next frame is equal to the 16th element in the current
    // frame.
    result[12] = op_flag.dup15() * are_equal(frame.stack_item_next(0), frame.stack_item(15));

    13
}

/// Enforces constraints of the SWAP operation.
///
/// The SWAP operation swaps the first two elements in the stack. Therefore, the following
/// constraints are enforced:
/// - The first element in the current frame should be equal to the second element in the next
///   frame.
/// - The second element in the current frame should be equal to the first element in the next
///   frame.
pub fn enforce_swap_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    // Enforces the first element in the current frame is same as to the second element in the
    // next frame.
    result[0] = op_flag * are_equal(frame.stack_item(0), frame.stack_item_next(1));

    // Enforces the second element in the current frame is same as to the first element in the
    // next frame.
    result[1] = op_flag * are_equal(frame.stack_item(1), frame.stack_item_next(0));

    2
}

/// Enforces constraints of all the SWAP{W, W2, W3, DW} operations. Each of the operation
/// effects the stack in the following way:
/// - The SWAPW operation swaps the elements 0,1,2,3 with 4,5,6,7 in the stack.
/// - The SWAPW2 operation swaps the elements 0,1,2,3 with 8,9,10,11 in the stack.
/// - The SWAPW3 operation swaps the elements 0,1,2,3 with 12,13,14,15 in the stack.
/// - The SWAPDW operation swaps the elements 0,1,2,3,4,5,6,7 with 8,9,10,11,12,13,14,15 in the
///   stack.
///
/// Therefore, the following constraints are enforced:
/// - During any frame, only one of these operation can be present (it is possible that none of
///   these operations are present), therefore, the respective stack item can only transition into
///   certain state and we can use this to combine these transition into one constraints where each
///   transition are weighted by their respective flag. for eg. in the case of SWAPW3 the first item
///   of the stack gets replaced with the 12 items and vice versa, therefore, only SWAPW3 transition
///   will be ONE and rest all flags would be ZERO.
#[expect(clippy::needless_range_loop)]
pub fn enforce_swapwx_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    let swapw_or_swapw3 = op_flag.swapw() + op_flag.swapw3();
    let swapw2_or_swapdw = op_flag.swapw2() + op_flag.swapdw();
    let swapwx = swapw_or_swapw3 + swapw2_or_swapdw;

    // enforce that the first four element in the stack have transitioned correctly.
    for i in 0..4 {
        let next_item = op_flag.swapw() * frame.stack_item_next(i + 4)
            + swapw2_or_swapdw * frame.stack_item_next(i + 8)
            + op_flag.swapw3() * frame.stack_item_next(i + 12);
        result[i] = are_equal(next_item, frame.stack_item(i) * swapwx);
    }

    // enforce that the transition into the first four elements in the next frame are done
    // correctly.
    for i in 0..4 {
        let current_item = op_flag.swapw() * frame.stack_item(i + 4)
            + swapw2_or_swapdw * frame.stack_item(i + 8)
            + op_flag.swapw3() * frame.stack_item(i + 12);
        result[i + 4] = are_equal(current_item, frame.stack_item_next(i) * swapwx);
    }

    // enforce that stack items 4,5,6,7 are swapped correctly.
    for i in 0..4 {
        result[i + 8] =
            op_flag.swapdw() * are_equal(frame.stack_item(i + 4), frame.stack_item_next(i + 12));
    }

    // enforce that stack items 12,13,14,15 are swapped correctly.
    for i in 0..4 {
        result[i + 12] =
            op_flag.swapdw() * are_equal(frame.stack_item(i + 12), frame.stack_item_next(i + 4));
    }

    16
}

/// Enforces constraints of the MOVDNn operation. The MOVDNn operation moves the top element
/// to depth n in the stack. Therefore, the following constraints are enforced:
/// - The top element in the current frame should be equal to the element at depth n in the next
///   frame. s0 - sn` = 0.
pub fn enforce_movdnn_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    // Enforces the top element in the current frame is equal to the nth element in the next
    // frame.
    result[0] = op_flag.movdn2() * are_equal(frame.stack_item(0), frame.stack_item_next(2));
    result[1] = op_flag.movdn3() * are_equal(frame.stack_item(0), frame.stack_item_next(3));
    result[2] = op_flag.movdn4() * are_equal(frame.stack_item(0), frame.stack_item_next(4));
    result[3] = op_flag.movdn5() * are_equal(frame.stack_item(0), frame.stack_item_next(5));
    result[4] = op_flag.movdn6() * are_equal(frame.stack_item(0), frame.stack_item_next(6));
    result[5] = op_flag.movdn7() * are_equal(frame.stack_item(0), frame.stack_item_next(7));
    result[6] = op_flag.movdn8() * are_equal(frame.stack_item(0), frame.stack_item_next(8));

    7
}

/// Enforces constraints of the CSWAP and CSWAPW operation. Each of the operation effects
/// the stack in the following way:
/// - The top element in the stack should be binary and is enforced as a general constraint.
/// - The CSWAP operation swaps the elements 1,2 in the stack if the first element is 1. The stack
///   remains the same if the top element is 0.
/// - The CSWAP operation swaps the elements 1,2,3,4 with 5,6,7,8 in the stack if the first element
///   is 1. The stack remains the same if the top element is 0.
///
/// Therefore, the following constraints are enforced:
/// - The top two elements or elements 1,2,3,4 should be swapped in the case of CSWAP and CSWAPW
///   respectively if the top element is 1, the state remains the same if the top element is 0.
pub fn enforce_cswapx_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    // condition should be binary and is enforced as a general constraint. It is used to
    // decide if the respective elements/words needs to be swapped or not.
    let condition = frame.stack_item(0);
    let not_condition = binary_not(frame.stack_item(0));

    let a = frame.stack_item(1);
    let b = frame.stack_item(2);
    let c = frame.stack_item_next(0);
    let d = frame.stack_item_next(1);

    // Enforces that b is moved to the top of the stack if the condition is 1 else a is
    //  moved to the top.
    result[0] = op_flag.cswap() * are_equal(c, a * not_condition + b * condition);

    // Enforces that b is at depth 2 in the stack if the condition is 0 else a should be
    // at depth 2.
    result[1] = op_flag.cswap() * are_equal(d, a * condition + b * not_condition);

    // Enforces the correct transition of a and b into item at index 0,1,2,3 in the next frame.
    for i in 0..4 {
        let a = frame.stack_item(i + 1);
        let b = frame.stack_item(i + 5);
        let c = frame.stack_item_next(i);

        result[i + 2] = op_flag.cswapw() * are_equal(c, a * not_condition + b * condition);
    }

    // Enforces the correct transition of a and b into item at index 4,5,6,7 in the next frame.
    for i in 0..4 {
        let a = frame.stack_item(i + 1);
        let b = frame.stack_item(i + 5);
        let c = frame.stack_item_next(i + 4);

        result[i + 6] = op_flag.cswapw() * are_equal(c, a * condition + b * not_condition);
    }

    10
}
