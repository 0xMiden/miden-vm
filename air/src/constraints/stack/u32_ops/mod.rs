use alloc::vec::Vec;

use super::{EvaluationFrame, Felt, FieldElement, TransitionConstraintDegree, op_flags::OpFlags};
use crate::{
    stack::EvaluationFrameExt,
    utils::{are_equal, is_binary},
};

#[cfg(test)]
//pub mod tests;

// CONSTANTS
// ================================================================================================

/// The number of unique transition constraints in stack manipulation operations.
pub const NUM_CONSTRAINTS: usize = 13;

// The co-efficient of the most significant 16-bit limb in the helper register during aggregation.
pub const TWO_48: Felt = Felt::new(2u64.pow(48));

// The co-efficient of the 2nd most significant 16-bit limb in the helper register during
// aggregation.
pub const TWO_32: Felt = Felt::new(2u64.pow(32));

// The co-efficient of the 3rd significant 16-bit limb in the helper register during aggregation.
pub const TWO_16: Felt = Felt::new(2u64.pow(16));

// The co-efficient of the least significant 16-bit bit in the helper register during aggregation.
pub const TWO_0: Felt = Felt::new(1);

/// The degrees of constraints in individual u32 operations.
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    // Given it is a degree 6 operation, 6 is added to all the individual constraints
    // degree.
    9, // constraint for element validity check
    7, 7, // 2 constraints in the agg of lower and upper limbs
    7, // constraint for U32SPLIT operation
    7, // constraint for U32ADD  operation
    7, // constraint for U32ADD3 operation
    7, 8, // 2 constraints for U32SUB operation
    8, // constraint for U32MUL operation
    8, // constraint for U32MADD operation
    8, 7, 7, // constraint for U32DIV operation
];

// U32 OPERATIONS TRANSITION CONSTRAINTS
// ================================================================================================

/// Builds the transition constraint degrees for the u32 operations.
pub fn get_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    CONSTRAINT_DEGREES
        .iter()
        .map(|&degree| TransitionConstraintDegree::new(degree))
        .collect()
}

/// Returns the number of transition constraints for the u32 operations.
pub fn get_transition_constraint_count() -> usize {
    NUM_CONSTRAINTS
}

/// Enforces constraints for the u32 operations.
pub fn enforce_constraints<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    let mut index = 0;

    let limbs = LimbCompositions::new(frame);

    index += enforce_check_element_validity(frame, result, op_flag, &limbs);

    // Enforce general constaints of the u32 arithmetic operations.
    index += enforce_limbs_agg(frame, &mut result[index..], op_flag, &limbs);

    // Enforce constaints of the U32SPLIT operations.
    index += enforce_u32split_constraints(frame, &mut result[index..], op_flag.u32split(), &limbs);

    // Enforce constaints of the U32ADD operations.
    index += enforce_u32add_constraints(frame, &mut result[index..], op_flag.u32add(), &limbs);

    // Enforce constaints of the U32ADD3 operations.
    index += enforce_u32add3_constraints(frame, &mut result[index..], op_flag.u32add3(), &limbs);

    // Enforce constaints of the U32SUB operations.
    index += enforce_u32sub_constraints(frame, &mut result[index..], op_flag.u32sub());

    // Enforce constaints of the U32MUL operations.
    index += enforce_u32mul_constraints(frame, &mut result[index..], op_flag.u32mul(), &limbs);

    // Enforce constaints of the U32MADD operations.
    index += enforce_u32madd_constraints(frame, &mut result[index..], op_flag.u32madd(), &limbs);

    // Enforce constaints of the U32DIV operations.
    index += enforce_u32div_constraints(frame, &mut result[index..], op_flag.u32div(), &limbs);

    index
}

// TRANSITION CONSTRAINT HELPERS
// ================================================================================================

/// Enforces constraints of the U32SPLIT operation. The U32SPLIT operation splits the top element
/// into two 32-bit numbers. Therefore, the following constraints are enforced:
/// - The aggregation of limbs from the helper registers forms the top element in the stack.
pub fn enforce_u32split_constraints<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
    limbs: &LimbCompositions<E>,
) -> usize {
    // Enforces the aggregation of limbs from the helper registers forms the top element in the
    // current trace.
    result[0] = op_flag * are_equal(frame.stack_item(0), limbs.v64());

    1
}

/// Enforces constraints of the U32ADD operation. The U32ADD operation adds the top two
/// elements in the current trace of the stack. Therefore, the following constraints are
/// enforced:
/// - The aggregation of limbs from the helper registers is equal to the sum of the top two element
///   in the stack.
pub fn enforce_u32add_constraints<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
    limbs: &LimbCompositions<E>,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item(1);

    // Enforces the aggregation of the least three significant limbs from the helper registers forms
    // the sum of a and b.
    result[0] = op_flag * are_equal(a + b, limbs.v48());

    1
}

/// Enforces constraints of the U32ADD3 operation. The U32ADD3 operation adds the top three
/// elements in the current trace of the stack. Therefore, the following constraints are
/// enforced:
/// - The aggregation of limbs from the helper registers is equal to the sum of the top three
///   elements in the stack.
pub fn enforce_u32add3_constraints<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
    limbs: &LimbCompositions<E>,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item(1);
    let c = frame.stack_item(2);

    // Enforces the aggregation of the least three significant limbs from the helper registers forms
    // the combined sum of a, b and c.
    result[0] = op_flag * are_equal(a + b + c, limbs.v48());

    1
}

/// Enforces constraints of the U32SUB operation. The U32SUB operation subtracts the first
/// element from the second in the current trace of the stack. Therefore, the following
/// constraints are enforced:
/// - The aggregation of limbs from helper registers is equal to the difference of the top two
///   elements in the stack.
/// - The first element in the next trace should be a binary.
pub fn enforce_u32sub_constraints<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item(1);
    let c = frame.stack_item_next(0);
    let d = frame.stack_item_next(1);

    let sub_limb_aggregation = a + d - E::from(TWO_32) * c;

    // Enforces the aggregation of the limbs from the helper registers is equal to the difference
    // of b and a.
    result[0] = op_flag * are_equal(b, sub_limb_aggregation);

    // Enforces that c is a binary.
    result[1] = op_flag * is_binary(c);

    2
}

/// Enforces constraints of the U32MUL operation. The U32MUL operation multiplies the top two
/// elements in the current trace of the stack. Therefore, the following constraints are
/// enforced:
/// - The aggregation of all the limbs in the helper registers is equal to the product of the top
///   two elements in the stack.
pub fn enforce_u32mul_constraints<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
    limbs: &LimbCompositions<E>,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item(1);

    // Enforces the aggregation of all the limbs in the helper registers is the product of
    // a and b.
    result[0] = op_flag * are_equal(a * b, limbs.v64());

    1
}

/// Enforces constraints of the U32MADD operation.
///
/// The U32MADD operation adds the third element to the product of the first two elements in the
/// current trace. Therefore, the following constraints are enforced:
/// - The aggregation of all the limbs in the helper registers is equal to the sum of the third
///   element with the product of the first two elements in the current trace.
pub fn enforce_u32madd_constraints<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
    limbs: &LimbCompositions<E>,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item(1);
    let c = frame.stack_item(2);

    // Enforces the aggregation of all the limbs in the helper registers is equal to the
    // addition of c with the product of a and b.
    result[0] = op_flag * are_equal(a * b + c, limbs.v64());

    1
}

/// Enforces constraints of the U32DIV operation.
///
/// The U32DIV operation divides the second element with the first element in the current trace.
/// Therefore, the following constraints are enforced:
/// - The second element in the current trace should be equal to the sum of the first element in the
///   next trace with the product of the first element in the current trace and second element in
///   the next trace.
/// - The difference between the second elements in the current and next trace should be equal to
///   the aggregation of the lower 16-bits limbs.
/// - The difference between the second elements in the current and next trace and one should be
///   equal to the aggregation of the upper 16-bits limbs.
pub fn enforce_u32div_constraints<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
    limbs: &LimbCompositions<E>,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item(1);
    let c = frame.stack_item_next(0);
    let d = frame.stack_item_next(1);

    // Enforces that adding c with the product of a and d is equal to b.
    result[0] = op_flag * are_equal(a * d + c, b);

    // Enforces the aggregation of the lower limbs is equal to the difference between b and d.
    result[1] = op_flag * are_equal(b - d, limbs.v_lo());

    // Enforces the aggregation of the upper limbs is equal to the difference between a and c + 1.
    result[2] = op_flag * are_equal(a - c, limbs.v_hi() + E::ONE);

    3
}

// GENERAL U32 OPERATION CONSTRAINTS
// ===============================================================================================================

/// The constraint checks if the top four element in the trace on aggregating forms a valid field
/// element. no not. This constraint is applicable in `U32SPLIT`, `U32MADD` and `U32MUL`.
pub fn enforce_check_element_validity<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
    limbs: &LimbCompositions<E>,
) -> usize {
    let m = frame.user_op_helper(4);

    // composite flag for u32split, u32madd and u32mul.
    let u32_split_mul_madd = op_flag.u32mul() + op_flag.u32split() + op_flag.u32madd();

    let v_hi_comp = E::ONE - m * (E::from(TWO_32) - E::ONE - limbs.v_hi());

    // Enforces that the agggregation of the limbs forms a valid field element.
    result[0] = u32_split_mul_madd * are_equal(v_hi_comp * limbs.v_lo(), E::ZERO);

    1
}

/// Enforces constraints of the general operation. The constaints checks if the lower 16-bits limbs
/// are aggregated correctly or not. Therefore, the following constraints are enforced:
/// - The aggregation of lower two lower 16-bits limbs in the helper registers is equal to the
///   second element in the next row.
/// - The aggregation of lower two upper 16-bits limbs in the helper registers is equal to the first
///   element in the next row.
pub fn enforce_limbs_agg<E: FieldElement<BaseField = Felt>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
    limbs: &LimbCompositions<E>,
) -> usize {
    // flag of u32 arithmetic operation excluding the `U32DIV` operation.
    let u32op_ex_div_assert2 = op_flag.u32_rc_op() - op_flag.u32div() - op_flag.u32assert2();

    let u32op_ex_div_assert2_sub = u32op_ex_div_assert2 - op_flag.u32sub();

    // Enforces that aggregation of the two lower 16-bits limbs is equal to the second stack element
    // in the next row.
    result[0] = u32op_ex_div_assert2 * are_equal(frame.stack_item_next(1), limbs.v_lo());

    // Enforces that aggregation of the two upper 16-bits limbs is equal to the first stack element
    // in the next row.
    result[1] = u32op_ex_div_assert2_sub * are_equal(frame.stack_item_next(0), limbs.v_hi());

    2
}

// U32 HELPERS
// ================================================================================================

/// Contains intermediate limbs values required in u32 constraint checks.
pub struct LimbCompositions<E: FieldElement> {
    v_hi: E,
    v_lo: E,
    v48: E,
    v64: E,
}

impl<E: FieldElement<BaseField = Felt>> LimbCompositions<E> {
    // Returns a new instance of [LimbCompositions] instantiated with all the intermediate limbs
    // values.
    pub fn new(frame: &EvaluationFrame<E>) -> Self {
        let v_lo =
            E::from(TWO_16) * frame.user_op_helper(1) + E::from(TWO_0) * frame.user_op_helper(0);

        let v_hi =
            E::from(TWO_16) * frame.user_op_helper(3) + E::from(TWO_0) * frame.user_op_helper(2);

        let v48 = E::from(TWO_32) * frame.user_op_helper(2) + v_lo;

        let v64 = E::from(TWO_48) * frame.user_op_helper(3) + v48;

        Self { v_hi, v_lo, v48, v64 }
    }

    /// Returns v_hi intermediate flag value.
    fn v_hi(&self) -> E {
        self.v_hi
    }

    /// Returns v_lo intermediate flag value.
    fn v_lo(&self) -> E {
        self.v_lo
    }

    /// Returns v48 intermediate flag value.
    fn v48(&self) -> E {
        self.v48
    }

    /// Returns v64 intermediate flag value.
    fn v64(&self) -> E {
        self.v64
    }
}
