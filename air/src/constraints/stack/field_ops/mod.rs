use alloc::vec::Vec;

use super::{EvaluationFrame, FieldElement, TransitionConstraintDegree, op_flags::OpFlags};
use crate::{
    stack::EvaluationFrameExt,
    utils::{are_equal, is_binary},
};

#[cfg(test)]
pub mod tests;

// CONSTANTS
// ================================================================================================

/// The number of transition constraints in all the field operations.
pub const NUM_CONSTRAINTS: usize = 22;

/// The degrees of constraints in individual stack operations of the field operations.
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    // Given it is a degree 7 operation, 7 is added to all the individual constraints
    // degree.
    8, // constraint for ADD field operation.
    8, // constraint for NEG field operation.
    9, // constraint for MUL field operation.
    9, // constraint for INV field operation.
    8, // constraint for INCR field operation.
    8, // constraint for NOT field operation.
    9, 9, // two constraints for AND field operation.
    9, 9, // two constraints for OR field operation.
    9, 9, // two constraints for EQ field operation.
    9, 9, // two constraints for EQZ field operation.
    9, 9, 9, 8, // four constraints for EXPACC field operation.
    8, 8, 9, 9, // four constraints for EXT2MUL field operation.
];

// FIELD OPERATIONS TRANSITION CONSTRAINTS
// ================================================================================================

/// Builds the transition constraint degrees of the field operations.
pub fn get_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    CONSTRAINT_DEGREES
        .iter()
        .map(|&degree| TransitionConstraintDegree::new(degree))
        .collect()
}

/// Returns the number of transition constraints of the field operations.
pub fn get_transition_constraint_count() -> usize {
    NUM_CONSTRAINTS
}

/// Enforces constraints of the Field operations.
pub fn enforce_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: &OpFlags<E>,
) -> usize {
    let mut index = 0;

    // Enforce constaints of the ADD operation.
    index += enforce_add_constraints(frame, result, op_flag.add());

    // Enforce constaints of the NEG operation.
    index += enforce_neg_constraints(frame, &mut result[index..], op_flag.neg());

    // Enforce constaints of the MUL operation.
    index += enforce_mul_constraints(frame, &mut result[index..], op_flag.mul());

    // Enforce constaints of the INV operation.
    index += enforce_inv_constraints(frame, &mut result[index..], op_flag.inv());

    // Enforce constaints of the INCR operation.
    index += enforce_incr_constraints(frame, &mut result[index..], op_flag.incr());

    // Enforce constaints of the NOT operation.
    index += enforce_not_constraints(frame, &mut result[index..], op_flag.not());

    // Enforce constaints of the AND operation.
    index += enforce_and_constraints(frame, &mut result[index..], op_flag.and());

    // Enforce constaints of the OR operation.
    index += enforce_or_constraints(frame, &mut result[index..], op_flag.or());

    // Enforce constaints of the EQ operation.
    index += enforce_eq_constraints(frame, &mut result[index..], op_flag.eq());

    // Enforce constaints of the EQZ operation.
    index += enforce_eqz_constraints(frame, &mut result[index..], op_flag.eqz());

    // Enforce constaints of the EXPACC operation.
    index += enforce_expacc_constraints(frame, &mut result[index..], op_flag.expacc());

    // Enforce constraints of the EXT2MUL operation.
    index += enforce_ext2mul_constraints(frame, &mut result[index..], op_flag.ext2mul());

    index
}

// TRANSITION CONSTRAINT HELPERS
// ================================================================================================

/// Enforces constraints of the ADD operation.
///
/// The ADD operation adds the first two elements in the current trace. Therefore, the following
/// constraints are enforced:
/// - The first element in the trace frame should be the addition of the first two elements in the
///   current trace. s0` - s0 - s1 = 0.
pub fn enforce_add_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item(1);
    let c = frame.stack_item_next(0);

    // Enforce that c is equal to the sum of a and b.
    result[0] = op_flag * are_equal(a + b, c);

    1
}

/// Enforces constraints of the NEG operation.
///
/// The NEG operation updates the top element in the stack with its inverse. Therefore, the
/// following constraints are enforced:
/// - The first element in the next frame should be the negation of first element in the current
///   frame, therefore, their sum should be 0. s0` + s0 = 0.
pub fn enforce_neg_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    // Enforces the first element in the current frame is a negation of the first element in the
    // next frame.
    result[0] = op_flag * are_equal(frame.stack_item(0) + frame.stack_item_next(0), E::ZERO);

    1
}

/// Enforces constraints of the MUL operation.
///
/// The MUL operation multiplies the first two elements in the current trace. Therefore, the
/// following constraints are enforced:
/// - The first element in the next frame should be the product of the first two elements in the
///   current frame. s0` - s0 * s1 = 0
pub fn enforce_mul_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item(1);
    let c = frame.stack_item_next(0);

    // Enforce that c is the product of a and b.
    result[0] = op_flag * are_equal(a * b, c);

    1
}

/// Enforces constraints of the INV operation.
///
/// The INV operation updates the top element in the stack with its inverse. Therefore, the
/// following constraints are enforced:
/// - The next element in the next frame should be the inverse of first element in the current
///   frame. s0` * s0 = 1.
pub fn enforce_inv_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    // Enforces the first element in the next frame is an inverse of the first element in the
    // current frame.
    result[0] = op_flag * are_equal(frame.stack_item(0) * frame.stack_item_next(0), E::ONE);

    1
}

/// Enforces constraints of the INCR operation.
///
/// The INCR operation increments the top element in the stack by 1. Therefore, the following
/// constraints are enforced:
/// - The next element in the next frame should be equal to the addition of first element in the
///   current frame with 1. s0` - s0 - 1 = 0.
pub fn enforce_incr_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    // Enforces the first element in the next frame is incremented by 1.
    result[0] = op_flag * are_equal(frame.stack_item(0) + E::ONE, frame.stack_item_next(0));

    1
}

/// Enforces constraints of the NOT operation.
///
/// The NOT operation updates the top element in the stack with its bitwise not value. Therefore,
/// the following constraints are enforced:
/// - The top element should be a binary. It is enforced as a general constraint.
/// - The first element of the next frame should be a binary not of the first element of the current
///   frame. s0` + s0 = 1.
pub fn enforce_not_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item_next(0);

    // The top element should be a binary and is enforced as a general constraint.
    // Enforce that b is the binary not of a.
    result[0] = op_flag * are_equal(a + b, E::ONE);

    1
}

/// Enforces constraints of the AND operation.
///
/// The AND operation computes the bitwise and of the first two elements in the current trace.
/// Therefore, the following constraints are enforced:
/// - The top two element in the current frame of the stack should be binary. s0^2 - s0 = 0, s1^2 -
///   s1 = 0. The top element is binary or not is enforced as a general constraint.
/// - The first element of the next frame should be a binary and of the first two elements in the
///   current frame. s0` - s0 * s1 = 0.
pub fn enforce_and_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item(1);
    let c = frame.stack_item_next(0);

    // Enforce that b is a binary. a is binary is enforced as a general constraint.
    result[0] = op_flag * is_binary(b);

    // bitwise and of a and b.
    let and_value = a * b;

    // Enforce that c is the bitwise and of a & b.
    result[1] = op_flag * are_equal(c, and_value);

    2
}

/// Enforces constraints of the OR operation.
///
/// The OR operation computes the bitwise or of the first two elements in the current trace.
/// Therefore, the following constraints are enforced:
/// - The top two element in the current frame of the stack should be binary. s0^2 - s0 = 0, s1^2 -
///   s1 = 0. The top element is binary or not is enforced as a general constraint.
/// - The first element of the next frame should be a binary or of the first two elements in the
///   current frame. s0` - ( s0 + s1 - s0 * s1 ) = 0.
pub fn enforce_or_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item(1);
    let c = frame.stack_item_next(0);

    // Enforce that b is a binary. a is binary is enforced as a general constraint.
    result[0] = op_flag * is_binary(b);

    // bitwise or of a and b.
    let or_value = a + b - a * b;

    // Enforce that c is the bitwise or of a and b.
    result[1] = op_flag * are_equal(c, or_value);

    2
}

/// Enforces constraints of the EQ operation.
///
/// The EQ operation checks if the top two elements in the current frame are equal or not.
/// Therefore, the following constraints are enforced:
/// - (s0 - s1) * s0' = 0
/// - s0` - (1 - (s0 - s1) * h0) = 0
pub fn enforce_eq_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item(1);
    let c = frame.stack_item_next(0);

    // difference between a and b.
    let diff_top_elements = a - b;

    // Enforce that either c or difference between a & b is zero.
    result[0] = op_flag * are_equal(diff_top_elements * c, E::ZERO);

    // It is the inverse of the diff of the top two element in the current frame if the diff is not
    // ZERO; otherwise it could be anything. The value is fetched from the first register in the
    // user op helper.
    let diff_inv = frame.user_op_helper(0);

    let helper_agg_value = E::ONE - diff_top_elements * diff_inv;

    // Enforce that if the difference between a & b is zero, c cannot be zero and vice versa.
    result[1] = op_flag * are_equal(c, helper_agg_value);

    2
}

/// Enforces constraints of the EQZ operation.
///
/// The EQZ operation checks if the top element in the current frame is 0 or not. Therefore, the
/// following constraints are enforced:
/// - s0 * s0` = 0.
/// - s0` - (1 - h0 * s0) = 0.
pub fn enforce_eqz_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    let a = frame.stack_item(0);
    let b = frame.stack_item_next(0);

    // Enforce that either a or b is zero.
    result[0] = op_flag * are_equal(a * b, E::ZERO);

    // It is the inverse of the top element in the current frame if the top element is not ZERO; it
    // could be anything otherwise. The value is fetched from the first register in the user op
    // helper.
    let inv = frame.user_op_helper(0);

    let helper_agg_value = E::ONE - a * inv;

    // Enforce that if a is zero, b cannot be zero and vice versa.
    result[1] = op_flag * are_equal(b, helper_agg_value);

    2
}

/// Enforces constraints of the EXPACC operation.
///
/// The EXPACC operation computes a single turn of exponent accumulation for the given inputs.
/// Therefore, the following constraints are enforced:
/// - The first element in the next frame should be a binary which is enforced as a general
///   constraint.
/// - The exp value in the next frame should be the square of exp value in the current frame.
/// - The accumulation value in the next frame is the product of the accumulation value in the
///   current frame and the value which needs to be included in this turn.
/// - The b value is right shifted by 1 bit.
pub fn enforce_expacc_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    let exp = frame.stack_item(1);
    let acc = frame.stack_item(2);
    let b = frame.stack_item(3);

    let bit = frame.stack_item_next(0);
    let val = frame.user_op_helper(0);
    let exp_next = frame.stack_item_next(1);
    let acc_next = frame.stack_item_next(2);
    let b_next = frame.stack_item_next(3);

    // bit should be binary and is enforced as a general constaint.
    // Enforces that exp_next is a square of exp.
    result[0] = op_flag * are_equal(exp_next, exp * exp);

    // Enforces that val is calculated correctly using exp and bit.
    result[1] = op_flag * are_equal(val - E::ONE, (exp - E::ONE) * bit);

    // Enforces that acc_next is the product of val and acc.
    result[2] = op_flag * are_equal(acc_next, acc * val);

    // Enforces that b_next is equal to b after a right shift.
    result[3] = op_flag * are_equal(b, b_next * E::from(2u32) + bit);

    4
}

/// Enforces constraints of the EXT2MUL operation.
///
/// The EXT2MUL operation computes the product of two elements in the extension
/// field 𝔽ₚ\[x\]/(x² - x + 2):
///
/// Let $a = a1 \cdot x + a0$ and $b = b1 \cdot x + b0$. Then:
///
/// ```math
/// a \cdot b = (a1 \cdot b1)x^2 + (a1 \cdot b0 + a0 \cdot b1)x + (a0 \cdot b0)
/// ```
///
/// Since $x^2 \equiv x - 2$ in $\mathbb{F}_p\[x\]/(x^2 - x + 2)$, this reduces to:
///
/// ```math
/// a \cdot b = (a1 \cdot b0 + a0 \cdot b1 + a1 \cdot b1)x + (a0 \cdot b0 - 2 \cdot a1 \cdot b1)
/// ```
///
/// The formula for the $x$ coefficient can be implemented more efficiently using the Karatsuba
/// trick:
///
/// ```math
/// a1 \cdot b0 + a0 \cdot b1 + a1 \cdot b1 = (b0 + b1)(a0 + a1) - (a0 \cdot b0)
/// ```
///
/// which reduces the number of multiplications at the expense of one subtraction.
///
/// Therefore, the following constraints are enforced, assuming the first 4 elements of the stack in
/// the current frame are a1, a0, b1, b0:
/// - The first element in the next frame should be a1.
/// - The second element in the next frame should be a0.
/// - The third element in the next frame should be equal to $(b0 + b1)(a0 + a1) - a0 \cdot b0$.
/// - The fourth element in the next frame should be equal to $a0 \cdot b0 - 2 \cdot a1 \cdot b1$.
pub fn enforce_ext2mul_constraints<E: FieldElement>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    op_flag: E,
) -> usize {
    let a1 = frame.stack_item(0);
    let a0 = frame.stack_item(1);
    let b1 = frame.stack_item(2);
    let b0 = frame.stack_item(3);
    let c1 = frame.stack_item_next(0);
    let c0 = frame.stack_item_next(1);
    let d1 = frame.stack_item_next(2);
    let d0 = frame.stack_item_next(3);

    // Enforce that c1 = a1
    result[0] = op_flag * are_equal(c1, a1);

    // Enforce that c0 = a0
    result[1] = op_flag * are_equal(c0, a0);

    // Enforce that d1 = (b0 + b1) * (a1 + a0) - b0 * a0
    result[2] = op_flag * are_equal(d1, (b0 + b1) * (a1 + a0) - b0 * a0);

    // Enforce that d0 = b0 * a0 - 2 * b1 * a1
    result[3] = op_flag * are_equal(d0, b0 * a0 - E::from(2_u32) * b1 * a1);

    4
}
