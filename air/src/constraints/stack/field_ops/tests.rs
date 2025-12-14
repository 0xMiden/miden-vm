use core::ops::Neg;

use miden_core::{Felt, ONE, Operation, ZERO};
use proptest::prelude::*;
use winter_rand_utils::rand_value;

use super::{
    super::{DECODER_TRACE_OFFSET, STACK_TRACE_OFFSET},
    EvaluationFrame, NUM_CONSTRAINTS, enforce_constraints,
};
use crate::{
    stack::op_flags::{OpFlags, generate_evaluation_frame},
    trace::decoder::USER_OP_HELPERS_OFFSET,
};

// RANDOMIZED TESTS
// ================================================================================================

proptest! {

    // -------------------------------- EQZ test --------------------------------------------------

    #[test]
    fn test_eqz_stack_operation(a in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];

        // ----------------- top element is anything except 0 ------------------------------------
        if a != 0 {
            let frame = get_eqz_test_frame(a);
            let result = get_constraint_evaluation(frame);
            assert_eq!(expected, result);
        }

        // ----------------- top element is 0 -----------------------------------------------------
        let a = 0;
        let frame = get_eqz_test_frame(a);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // --------------------------------INCR test --------------------------------------------------

    #[test]
    fn test_incr_stack_operation(a in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_incr_test_frame(a);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // --------------------------------INV test --------------------------------------------------

    #[test]
    fn test_inv_stack_operation(a in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_inv_test_frame(a);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }
    // --------------------------------NEG test --------------------------------------------------

    #[test]
    fn test_neg_stack_operation(a in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_neg_test_frame(a);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- ADD test --------------------------------------------------

    #[test]
    fn test_add_stack_operation(a in any::<u64>(), b in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_add_test_frame(a, b);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- MUL test --------------------------------------------------

    #[test]
    fn test_mul_stack_operation(a in any::<u64>(), b in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_mul_test_frame(a, b);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- EQ test --------------------------------------------------

    #[test]
    fn test_eq_stack_operation(a in any::<u64>(), b in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];

        // ----------------- top two elements are not same ------------------------------------
        if a != b {
            let frame = get_eq_test_frame(a, b);
            let result = get_constraint_evaluation(frame);
            assert_eq!(expected, result);
        }

        // ----------------- top two elements are same -----------------------------------------------------
        let b = a;
        let frame = get_eq_test_frame(a, b);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- EXPACC test --------------------------------------------------

    #[test]
    fn test_expacc_stack_operation(a in any::<u64>(), b in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let no_bits_stack = (b as f64).log2().ceil() as u64;
        for c in 0..no_bits_stack{
            let frame = get_expacc_test_frame(c, a, b);
            let result = get_constraint_evaluation(frame);
            assert_eq!(expected, result);
        }
    }

    // -------------------------------- EXT2MUL test --------------------------------------------------

    #[test]
    fn test_ext2mul_stack_operation(a0 in any::<u64>(), a1 in any::<u64>(), b0 in any::<u64>(), b1 in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_ext2_mul_test_frame(Felt::new(a0), Felt::new(a1), Felt::new(b0), Felt::new(b1));
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }
}

// UNIT TESTS
// ================================================================================================

// -------------------------------- NOT test --------------------------------------------------

#[test]
fn test_not_stack_operation() {
    let expected = [ZERO; NUM_CONSTRAINTS];

    // ----------------- top element is 1 -----------------------------------------------------
    let a = ONE;
    let frame = get_not_test_frame(a);
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);

    // ----------------- top element is 0 -----------------------------------------------------
    let a = ZERO;
    let frame = get_not_test_frame(a);
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);
}

// -------------------------------- AND test --------------------------------------------------

#[test]
fn test_and_stack_operation() {
    let expected = [ZERO; NUM_CONSTRAINTS];

    // ----------------- top elements are 0 and 0 -------------------------------------------------
    let a = ZERO;
    let b = ZERO;
    let frame = get_and_test_frame(a, b);
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);

    // ----------------- top elements are 0 and 1 -------------------------------------------------

    let a = ZERO;
    let b = ONE;
    let frame = get_and_test_frame(a, b);
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);

    // ----------------- top elements are 1 and 0 -------------------------------------------------

    let a = ONE;
    let b = ZERO;
    let frame = get_and_test_frame(a, b);
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);

    // ----------------- top elements are 1 and 1 -------------------------------------------------

    let a = ONE;
    let b = ONE;
    let frame = get_and_test_frame(a, b);
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);
}

// -------------------------------- OR test --------------------------------------------------

#[test]
fn test_or_stack_operation() {
    let expected = [ZERO; NUM_CONSTRAINTS];

    // ----------------- top elements are 0 and 0 -------------------------------------------------
    let a = ZERO;
    let b = ZERO;
    let frame = get_or_test_frame(a, b);
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);

    // ----------------- top elements are 0 and 1 -------------------------------------------------

    let a = ZERO;
    let b = ONE;
    let frame = get_or_test_frame(a, b);
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);

    // ----------------- top elements are 1 and 0 -------------------------------------------------

    let a = ONE;
    let b = ZERO;
    let frame = get_or_test_frame(a, b);
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);

    // ----------------- top elements are 1 and 1 -------------------------------------------------

    let a = ONE;
    let b = ONE;
    let frame = get_or_test_frame(a, b);
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);
}

// TEST HELPERS
// ================================================================================================

/// Returns the result of stack operation constraint evaluations on the provided frame.
fn get_constraint_evaluation(frame: EvaluationFrame<Felt>) -> [Felt; NUM_CONSTRAINTS] {
    let mut result = [ZERO; NUM_CONSTRAINTS];

    let op_flag = OpFlags::new(&frame);

    enforce_constraints(&frame, &mut result, &op_flag);

    result
}

/// Generates the correct current and next rows for the EQZ operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_eqz_test_frame(a: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a EQZ operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Eqz.op_code() as usize);

    // Set the output. First element in the next frame should be 1 if the first element
    // in the current frame is 0 and 0 vice-versa.
    match a {
        0 => {
            frame.current_mut()[STACK_TRACE_OFFSET] = ZERO;
            frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] =
                Felt::new(rand_value::<u64>());
            frame.next_mut()[STACK_TRACE_OFFSET] = ONE;
        },
        _ => {
            frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
            frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] = Felt::new(a).inverse();
            frame.next_mut()[STACK_TRACE_OFFSET] = ZERO;
        },
    }

    frame
}

/// Generates the correct current and next rows for the INCR operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_incr_test_frame(a: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a Incr operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Incr.op_code() as usize);

    // Set the output. First element in the next frame should be 1 + first
    // element of the current frame.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(a) + ONE;

    frame
}

/// Generates the correct current and next rows for the INV operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_inv_test_frame(a: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a Inv operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Inv.op_code() as usize);

    // Set the output. First element in the next frame should be the inverse of
    // the first element of the current frame.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(a).inverse();

    frame
}

/// Generates the correct current and next rows for the NEG operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_neg_test_frame(a: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a Neg operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Neg.op_code() as usize);

    // Set the output. First element in the next frame should be the negation of
    // the first element of the current frame.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(a).neg();

    frame
}

/// Generates the correct current and next rows for the ADD operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_add_test_frame(a: u64, b: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a ADD operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Add.op_code() as usize);

    // Set the output. First element in the next frame should be the addition of
    // the first two elements in the current frame.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b);
    frame.next_mut()[STACK_TRACE_OFFSET] =
        frame.current_mut()[STACK_TRACE_OFFSET] + frame.current_mut()[STACK_TRACE_OFFSET + 1];

    frame
}

/// Generates the correct current and next rows for the MUL operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_mul_test_frame(a: u64, b: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a MUL operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Mul.op_code() as usize);

    // Set the output. First element in the next frame should be the product of
    // the first two elements in the current frame.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b);
    frame.next_mut()[STACK_TRACE_OFFSET] =
        frame.current_mut()[STACK_TRACE_OFFSET] * frame.current_mut()[STACK_TRACE_OFFSET + 1];

    frame
}

/// Generates the correct current and next rows for the EQ operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_eq_test_frame(a: u64, b: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a EQ operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Eq.op_code() as usize);

    // Set the output. First element in the next frame should be 1 if the first two elements
    // in the current frame are equal and 0 otherwise.
    if a == b {
        frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
        frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b);
        frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] =
            Felt::new(rand_value::<u64>());
        frame.next_mut()[STACK_TRACE_OFFSET] = ONE;
    } else {
        frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
        frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b);
        frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] =
            (Felt::new(a) - Felt::new(b)).inverse();
        frame.next_mut()[STACK_TRACE_OFFSET] = ZERO;
    }

    frame
}

/// Generates the correct current and next rows for the NOT operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_not_test_frame(a: Felt) -> EvaluationFrame<Felt> {
    // frame initialised with a NOT operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Not.op_code() as usize);

    // Set the output. First element in the next frame should be the binary not of
    // the first element of the current frame.
    frame.current_mut()[STACK_TRACE_OFFSET] = a;
    frame.next_mut()[STACK_TRACE_OFFSET] = ONE - a;

    frame
}

/// Generates the correct current and next rows for the AND operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_and_test_frame(a: Felt, b: Felt) -> EvaluationFrame<Felt> {
    // frame initialised with an AND operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::And.op_code() as usize);

    // Set the output. First element in the next frame should be the binary and of
    // the first two elements of the current frame.
    frame.current_mut()[STACK_TRACE_OFFSET] = a;
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = b;
    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(a.as_int() & b.as_int());

    frame
}

/// Generates the correct current and next rows for the OR operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_or_test_frame(a: Felt, b: Felt) -> EvaluationFrame<Felt> {
    // frame initialised with a OR operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Or.op_code() as usize);

    // Set the output. First element in the next frame should be the binary or of
    // the first two elements of the current frame.
    frame.current_mut()[STACK_TRACE_OFFSET] = a;
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = b;
    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(a.as_int() | b.as_int());

    frame
}

/// Generates the correct current and next rows for the EXPACC operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_expacc_test_frame(a: u64, base: u64, exp: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a EXPACC operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Expacc.op_code() as usize);

    let (exp, res, b) = expacc_helper(a, base, exp);

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = exp;
    frame.current_mut()[STACK_TRACE_OFFSET + 2] = res;
    frame.current_mut()[STACK_TRACE_OFFSET + 3] = b;

    let bit = Felt::new(b.as_int() & 1);
    let val = (exp - ONE) * bit + ONE;
    let b = Felt::new(b.as_int() >> 1);

    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] = val;
    frame.next_mut()[STACK_TRACE_OFFSET] = bit;
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = exp * exp;
    frame.next_mut()[STACK_TRACE_OFFSET + 2] = res * val;
    frame.next_mut()[STACK_TRACE_OFFSET + 3] = b;

    frame
}

/// Generates the correct current and next rows for the EXT2MUL operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_ext2_mul_test_frame(a0: Felt, a1: Felt, b0: Felt, b1: Felt) -> EvaluationFrame<Felt> {
    // frame initialised with a EXT2MUL operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Ext2Mul.op_code() as usize);

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET] = a1;
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = a0;
    frame.current_mut()[STACK_TRACE_OFFSET + 2] = b1;
    frame.current_mut()[STACK_TRACE_OFFSET + 3] = b0;

    frame.next_mut()[STACK_TRACE_OFFSET] = a1;
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = a0;
    frame.next_mut()[STACK_TRACE_OFFSET + 2] = (b0 + b1) * (a1 + a0) - b0 * a0;
    frame.next_mut()[STACK_TRACE_OFFSET + 3] = b0 * a0 - Felt::new(2) * b1 * a1;

    frame
}

// This helper computes the power of base raised to exp.
fn expacc_helper(mut a: u64, base: u64, mut pow: u64) -> (Felt, Felt, Felt) {
    let mut res = ONE;
    let mut base_exp = Felt::new(base);
    while a > 0 {
        let bit = pow & 1;

        if bit == 1 {
            res *= base_exp;
        }

        pow >>= 1;

        base_exp *= base_exp;

        a -= 1;
    }

    (base_exp, res, Felt::new(pow))
}
