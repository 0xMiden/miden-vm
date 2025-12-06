use miden_core::{Felt, FieldElement, Operation, ZERO};
use proptest::prelude::*;

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

    // -------------------------------- U32SPLIT test -----------------------------------------------

    #[test]
    fn test_u32split_operation(a in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_u32split_test_frame(a);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- U32ADD test --------------------------------------------------

    #[test]
    fn test_u32add_operation(a in any::<u32>(), b in any::<u32>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_u32add_test_frame(a, b);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- U32ADD3 test --------------------------------------------------

    #[test]
    fn test_u32add3_operation(a in any::<u32>(), b in any::<u32>(), c in any::<u32>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_u32add3_test_frame(a, b, c);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- U32MUL test --------------------------------------------------

    #[test]
    fn test_u32mul_operation(a in any::<u32>(), b in any::<u32>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_u32mul_test_frame(a, b);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- U32MADD test --------------------------------------------------

    #[test]
    fn test_u32madd_operation(a in any::<u32>(), b in any::<u32>(), c in any::<u32>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_u32madd_test_frame(a, b, c);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- U32SUB test --------------------------------------------------

    #[test]
    fn test_u32sub_operation(a in any::<u32>(), b in any::<u32>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_u32sub_test_frame(a, b);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- U32DIV test --------------------------------------------------

    #[test]
    fn test_u32div_operation(a in any::<u32>(), b in any::<u32>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        if a != 0 {
            let frame = get_u32div_test_frame(a, b);
            let result = get_constraint_evaluation(frame);
            assert_eq!(expected, result);
        }

    }
}

// TEST HELPERS
// ================================================================================================

/// Returns the result of stack operation constraint evaluations on the provided frame.
fn get_constraint_evaluation(frame: EvaluationFrame<Felt>) -> [Felt; NUM_CONSTRAINTS] {
    let mut result = [ZERO; NUM_CONSTRAINTS];

    let op_flag = &OpFlags::new(&frame);

    enforce_constraints(&frame, &mut result, op_flag);

    result
}

/// Generates the correct current and next rows for the U32SPLIT operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_u32split_test_frame(a: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a u32split operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::U32split.op_code() as usize);

    // element splitted into two 32-bit limbs.
    let (c, b) = split_element(Felt::new(a));

    // Set the output. First and second element in the next frame should be the
    // upper and lower 32-bit limb of the first element in the current trace.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.next_mut()[STACK_TRACE_OFFSET] = c;
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = b;

    let (t1, t0) = split_u32_into_u16(b.as_int());
    let (t3, t2) = split_u32_into_u16(c.as_int());
    let m = (Felt::from(u32::MAX) - c).inv();

    // set the helper registers in the decoder.
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] = Felt::new(t0 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 1] = Felt::new(t1 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 2] = Felt::new(t2 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 3] = Felt::new(t3 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 4] = m;

    frame
}

/// Generates the correct current and next rows for the U32ADD operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_u32add_test_frame(a: u32, b: u32) -> EvaluationFrame<Felt> {
    // frame initialised with a u32add operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::U32add.op_code() as usize);

    // the sum of a and b is splitted into two 32-bit limbs.
    let (hi, lo) = split_element(Felt::new(a.into()) + Felt::new(b.into()));

    // Set the output. First and second element in the next frame should be the
    // upper and lower 32-bit limb of the sum of the first two elements in the current trace.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a.into());
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b.into());
    frame.next_mut()[STACK_TRACE_OFFSET] = hi;
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = lo;

    let (t1, t0) = split_u32_into_u16(lo.as_int());

    // set the helper registers in the decoder.
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] = Felt::new(t0 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 1] = Felt::new(t1 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 2] = hi;
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 3] = ZERO;
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 4] = ZERO;

    frame
}

/// Generates the correct current and next rows for the U32ADD3 operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_u32add3_test_frame(a: u32, b: u32, c: u32) -> EvaluationFrame<Felt> {
    // frame initialised with a u32add3 operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::U32add3.op_code() as usize);

    // the combined sum of a, b and c is splitted into two 32-bit limbs.
    let (hi, lo) = split_element(Felt::new(a.into()) + Felt::new(b.into()) + Felt::new(c.into()));

    // Set the output. First and second element in the next frame should be the
    // upper and lower 32-bit limb of the sum of the first three elements in the current trace.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a.into());
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b.into());
    frame.current_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(c.into());
    frame.next_mut()[STACK_TRACE_OFFSET] = hi;
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = lo;

    let (t1, t0) = split_u32_into_u16(lo.as_int());

    // set the helper registers in the decoder.
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] = Felt::new(t0 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 1] = Felt::new(t1 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 2] = hi;
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 3] = ZERO;
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 4] = ZERO;

    frame
}

/// Generates the correct current and next rows for the U32MUL operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_u32mul_test_frame(a: u32, b: u32) -> EvaluationFrame<Felt> {
    // frame initialised with a u32mul operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::U32mul.op_code() as usize);

    // element splitted into two 32-bit limbs.
    let (hi, lo) = split_element(Felt::new(a.into()) * Felt::new(b.into()));

    // Set the output. First and second element in the next frame should be the
    // upper and lower 32-bit limb of the product of the first two elements in the current trace.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a.into());
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b.into());
    frame.next_mut()[STACK_TRACE_OFFSET] = hi;
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = lo;

    let (t1, t0) = split_u32_into_u16(lo.as_int());
    let (t3, t2) = split_u32_into_u16(hi.as_int());
    let m = (Felt::from(u32::MAX) - hi).inv();

    // set the helper registers in the decoder.
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] = Felt::new(t0 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 1] = Felt::new(t1 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 2] = Felt::new(t2 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 3] = Felt::new(t3 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 4] = m;

    frame
}

/// Generates the correct current and next rows for the U32MADD operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_u32madd_test_frame(a: u32, b: u32, c: u32) -> EvaluationFrame<Felt> {
    // frame initialised with a u32madd operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::U32madd.op_code() as usize);

    // element splitted into two 32-bit limbs.
    let (hi, lo) = split_element(Felt::new((a as u64) * (b as u64) + (c as u64)));

    // Set the output. First and second element in the next frame should be the upper and
    // lower 32-bit limb of the addition of the third element with the product of the first
    //  two elements in the current trace.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a.into());
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b.into());
    frame.current_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(c.into());
    frame.next_mut()[STACK_TRACE_OFFSET] = hi;
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = lo;

    let (t1, t0) = split_u32_into_u16(lo.as_int());
    let (t3, t2) = split_u32_into_u16(hi.as_int());
    let m = (Felt::from(u32::MAX) - hi).inv();

    // set the helper registers in the decoder.
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] = Felt::new(t0 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 1] = Felt::new(t1 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 2] = Felt::new(t2 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 3] = Felt::new(t3 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 4] = m;

    frame
}

/// Generates the correct current and next rows for the U32SUB operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_u32sub_test_frame(a: u32, b: u32) -> EvaluationFrame<Felt> {
    // frame initialised with a u32sub operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::U32sub.op_code() as usize);

    // the sum of a and b is splitted into two 32-bit limbs.
    let (result, under) = b.overflowing_sub(a);

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a.into());
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b.into());
    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(under.into());
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(result.into());

    let (t1, t0) = split_u32_into_u16(result.into());

    // set the helper registers in the decoder.
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] = Felt::new(t0 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 1] = Felt::new(t1 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 2] = ZERO;
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 3] = ZERO;
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 4] = ZERO;

    frame
}

/// Generates the correct current and next rows for the U32DIV operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_u32div_test_frame(a: u32, b: u32) -> EvaluationFrame<Felt> {
    // frame initialised with a u32div operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::U32div.op_code() as usize);

    let q = b / a;
    let r = b - q * a;

    // These range checks help enforce that q <= b.
    let lo = b - q;
    // These range checks help enforce that r < a.
    let hi = a - r - 1;

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a.into());
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b.into());
    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(r.into());
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(q.into());

    let (t1, t0) = split_u32_into_u16(lo.into());
    let (t3, t2) = split_u32_into_u16(hi.into());

    // set the helper registers in the decoder.
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET] = Felt::new(t0 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 1] = Felt::new(t1 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 2] = Felt::new(t2 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 3] = Felt::new(t3 as u64);
    frame.current_mut()[DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + 4] = ZERO;

    frame
}

/// Splits an element into two field elements containing 32-bit integer values
pub fn split_element(value: Felt) -> (Felt, Felt) {
    let value = value.as_int();
    let lo = (value as u32) as u64;
    let hi = value >> 32;
    (Felt::new(hi), Felt::new(lo))
}

/// Splits an element into two 16 bit integer limbs. It assumes that the field element contains a
/// valid 32-bit integer value.
pub fn split_element_u32_into_u16(value: Felt) -> (Felt, Felt) {
    let (hi, lo) = split_u32_into_u16(value.as_int());
    (Felt::new(hi as u64), Felt::new(lo as u64))
}

/// Splits a u64 integer assumed to contain a 32-bit value into two u16 integers.
///
/// # Errors
/// Fails in debug mode if the provided value is not a 32-bit value.
pub fn split_u32_into_u16(value: u64) -> (u16, u16) {
    const U32MAX: u64 = u32::MAX as u64;
    debug_assert!(value <= U32MAX, "not a 32-bit value");

    let lo = value as u16;
    let hi = (value >> 16) as u16;

    (hi, lo)
}
