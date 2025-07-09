use miden_core::{Felt, ONE, Operation, ZERO};
use proptest::prelude::*;

use super::{
    super::{CLK_COL_IDX, FMP_COL_IDX, STACK_TRACE_OFFSET},
    EvaluationFrame, NUM_CONSTRAINTS, enforce_constraints,
};
use crate::stack::op_flags::{OpFlags, generate_evaluation_frame};

// RANDOMIZED TESTS
// ================================================================================================

proptest! {

    // -------------------------------- FMPADD test -----------------------------------------------

    #[test]
    fn test_fmpadd_operation(a in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_fmpadd_test_frame(a);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- FMPUPDATE test --------------------------------------------

    #[test]
    fn test_fmpupdate_operation(a in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_fmpupdate_test_frame(a);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // -------------------------------- CLK test --------------------------------------------------

    #[test]
    fn test_clk_operation(a in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_clk_test_frame(a);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }
}

// UNIT TEST
// ================================================================================================

#[test]
fn test_assert_operation() {
    let expected = [ZERO; NUM_CONSTRAINTS];
    let frame = get_assert_test_frame();
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);
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

/// Generates the correct current and next rows for the FMPADD operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_fmpadd_test_frame(a: u64) -> EvaluationFrame<Felt> {
    // frame initialized with a fmpadd operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::FmpAdd.op_code() as usize);

    // Set the output. First element in the next frame should be incremented
    // by value present in the fmp register.
    frame.current_mut()[FMP_COL_IDX] = Felt::new(a);
    frame.next_mut()[STACK_TRACE_OFFSET] =
        frame.current()[STACK_TRACE_OFFSET] + frame.current()[FMP_COL_IDX];

    frame
}

/// Generates the correct current and next rows for the FMPUPDATE operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_fmpupdate_test_frame(a: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a fmpupdate operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::FmpUpdate.op_code() as usize);

    // Set the output. fmp register in the next frame should be incremented
    // by value present in the first element in the stack.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.next_mut()[FMP_COL_IDX] =
        frame.current()[STACK_TRACE_OFFSET] + frame.current()[FMP_COL_IDX];

    frame
}

/// Generates the correct current and next rows for the ASSERT operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_assert_test_frame() -> EvaluationFrame<Felt> {
    // frame initialized with a fmpupdate operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Assert(ZERO).op_code() as usize);

    // Set the output. The top element in the current frame of the stack should be ONE.
    frame.current_mut()[STACK_TRACE_OFFSET] = ONE;

    frame
}

/// Generates the correct current and next rows for the CLK operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_clk_test_frame(a: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a clk operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Clk.op_code() as usize);

    // Set the output. The top element in the next frame should be the current clock cycle value.
    frame.current_mut()[CLK_COL_IDX] = Felt::new(a);
    frame.next_mut()[STACK_TRACE_OFFSET] = frame.current()[CLK_COL_IDX];

    frame
}
