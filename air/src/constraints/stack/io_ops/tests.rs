use miden_core::{Felt, Operation, ZERO};
use winter_rand_utils::rand_value;

use super::{EvaluationFrame, NUM_CONSTRAINTS, enforce_constraints};
use crate::stack::{
    B0_COL_IDX, STACK_TRACE_OFFSET,
    op_flags::{OpFlags, generate_evaluation_frame},
};

// UNIT TESTS
// ================================================================================================

#[test]
fn test_sdepth_operation() {
    let expected = [ZERO; NUM_CONSTRAINTS];
    let depth = u64::from(rand_value::<u32>());

    let frame = get_sdepth_test_frame(depth);
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

/// Generates the correct current and next rows for the SDEPTH operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_sdepth_test_frame(depth: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a u32split operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::SDepth.op_code() as usize);

    // Set the output. The depth of the stack in the current trace should be the top
    // element in the next frame.
    frame.current_mut()[B0_COL_IDX] = Felt::new(depth);
    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(depth);

    frame
}
