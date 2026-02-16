use alloc::vec;

use miden_core::{
    Felt, ONE, ZERO,
    mast::MastForest,
    program::{MIN_STACK_DEPTH, StackInputs},
};

use super::{op_assert, op_clk, op_sdepth};
use crate::{
    execution::operations::stack_ops::op_push,
    fast::{FastProcessor, NoopTracer},
    processor::{Processor, StackInterface, SystemInterface},
};

// TESTS
// ================================================================================================

#[test]
fn test_op_assert() {
    let program = MastForest::default();
    let mut tracer = NoopTracer;

    // Calling assert with a minimum stack should be ok, as long as the top value is ONE.
    let mut processor = FastProcessor::new(StackInputs::new(&[ONE]).unwrap());

    assert!(op_assert(&mut processor, ZERO, &program, &mut tracer).is_ok());
}

#[test]
fn test_op_sdepth() {
    let mut tracer = NoopTracer;

    // stack is empty
    let mut processor = FastProcessor::new(StackInputs::default());

    op_sdepth(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[MIN_STACK_DEPTH as u64]);
    assert_eq!(expected, processor.stack_top());
    assert_eq!(MIN_STACK_DEPTH as u32 + 1, processor.stack_depth());

    // stack has one item
    op_sdepth(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[MIN_STACK_DEPTH as u64 + 1, MIN_STACK_DEPTH as u64]);
    assert_eq!(expected, processor.stack_top());
    assert_eq!(MIN_STACK_DEPTH as u32 + 2, processor.stack_depth());

    // stack has 3 items - add a pad (push 0)
    Processor::stack_mut(&mut processor).increment_size().unwrap();
    processor.stack_write(0, ZERO);

    op_sdepth(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[
        MIN_STACK_DEPTH as u64 + 3,
        0,
        MIN_STACK_DEPTH as u64 + 1,
        MIN_STACK_DEPTH as u64,
    ]);
    assert_eq!(expected, processor.stack_top());
    assert_eq!(MIN_STACK_DEPTH as u32 + 4, processor.stack_depth());
}

#[test]
fn test_op_clk() {
    let mut tracer = NoopTracer;
    let mut processor = FastProcessor::new(StackInputs::default());

    // initial value of clk register should be 0
    //
    // Note though that in a real program, the first operation executed is never clk, since at least
    // one SPAN must be executed first.
    op_clk(&mut processor, &mut tracer).unwrap();
    processor.system_mut().increment_clock();
    let expected = build_expected(&[0]);
    assert_eq!(expected, processor.stack_top());

    // push another value onto the stack
    op_push(&mut processor, ONE, &mut tracer).unwrap();
    processor.system_mut().increment_clock();

    // clk is 2 after executing two operations
    op_clk(&mut processor, &mut tracer).unwrap();
    processor.system_mut().increment_clock();

    let expected = build_expected(&[2, 1, 0]);
    assert_eq!(expected, processor.stack_top());
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

/// Builds an expected stack state from the given values.
///
/// The values are provided in "stack order" (top of stack first), and the result is a Vec<Felt>
/// that can be compared with `processor.stack_top()`, where the top of the stack is at the
/// **last** index.
fn build_expected(values: &[u64]) -> alloc::vec::Vec<Felt> {
    let mut expected = vec![ZERO; 16];
    for (i, &value) in values.iter().enumerate() {
        // In the result, top of stack is at index 15, second at 14, etc.
        expected[15 - i] = Felt::new(value);
    }
    expected
}
