use alloc::{string::ToString, sync::Arc};

use miden_air::ExecutionOptions;
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{Kernel, ONE, Operation, StackInputs, assert_matches};
use miden_utils_testing::build_test;
use rstest::rstest;

use super::*;
use crate::{DefaultHost, Process, system::FMP_MAX};

mod advice_provider;
mod all_ops;
mod fast_decorator_execution_tests;
mod masm_consistency;
mod memory;

/// Ensures that the stack is correctly reset in the buffer when the stack is reset in the buffer
/// as a result of underflow.
///
/// Also checks that 0s are correctly pulled from the stack overflow table when it's empty.
#[test]
fn test_reset_stack_in_buffer_from_drop() {
    let asm = format!(
        "
    begin
        repeat.{}
            movup.15 assertz
        end
    end
    ",
        INITIAL_STACK_TOP_IDX * 5
    );

    let initial_stack: [u64; 15] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    // we expect the final stack to be the initial stack unchanged; we reverse since in
    // `build_test!`, we call `StackInputs::new()`, which reverses the input stack.
    let final_stack: Vec<u64> = initial_stack.iter().cloned().rev().collect();

    let test = build_test!(&asm, &initial_stack);
    test.expect_stack(&final_stack);
}

/// Similar to `test_reset_stack_in_buffer_from_drop`, but here we test that the stack is correctly
/// reset in the buffer when the stack is reset in the buffer as a result of an execution context
/// being restored (and the overflow table restored back in the stack buffer).
#[test]
fn test_reset_stack_in_buffer_from_restore_context() {
    /// Number of values pushed onto the stack initially.
    const NUM_INITIAL_PUSHES: usize = INITIAL_STACK_TOP_IDX * 2;
    /// This moves the stack in the stack buffer to the left, close enough to the edge that when we
    /// restore the context, we will have to copy the overflow table values back into the stack
    /// buffer.
    const NUM_DROPS_IN_NEW_CONTEXT: usize = NUM_INITIAL_PUSHES + (INITIAL_STACK_TOP_IDX / 2);
    /// The called function will have dropped all 16 of the pushed values, so when we return to
    /// the caller, we expect the overflow table to contain all the original values, except for
    /// the 16 that were dropped by the callee.
    const NUM_EXPECTED_VALUES_IN_OVERFLOW: usize = NUM_INITIAL_PUSHES - MIN_STACK_DEPTH;

    let asm = format!(
        "
        proc.fn_in_new_context
            repeat.{NUM_DROPS_IN_NEW_CONTEXT} drop end
        end

    begin
        # Create a big overflow table
        repeat.{NUM_INITIAL_PUSHES} push.42 end

        # Call a proc to create a new execution context
        call.fn_in_new_context

        # Drop the stack top coming back from the called proc; these should all
        # be 0s pulled from the overflow table
        repeat.{MIN_STACK_DEPTH} drop end

        # Make sure that the rest of the pushed values were properly restored
        repeat.{NUM_EXPECTED_VALUES_IN_OVERFLOW} push.42 assert_eq end
    end
    "
    );

    let initial_stack: [u64; 15] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    // we expect the final stack to be the initial stack unchanged; we reverse since in
    // `build_test!`, we call `StackInputs::new()`, which reverses the input stack.
    let final_stack: Vec<u64> = initial_stack.iter().cloned().rev().collect();

    let test = build_test!(&asm, &initial_stack);
    test.expect_stack(&final_stack);
}

#[test]
fn test_fmp_add() {
    let mut host = DefaultHost::default();

    // set the initial FMP to a different value than the default
    let initial_fmp = Felt::new(FMP_MIN + 4);
    let stack_inputs = vec![1_u32.into(), 2_u32.into(), 3_u32.into()];
    let program = simple_program_with_ops(vec![Operation::FmpAdd]);

    let mut processor = FastProcessor::new(&stack_inputs);
    processor.fmp = initial_fmp;

    let stack_outputs = processor.execute_sync(&program, &mut host).unwrap();

    // Check that the top of the stack is the sum of the initial FMP and the top of the stack input
    let expected_top = initial_fmp + stack_inputs[2];
    assert_eq!(stack_outputs.stack_truncated(1)[0], expected_top);
}

#[test]
fn test_fmp_update() {
    let mut host = DefaultHost::default();

    // set the initial FMP to a different value than the default
    let initial_fmp = Felt::new(FMP_MIN + 4);
    let stack_inputs = vec![5_u32.into()];
    let program = simple_program_with_ops(vec![Operation::FmpUpdate]);

    let mut processor = FastProcessor::new(&stack_inputs);
    processor.fmp = initial_fmp;

    let stack_outputs = processor.execute_sync_mut(&program, &mut host).unwrap();

    // Check that the FMP is updated correctly
    let expected_fmp = initial_fmp + stack_inputs[0];
    assert_eq!(processor.fmp, expected_fmp);

    // Check that the top of the stack is popped correctly
    assert_eq!(stack_outputs.stack_truncated(0).len(), 0);
}

#[test]
fn test_fmp_update_fail() {
    let mut host = DefaultHost::default();

    // set the initial FMP to a value close to FMP_MAX
    let initial_fmp = Felt::new(FMP_MAX - 4);
    let stack_inputs = vec![5_u32.into()];
    let program = simple_program_with_ops(vec![Operation::FmpUpdate]);

    let mut processor = FastProcessor::new(&stack_inputs);
    processor.fmp = initial_fmp;

    let err = processor.execute_sync(&program, &mut host).unwrap_err();

    // Check that the error is due to the FMP exceeding FMP_MAX
    assert_matches!(err, ExecutionError::InvalidFmpValue(_, _));

    // set the initial FMP to a value close to FMP_MIN
    let initial_fmp = Felt::new(FMP_MIN + 4);
    let stack_inputs = vec![-Felt::new(5_u64)];
    let program = simple_program_with_ops(vec![Operation::FmpUpdate]);

    let mut processor = FastProcessor::new(&stack_inputs);
    processor.fmp = initial_fmp;

    let err = processor.execute_sync(&program, &mut host).unwrap_err();

    // Check that the error is due to the FMP being less than FMP_MIN
    assert_matches!(err, ExecutionError::InvalidFmpValue(_, _));
}

/// Tests that a syscall fails when the syscall target is not in the kernel.
#[test]
fn test_syscall_fail() {
    let mut host = DefaultHost::default();

    // set the initial FMP to a value close to FMP_MAX
    let stack_inputs = vec![5_u32.into()];
    let program = {
        let mut program = MastForest::new();
        let basic_block_id = program.add_block(vec![Operation::Add], Vec::new()).unwrap();
        let root_id = program.add_syscall(basic_block_id).unwrap();
        program.make_root(root_id);

        Program::new(program.into(), root_id)
    };

    let processor = FastProcessor::new(&stack_inputs);

    let err = processor.execute_sync(&program, &mut host).unwrap_err();

    // Check that the error is due to the syscall target not being in the kernel
    assert_matches!(
        err,
        ExecutionError::SyscallTargetNotInKernel { label: _, source_file: _, proc_root: _ }
    );
}

#[test]
fn test_assert() {
    let mut host = DefaultHost::default();

    // Case 1: the stack top is ONE
    {
        let stack_inputs = vec![ONE];
        let program = simple_program_with_ops(vec![Operation::Assert(ZERO)]);

        let processor = FastProcessor::new(&stack_inputs);
        let result = processor.execute_sync(&program, &mut host);

        // Check that the execution succeeds
        assert!(result.is_ok());
    }

    // Case 2: the stack top is not ONE
    {
        let stack_inputs = vec![ZERO];
        let program = simple_program_with_ops(vec![Operation::Assert(ZERO)]);

        let processor = FastProcessor::new(&stack_inputs);
        let err = processor.execute_sync(&program, &mut host).unwrap_err();

        // Check that the error is due to a failed assertion
        assert_matches!(err, ExecutionError::FailedAssertion { .. });
    }
}

/// Tests all valid inputs for the `And` operation.
///
/// The `test_basic_block()` test already covers the case where the stack top doesn't contain binary
/// values.
#[rstest]
#[case(vec![ZERO, ZERO], ZERO)]
#[case(vec![ZERO, ONE], ZERO)]
#[case(vec![ONE, ZERO], ZERO)]
#[case(vec![ONE, ONE], ONE)]
fn test_valid_combinations_and(#[case] stack_inputs: Vec<Felt>, #[case] expected_output: Felt) {
    let program = simple_program_with_ops(vec![Operation::And]);

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new(&stack_inputs);
    let stack_outputs = processor.execute_sync(&program, &mut host).unwrap();

    assert_eq!(stack_outputs.stack_truncated(1)[0], expected_output);
}

/// Tests all valid inputs for the `Or` operation.
///
/// The `test_basic_block()` test already covers the case where the stack top doesn't contain binary
/// values.
#[rstest]
#[case(vec![ZERO, ZERO], ZERO)]
#[case(vec![ZERO, ONE], ONE)]
#[case(vec![ONE, ZERO], ONE)]
#[case(vec![ONE, ONE], ONE)]
fn test_valid_combinations_or(#[case] stack_inputs: Vec<Felt>, #[case] expected_output: Felt) {
    let program = simple_program_with_ops(vec![Operation::Or]);

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new(&stack_inputs);
    let stack_outputs = processor.execute_sync(&program, &mut host).unwrap();

    assert_eq!(stack_outputs.stack_truncated(1)[0], expected_output);
}

/// Tests a valid set of inputs for the `Frie2f4` operation. This test reuses most of the logic of
/// `op_fri_ext2fold4` in `Process`.
#[test]
fn test_frie2f4() {
    let mut host = DefaultHost::default();

    // --- build stack inputs ---------------------------------------------
    let previous_value = [10_u32.into(), 11_u32.into()];
    let stack_inputs = vec![
        1_u32.into(),
        2_u32.into(),
        3_u32.into(),
        4_u32.into(),
        previous_value[0], // 4: 3rd query value and "previous value" (idx 13) must be the same
        previous_value[1], // 5: 3rd query value and "previous value" (idx 13) must be the same
        7_u32.into(),
        2_u32.into(), //7: domain segment, < 4
        9_u32.into(),
        10_u32.into(),
        11_u32.into(),
        12_u32.into(),
        13_u32.into(),
        previous_value[0], // 13: previous value
        previous_value[1], // 14: previous value
        16_u32.into(),
    ];

    let program =
        simple_program_with_ops(vec![Operation::Push(Felt::new(42_u64)), Operation::FriE2F4]);

    // fast processor
    let fast_processor = FastProcessor::new(&stack_inputs);
    let fast_stack_outputs = fast_processor.execute_sync(&program, &mut host).unwrap();

    // slow processor
    let mut slow_processor = Process::new(
        Kernel::default(),
        StackInputs::new(stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    );
    let slow_stack_outputs = slow_processor.execute(&program, &mut host).unwrap();

    assert_eq!(fast_stack_outputs, slow_stack_outputs);
}

#[test]
fn test_call_node_preserves_stack_overflow_table() {
    let mut host = DefaultHost::default();

    // equivalent to:
    // proc.foo
    //   add
    // end
    //
    // begin
    //   # stack: [1, 2, 3, 4, ..., 16]
    //   push.10 push.20
    //   # stack: [10, 20, 1, 2, ..., 15, 16], 15 and 16 on overflow
    //   call.foo
    //   # => stack: [30, 1, 2, 3, 4, 5, ..., 14, 0, 15, 16]
    //   swap drop swap drop
    //   # => stack: [30, 3, 4, 5, 6, ..., 14, 0, 15, 16]
    // end
    let program = {
        let mut program = MastForest::new();
        // foo proc
        let foo_id = program.add_block(vec![Operation::Add], Vec::new()).unwrap();

        // before call
        let push10_push20_id = program
            .add_block(
                vec![Operation::Push(10_u32.into()), Operation::Push(20_u32.into())],
                Vec::new(),
            )
            .unwrap();

        // call
        let call_node_id = program.add_call(foo_id).unwrap();
        // after call
        let swap_drop_swap_drop = program
            .add_block(
                vec![Operation::Swap, Operation::Drop, Operation::Swap, Operation::Drop],
                Vec::new(),
            )
            .unwrap();

        // joins
        let join_call_swap = program.add_join(call_node_id, swap_drop_swap_drop).unwrap();
        let root_id = program.add_join(push10_push20_id, join_call_swap).unwrap();

        program.make_root(root_id);

        Program::new(program.into(), root_id)
    };

    // initial stack: (top) [1, 2, 3, 4, ..., 16] (bot)
    let mut processor = FastProcessor::new(&[
        16_u32.into(),
        15_u32.into(),
        14_u32.into(),
        13_u32.into(),
        12_u32.into(),
        11_u32.into(),
        10_u32.into(),
        9_u32.into(),
        8_u32.into(),
        7_u32.into(),
        6_u32.into(),
        5_u32.into(),
        4_u32.into(),
        3_u32.into(),
        2_u32.into(),
        1_u32.into(),
    ]);

    // Execute the program
    let result = processor.execute_sync_mut(&program, &mut host).unwrap();

    assert_eq!(
        result.stack_truncated(16),
        &[
            // the sum from the call to foo
            30_u32.into(),
            // rest of the stack
            3_u32.into(),
            4_u32.into(),
            5_u32.into(),
            6_u32.into(),
            7_u32.into(),
            8_u32.into(),
            9_u32.into(),
            10_u32.into(),
            11_u32.into(),
            12_u32.into(),
            13_u32.into(),
            14_u32.into(),
            // the 0 shifted in during `foo`
            0_u32.into(),
            // the preserved overflow from before the call
            15_u32.into(),
            16_u32.into(),
        ]
    );
}

// TEST HELPERS
// -----------------------------------------------------------------------------------------------

fn simple_program_with_ops(ops: Vec<Operation>) -> Program {
    let program: Program = {
        let mut program = MastForest::new();
        let root_id = program.add_block(ops, Vec::new()).unwrap();
        program.make_root(root_id);

        Program::new(program.into(), root_id)
    };

    program
}
