use alloc::{string::ToString, sync::Arc};

use miden_air::ExecutionOptions;
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{
    Kernel, ONE, Operation, StackInputs, assert_matches,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
        MastForestContributor,
    },
};
use miden_utils_testing::build_test;
use rstest::rstest;

use super::*;
use crate::{DefaultHost, Process};

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
        proc fn_in_new_context
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

/// Tests that a syscall fails when the syscall target is not in the kernel.
#[test]
fn test_syscall_fail() {
    let mut host = DefaultHost::default();

    // set the initial FMP to a value close to FMP_MAX
    let stack_inputs = vec![5_u32.into()];
    let program = {
        let mut program = MastForest::new();
        let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut program)
            .unwrap();
        let root_id = CallNodeBuilder::new_syscall(basic_block_id)
            .add_to_forest(&mut program)
            .unwrap();
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
    // proc foo
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
        let foo_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut program)
            .unwrap();

        // before call
        let push10_push20_id = BasicBlockNodeBuilder::new(
            vec![Operation::Push(10_u32.into()), Operation::Push(20_u32.into())],
            Vec::new(),
        )
        .add_to_forest(&mut program)
        .unwrap();

        // call
        let call_node_id = CallNodeBuilder::new(foo_id).add_to_forest(&mut program).unwrap();
        // after call
        let swap_drop_swap_drop = BasicBlockNodeBuilder::new(
            vec![Operation::Swap, Operation::Drop, Operation::Swap, Operation::Drop],
            Vec::new(),
        )
        .add_to_forest(&mut program)
        .unwrap();

        // joins
        let join_call_swap = JoinNodeBuilder::new([call_node_id, swap_drop_swap_drop])
            .add_to_forest(&mut program)
            .unwrap();
        let root_id = JoinNodeBuilder::new([push10_push20_id, join_call_swap])
            .add_to_forest(&mut program)
            .unwrap();

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

// EXTERNAL NODE TESTS
// -----------------------------------------------------------------------------------------------

#[test]
fn test_external_node_decorator_sequencing() {
    let mut lib_forest = MastForest::new();

    // Add a decorator to the lib forest to track execution inside the external node
    let lib_decorator = Decorator::Trace(2);
    let lib_decorator_id = lib_forest.add_decorator(lib_decorator.clone()).unwrap();

    let lib_operations = [Operation::Push(1_u32.into()), Operation::Add];
    // Attach the decorator to the first operation (index 0)
    let lib_block_id =
        BasicBlockNodeBuilder::new(lib_operations.to_vec(), vec![(0, lib_decorator_id)])
            .add_to_forest(&mut lib_forest)
            .unwrap();
    lib_forest.make_root(lib_block_id);

    let mut main_forest = MastForest::new();
    let before_decorator = Decorator::Trace(1);
    let after_decorator = Decorator::Trace(3);
    let before_id = main_forest.add_decorator(before_decorator.clone()).unwrap();
    let after_id = main_forest.add_decorator(after_decorator.clone()).unwrap();

    let external_id = ExternalNodeBuilder::new(lib_forest[lib_block_id].digest())
        .with_before_enter([before_id])
        .with_after_exit([after_id])
        .add_to_forest(&mut main_forest)
        .unwrap();
    main_forest.make_root(external_id);

    let program = Program::new(main_forest.into(), external_id);
    let mut host =
        crate::test_utils::test_consistency_host::TestConsistencyHost::with_kernel_forest(
            Arc::new(lib_forest),
        );
    let processor = FastProcessor::new(&alloc::vec::Vec::new());

    let result = processor.execute_sync(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {:?}", result);

    // Verify all decorators executed
    assert_eq!(host.get_trace_count(1), 1, "before_enter decorator should execute exactly once");
    assert_eq!(
        host.get_trace_count(2),
        1,
        "external node decorator should execute exactly once"
    );
    assert_eq!(host.get_trace_count(3), 1, "after_exit decorator should execute exactly once");

    // More importantly, verify the complete execution order
    let execution_order = host.get_execution_order();
    assert_eq!(execution_order.len(), 3, "Should have exactly 3 trace events");
    assert_eq!(execution_order[0].0, 1, "before_enter should execute first");
    assert_eq!(execution_order[1].0, 2, "external node decorator should execute second");
    assert_eq!(execution_order[2].0, 3, "after_exit should execute last");

    // Verify that clock cycles are in strictly increasing order
    assert!(
        execution_order[1].1 > execution_order[0].1,
        "external node should execute after before_enter"
    );
    assert!(
        execution_order[2].1 > execution_order[1].1,
        "after_exit should execute after external node operations"
    );
}

// TEST HELPERS
// -----------------------------------------------------------------------------------------------

fn simple_program_with_ops(ops: Vec<Operation>) -> Program {
    let program: Program = {
        let mut program = MastForest::new();
        let root_id =
            BasicBlockNodeBuilder::new(ops, Vec::new()).add_to_forest(&mut program).unwrap();
        program.make_root(root_id);

        Program::new(program.into(), root_id)
    };

    program
}
