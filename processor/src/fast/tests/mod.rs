use alloc::{string::ToString, sync::Arc, vec};

use miden_air::trace::MIN_TRACE_LEN;
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{
    ONE, Operation, assert_matches,
    field::PrimeCharacteristicRing,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
        MastForestContributor,
    },
};
use miden_utils_testing::build_test;
use rstest::rstest;

use super::*;
use crate::{AdviceInputs, DefaultHost, OperationError};

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
    let final_stack: Vec<u64> = initial_stack.to_vec();

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
    let final_stack: Vec<u64> = initial_stack.to_vec();

    let test = build_test!(&asm, &initial_stack);
    test.expect_stack(&final_stack);
}

/// Tests that a syscall fails when the syscall target is not in the kernel.
#[test]
fn test_syscall_fail() {
    let mut host = DefaultHost::default();

    // set the initial FMP to a value close to FMP_MAX
    let stack_inputs = vec![Felt::from_u32(5)];
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
        ExecutionError::OperationError {
            err: OperationError::SyscallTargetNotInKernel { .. },
            ..
        }
    );
}

/// Tests that `ExecutionError::CycleLimitExceeded` is correctly emitted when a program exceeds the
/// number of allowed cycles.
#[test]
fn test_cycle_limit_exceeded() {
    use miden_air::{DEFAULT_CORE_TRACE_FRAGMENT_SIZE, ExecutionOptions};

    let mut host = DefaultHost::default();

    let options = ExecutionOptions::new(
        Some(MIN_TRACE_LEN as u32),
        MIN_TRACE_LEN as u32,
        DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
        false,
        false,
    )
    .unwrap();

    // Note: when executing, the processor executes `SPAN`, `END` and `HALT` operations, and hence
    // the total number of operations is certain to be greater than `MIN_TRACE_LEN`.
    let program = simple_program_with_ops(vec![Operation::Swap; MIN_TRACE_LEN]);

    let processor = FastProcessor::new_with_options(&[], AdviceInputs::default(), options);
    let err = processor.execute_sync(&program, &mut host).unwrap_err();

    assert_matches!(err, ExecutionError::CycleLimitExceeded(max_cycles) if max_cycles == MIN_TRACE_LEN as u32);
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
        assert_matches!(
            err,
            ExecutionError::OperationError {
                err: OperationError::FailedAssertion { .. },
                ..
            }
        );
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
    let stack_outputs = processor.execute_sync(&program, &mut host).unwrap().stack;

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
    let stack_outputs = processor.execute_sync(&program, &mut host).unwrap().stack;

    assert_eq!(stack_outputs.stack_truncated(1)[0], expected_output);
}

/// Tests a valid set of inputs for the `Frie2f4` operation. This test reuses most of the logic of
/// `op_fri_ext2fold4` in `Process`.
#[test]
fn test_frie2f4() {
    let mut host = DefaultHost::default();

    // --- build stack inputs ---------------------------------------------
    // FastProcessor::new expects inputs in natural order: first element goes to top.
    // After Push(42), the stack layout becomes:
    //   [v0, v1, v2, v3, v4, v5, v6, v7, f_pos, d_seg, poe, pe1, pe0, a1, a0, cptr, ...]
    //    ^0   1   2   3   4   5   6   7    8      9    10   11   12  13  14   15
    //
    // With d_seg=2, query_values[2] = (v4, v5) must equal prev_value = (pe0, pe1).
    let previous_value: [Felt; 2] = [Felt::from_u32(10), Felt::from_u32(11)];
    let stack_inputs = vec![
        Felt::from_u32(16), // pos 0 -> pos 1 (v1) after push
        Felt::from_u32(15), // pos 1 -> pos 2 (v2) after push
        Felt::from_u32(14), // pos 2 -> pos 3 (v3) after push
        previous_value[0],  // pos 3 -> pos 4 (v4) after push: must match pe0
        previous_value[1],  // pos 4 -> pos 5 (v5) after push: must match pe1
        Felt::from_u32(11), // pos 5 -> pos 6 (v6) after push
        Felt::from_u32(10), // pos 6 -> pos 7 (v7) after push
        Felt::from_u32(9),  // pos 7 -> pos 8 (f_pos) after push
        Felt::from_u32(2),  // pos 8 -> pos 9 (d_seg=2) after push
        Felt::from_u32(7),  // pos 9 -> pos 10 (poe) after push
        previous_value[1],  // pos 10 -> pos 11 (pe1) after push
        previous_value[0],  // pos 11 -> pos 12 (pe0) after push
        Felt::from_u32(3),  // pos 12 -> pos 13 (a1) after push
        Felt::from_u32(2),  // pos 13 -> pos 14 (a0) after push
        Felt::from_u32(1),  // pos 14 -> pos 15 (cptr) after push
        Felt::from_u32(0),  // pos 15 -> overflow after push
    ];

    let program =
        simple_program_with_ops(vec![Operation::Push(Felt::new(42_u64)), Operation::FriE2F4]);

    // fast processor
    let fast_processor = FastProcessor::new(&stack_inputs);
    let stack_outputs = fast_processor.execute_sync(&program, &mut host).unwrap().stack;

    insta::assert_debug_snapshot!(stack_outputs);
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
            vec![Operation::Push(Felt::from_u32(10)), Operation::Push(Felt::from_u32(20))],
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
        Felt::from_u32(1),
        Felt::from_u32(2),
        Felt::from_u32(3),
        Felt::from_u32(4),
        Felt::from_u32(5),
        Felt::from_u32(6),
        Felt::from_u32(7),
        Felt::from_u32(8),
        Felt::from_u32(9),
        Felt::from_u32(10),
        Felt::from_u32(11),
        Felt::from_u32(12),
        Felt::from_u32(13),
        Felt::from_u32(14),
        Felt::from_u32(15),
        Felt::from_u32(16),
    ]);

    // Execute the program
    let result = processor.execute_sync_mut(&program, &mut host).unwrap();

    assert_eq!(
        result.stack_truncated(16),
        &[
            // the sum from the call to foo
            Felt::from_u32(30),
            // rest of the stack
            Felt::from_u32(3),
            Felt::from_u32(4),
            Felt::from_u32(5),
            Felt::from_u32(6),
            Felt::from_u32(7),
            Felt::from_u32(8),
            Felt::from_u32(9),
            Felt::from_u32(10),
            Felt::from_u32(11),
            Felt::from_u32(12),
            Felt::from_u32(13),
            Felt::from_u32(14),
            // the 0 shifted in during `foo`
            Felt::from_u32(0),
            // the preserved overflow from before the call
            Felt::from_u32(15),
            Felt::from_u32(16),
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

    let lib_operations = [Operation::Push(Felt::from_u32(1)), Operation::Add];
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
    let processor = FastProcessor::new_debug(&alloc::vec::Vec::new(), AdviceInputs::default());

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
