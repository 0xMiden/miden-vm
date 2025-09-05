use alloc::{string::ToString, sync::Arc};

use miden_air::ExecutionOptions;
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{Kernel, ONE, Operation, StackInputs, assert_matches};
use rstest::rstest;

use super::*;
use crate::{DefaultHost, Process, system::FMP_MAX};

mod advice_provider;
mod all_ops;
mod masm_consistency;
mod memory;

/// Makes sure that the bounds checking fails when expected.
#[ignore] // see https://github.com/0xMiden/miden-vm/pull/2094#discussion_r2310788436 for rationale
#[test]
fn test_stack_underflow_and_overflow_bounds_failure() {
    let mut host = DefaultHost::default();

    // Test underflow
    {
        // program 1: just enough drops as to not underflow, and then some swaps which don't change
        // stack size. Although theoretically we could allow operations that don't change the stack
        // size when just at the boundary of underflow, our current implementation is slightly
        // conservative and doesn't allow it. Hence in this program, we drop enough times to reach 1
        // from the underflow boundary, and then test that multiple swaps are allowed.
        const NUM_DROPS_NO_UNDERFLOW_SWAPS_ALLOWED: usize =
            INITIAL_STACK_TOP_IDX - MIN_STACK_DEPTH - 1;
        let ops = {
            let mut ops = vec![Operation::Drop; NUM_DROPS_NO_UNDERFLOW_SWAPS_ALLOWED];
            ops.extend(vec![Operation::Swap; 25]);

            ops
        };
        let program_no_underflow = simple_program_with_ops(ops);
        let result = FastProcessor::new(&[]).execute_sync(&program_no_underflow, &mut host);
        assert!(result.is_ok());

        // program 2: just enough drops as to not underflow, but no operation after.
        const NUM_DROPS_NO_UNDERFLOW: usize = NUM_DROPS_NO_UNDERFLOW_SWAPS_ALLOWED + 1;
        let program_no_underflow =
            simple_program_with_ops(vec![Operation::Drop; NUM_DROPS_NO_UNDERFLOW]);
        let result = FastProcessor::new(&[]).execute_sync(&program_no_underflow, &mut host);
        assert!(result.is_ok());

        // program 3: just enough drops to underflow
        const NUM_DROPS_WITH_UNDERFLOW: usize = NUM_DROPS_NO_UNDERFLOW + 1;
        let program_with_underflow =
            simple_program_with_ops(vec![Operation::Drop; NUM_DROPS_WITH_UNDERFLOW]);
        let err = FastProcessor::new(&[]).execute_sync(&program_with_underflow, &mut host);

        assert_matches!(err, Err(ExecutionError::FailedToExecuteProgram(_)));
    }

    // Test overflow (similar structure to the underflow part)
    {
        // program 1: just enough dups to get 1 away from the stack buffer overflow error, and check
        // that we can do some operations that don't change stack size there.
        const NUM_DUPS_NO_OVERFLOW_SWAPS_ALLOWED: usize =
            STACK_BUFFER_SIZE - INITIAL_STACK_TOP_IDX - 1;
        let ops = {
            let mut ops = vec![Operation::Dup0; NUM_DUPS_NO_OVERFLOW_SWAPS_ALLOWED];
            ops.extend(vec![Operation::Swap; 25]);
            // drop all the elements to not get an *output* stack overflow error (i.e. stack size is
            // 16 at the end)
            ops.extend(vec![Operation::Drop; NUM_DUPS_NO_OVERFLOW_SWAPS_ALLOWED]);

            ops
        };
        let program_no_overflow = simple_program_with_ops(ops);
        let result = FastProcessor::new(&[]).execute_sync(&program_no_overflow, &mut host);
        assert_matches!(result, Ok(_));

        // program 2: just enough dups to get 1 away from the stack buffer overflow error. Since we
        // can't drop the elements, we expect to end the program with a stack output overflow.
        // Two padding Noop inserted as of #2094 => const NUM_DUPS_NO_OVERFLOW: usize =
        // NUM_DUPS_NO_OVERFLOW_SWAPS_ALLOWED + 1 - 2;
        const NUM_DUPS_NO_OVERFLOW: usize = NUM_DUPS_NO_OVERFLOW_SWAPS_ALLOWED + 1;

        let ops = vec![Operation::Dup0; NUM_DUPS_NO_OVERFLOW];
        let program_output_overflow = simple_program_with_ops(ops);
        let result = FastProcessor::new(&[]).execute_sync(&program_output_overflow, &mut host);
        assert_matches!(result, Err(ExecutionError::OutputStackOverflow(_)));

        // program 3: just enough dups to get 1 away from the stack buffer overflow error. Since we
        // can't drop the elements, we expect to end the program with a stack output overflow.
        // Padding insertion in #2094 : const NUM_DUPS_WITH_OVERFLOW: usize = NUM_DUPS_NO_OVERFLOW +
        // 2;
        const NUM_DUPS_WITH_OVERFLOW: usize = NUM_DUPS_NO_OVERFLOW + 1;

        let ops = vec![Operation::Dup0; NUM_DUPS_WITH_OVERFLOW];
        let program_with_overflow = simple_program_with_ops(ops);
        let result = FastProcessor::new(&[]).execute_sync(&program_with_overflow, &mut host);
        assert_matches!(result, Err(ExecutionError::FailedToExecuteProgram(_)));
    }
}

/// In all these cases, the stack only grows or shrink by 1, and we have 2 spots on each side, so
/// execution never fails.
#[test]
fn test_stack_overflow_bounds_success() {
    let mut host = DefaultHost::default();

    // dup1, add
    {
        let program = simple_program_with_ops(vec![Operation::Dup1, Operation::Add]);
        FastProcessor::new(&[]).execute_sync(&program, &mut host).unwrap();
    }

    // the first add doesn't change the stack size, but the subsequent dup1 does
    {
        let program =
            simple_program_with_ops(vec![Operation::Add, Operation::Dup1, Operation::Add]);
        FastProcessor::new(&[]).execute_sync(&program, &mut host).unwrap();
    }

    // alternating add/dup1, with some swaps which don't change the stack size.
    // Note that add when stack size is 16 doesn't reduce the stack size.
    {
        let program = simple_program_with_ops(vec![
            // stack depth after: 16
            Operation::Add,
            // stack depth after: 17
            Operation::Dup1,
            // stack depth after: 16
            Operation::Add,
            // stack depth after: 17
            Operation::Dup1,
            // stack depth after: 17
            Operation::Swap,
            // stack depth after: 16
            Operation::Add,
            // stack depth after: 17
            Operation::Dup1,
            // stack depth after: 16
            Operation::Add,
            // stack depth after: 16
            Operation::Swap,
        ]);
        FastProcessor::new(&[]).execute_sync(&program, &mut host).unwrap();
    }
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
        let basic_block_id = program.add_block(vec![Operation::Add], None).unwrap();
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
        let foo_id = program.add_block(vec![Operation::Add], None).unwrap();

        // before call
        let push10_push20_id = program
            .add_block(vec![Operation::Push(10_u32.into()), Operation::Push(20_u32.into())], None)
            .unwrap();

        // call
        let call_node_id = program.add_call(foo_id).unwrap();
        // after call
        let swap_drop_swap_drop = program
            .add_block(
                vec![Operation::Swap, Operation::Drop, Operation::Swap, Operation::Drop],
                None,
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
        let root_id = program.add_block(ops, None).unwrap();
        program.make_root(root_id);

        Program::new(program.into(), root_id)
    };

    program
}
