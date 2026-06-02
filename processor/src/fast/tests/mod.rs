use alloc::{string::ToString, sync::Arc, vec};

use miden_air::trace::MIN_TRACE_LEN;
use miden_assembly::{
    Assembler, DefaultSourceManager, Path,
    ast::{Module, ModuleKind},
};
use miden_core::{
    ONE, Word, assert_matches,
    events::SystemEvent,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
        MastForestContributor, SplitNodeBuilder,
    },
    operations::Operation,
    program::StackInputs,
};
use miden_debug_types::{ByteIndex, Location, SourceContent, SourceManager, SourceSpan, Uri};
use miden_mast_package::debug_info::{
    DebugSourceAsmOp, DebugSourceGraphSection, DebugSourceMapSection, DebugSourceMastNode,
    DebugSourceMastNodeId, PackageDebugInfo,
};
use miden_utils_testing::{build_test, stack_inputs_from_ints};
use rstest::rstest;

use super::*;
use crate::{
    AdviceInputs, DefaultHost,
    operation::OperationError,
    processor::{StackInterface, SystemInterface},
};

mod advice_provider;
mod all_ops;
mod masm_consistency;
mod memory;

fn parse_kernel_source(
    source_manager: Arc<dyn miden_debug_types::SourceManager>,
    source: &str,
) -> Box<Module> {
    let mut parser = Module::parser(Some(ModuleKind::Kernel));
    parser.parse_str(Some(Path::KERNEL), source, source_manager).unwrap()
}

#[test]
fn stack_get_word_out_of_bounds_read() {
    // This event reads a word whose last felt is at index 16, which we will set to be out of bounds
    // in the stack buffer.
    const SYS_HQWORD_TO_MAP_EVENT_ID: u64 = SystemEvent::HqwordToMap.event_id().as_u64();

    let program_source = format!(
        "
    begin
        repeat.{} drop end

        push.{SYS_HQWORD_TO_MAP_EVENT_ID}
        swap
        drop

        emit
    end
    ",
        INITIAL_STACK_TOP_IDX - MIN_STACK_DEPTH
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let program = Assembler::new(source_manager)
        .assemble_program("program", &program_source)
        .expect("program should assemble")
        .unwrap_program();

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new(StackInputs::default());

    // Should not panic
    processor.execute_sync(&program, &mut host).unwrap();
}

#[test]
fn stack_get_safe_boundary() {
    let inputs = stack_inputs_from_ints(1..=16_u64);
    let processor = FastProcessor::new(inputs);

    // idx == stack_top_idx: out of bounds, should return ZERO.
    assert_eq!(processor.stack_get_safe(INITIAL_STACK_TOP_IDX), ZERO);

    // idx == stack_top_idx - 1: below the stack (buffer index 0 is zeroed), should return ZERO.
    assert_eq!(processor.stack_get_safe(INITIAL_STACK_TOP_IDX - 1), ZERO);

    // idx == stack_top_idx + 1: out of bounds, should return ZERO.
    assert_eq!(processor.stack_get_safe(INITIAL_STACK_TOP_IDX + 1), ZERO);

    // idx == usize::MAX: far out of bounds, should return ZERO.
    assert_eq!(processor.stack_get_safe(usize::MAX), ZERO);
}

#[test]
fn stack_get_word_safe_partial_read() {
    let inputs = stack_inputs_from_ints(1..=16_u64);
    let processor = FastProcessor::new(inputs);

    // The stack has 16 elements (indices 0..=15). Reading a word at start_idx=15 means we want
    // elements at indices 15, 16, 17, 18. Only index 15 is valid; the rest should be ZERO.
    let word = processor.stack_get_word_safe(15);
    // Index 15 is the bottom of the stack (value 16, since inputs are in stack order: top first).
    assert_eq!(word, [Felt::new_unchecked(16), ZERO, ZERO, ZERO].into());
}

#[test]
fn stack_get_word_safe_usize_max() {
    let processor = FastProcessor::new(StackInputs::default());
    let word = processor.stack_get_word_safe(usize::MAX);
    assert_eq!(word, Word::default());
}

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

    let test = build_test!(asm, &initial_stack);
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

    let test = build_test!(asm, &initial_stack);
    test.expect_stack(&final_stack);
}

/// Tests that a syscall fails when the syscall target is not in the kernel.
#[test]
fn test_syscall_fail() {
    let mut host = DefaultHost::default();

    // set the initial FMP to a value close to FMP_MAX
    let stack_inputs = StackInputs::new(&[Felt::from_u32(5)]).unwrap();
    let program = {
        let mut program = MastForest::new();
        let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut program)
            .unwrap();
        let root_id = CallNodeBuilder::new_syscall(basic_block_id)
            .add_to_forest(&mut program)
            .unwrap();
        program.make_root(root_id);

        Program::new(program.into(), root_id)
    };

    let processor = FastProcessor::new(stack_inputs);

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

#[test]
fn package_source_debug_execution_distinguishes_same_exec_node_split_children() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::from_u32(7))])
        .add_to_forest(&mut forest)
        .unwrap();
    let root_id = SplitNodeBuilder::new([block_id, block_id]).add_to_forest(&mut forest).unwrap();
    forest.make_root(root_id);
    let program = Program::new(forest.into(), root_id);

    let source_manager = Arc::new(DefaultSourceManager::default());
    let uri = Uri::new("file://pkg/same-node.masm");
    let source_file = source_manager.load_from_raw_parts(
        uri.clone(),
        SourceContent::new("masm", uri.clone(), "true;\nfalse;\n"),
    );
    let mut host = DefaultHost::default().with_source_manager(source_manager);

    let source_root = DebugSourceMastNodeId::from(0);
    let source_true = DebugSourceMastNodeId::from(1);
    let source_false = DebugSourceMastNodeId::from(2);
    let package_debug_info = PackageDebugInfo {
        source_graph: Some(DebugSourceGraphSection {
            nodes: vec![
                DebugSourceMastNode::new(root_id, vec![source_true, source_false], 0, 1),
                DebugSourceMastNode::new(block_id, vec![], 0, 1),
                DebugSourceMastNode::new(block_id, vec![], 0, 1),
            ],
            roots: vec![source_root],
            ..DebugSourceGraphSection::new()
        }),
        source_map: Some(DebugSourceMapSection {
            asm_ops: vec![
                DebugSourceAsmOp::new(
                    source_true,
                    0,
                    Some(Location::new(uri.clone(), ByteIndex::new(0), ByteIndex::new(5))),
                    "true_branch".into(),
                    "assert".into(),
                    1,
                ),
                DebugSourceAsmOp::new(
                    source_false,
                    0,
                    Some(Location::new(uri, ByteIndex::new(6), ByteIndex::new(12))),
                    "false_branch".into(),
                    "assert".into(),
                    2,
                ),
            ],
            ..DebugSourceMapSection::new()
        }),
        ..PackageDebugInfo::default()
    };

    let processor = FastProcessor::new(StackInputs::default());
    let err = processor
        .execute_with_package_debug_info_sync(&program, &package_debug_info, &mut host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::FailedAssertion { err_code, .. },
        } if label == SourceSpan::new(source_file.id(), 6u32..12)
            && actual_source_file.id() == source_file.id()
            && err_code == Felt::from_u32(7)
    );
}

#[test]
fn package_source_debug_execution_ignores_ambiguous_local_dyn_root() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let program = Assembler::new(source_manager)
        .assemble_program(
            "program",
            "
        proc foo
            assert
        end

        begin
            procref.foo mem_storew_le.100 dropw push.100
            dynexec
        end
        ",
        )
        .expect("program should assemble")
        .unwrap_program();

    let entrypoint = program.entrypoint();
    let callee_root = program
        .mast_forest()
        .procedure_roots()
        .iter()
        .copied()
        .find(|&root| root != entrypoint)
        .expect("program should contain a callee procedure root");

    let source_entry = DebugSourceMastNodeId::from(0);
    let source_callee_a = DebugSourceMastNodeId::from(1);
    let source_callee_b = DebugSourceMastNodeId::from(2);
    let package_debug_info = PackageDebugInfo {
        source_graph: Some(DebugSourceGraphSection {
            nodes: vec![
                DebugSourceMastNode::new(entrypoint, vec![], 0, 1),
                DebugSourceMastNode::new(callee_root, vec![], 0, 1),
                DebugSourceMastNode::new(callee_root, vec![], 0, 1),
            ],
            roots: vec![source_entry, source_callee_a, source_callee_b],
            ..DebugSourceGraphSection::new()
        }),
        ..PackageDebugInfo::default()
    };

    let processor = FastProcessor::new(StackInputs::default());
    let err = processor
        .execute_with_package_debug_info_sync(
            &program,
            &package_debug_info,
            &mut DefaultHost::default(),
        )
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: None,
            err: OperationError::FailedAssertion { err_code, .. },
        } if label == SourceSpan::UNKNOWN && err_code == Felt::ZERO
    );
}

fn missing_external_package_source_debug_fixture() -> (
    Program,
    PackageDebugInfo,
    DefaultHost,
    SourceSpan,
    Arc<miden_debug_types::SourceFile>,
) {
    let mut forest = MastForest::new();
    let missing_digest = Word::from([ONE, ONE, ONE, ONE]);
    let external_id = ExternalNodeBuilder::new(missing_digest).add_to_forest(&mut forest).unwrap();
    let root_id = CallNodeBuilder::new(external_id).add_to_forest(&mut forest).unwrap();
    forest.make_root(root_id);
    let program = Program::new(forest.into(), root_id);

    let source_manager = Arc::new(DefaultSourceManager::default());
    let uri = Uri::new("file://pkg/missing-external.masm");
    let source_file = source_manager.load_from_raw_parts(
        uri.clone(),
        SourceContent::new("masm", uri.clone(), "begin\n    call.missing::proc\nend\n"),
    );
    let host = DefaultHost::default().with_source_manager(source_manager);

    let source_root = DebugSourceMastNodeId::from(0);
    let source_external = DebugSourceMastNodeId::from(1);
    let expected_span = SourceSpan::new(source_file.id(), 10u32..28);
    let package_debug_info = PackageDebugInfo {
        source_graph: Some(DebugSourceGraphSection {
            nodes: vec![
                DebugSourceMastNode::new(root_id, vec![source_external], 0, 1),
                DebugSourceMastNode::new(external_id, vec![], 0, 1),
            ],
            roots: vec![source_root],
            ..DebugSourceGraphSection::new()
        }),
        source_map: Some(DebugSourceMapSection {
            asm_ops: vec![DebugSourceAsmOp::new(
                source_external,
                0,
                Some(Location::new(uri, ByteIndex::new(10), ByteIndex::new(28))),
                "external_call".into(),
                "call.missing::proc".into(),
                2,
            )],
            ..DebugSourceMapSection::new()
        }),
        ..PackageDebugInfo::default()
    };

    (program, package_debug_info, host, expected_span, source_file)
}

#[test]
fn package_source_debug_missing_external_preserves_external_source_span() {
    let (program, package_debug_info, mut host, expected_span, source_file) =
        missing_external_package_source_debug_fixture();

    let err = FastProcessor::new(StackInputs::default())
        .execute_with_package_debug_info_sync(&program, &package_debug_info, &mut host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::ProcedureNotFound {
            label,
            source_file: Some(actual_source_file),
            ..
        } if label == expected_span && actual_source_file.id() == source_file.id()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn package_source_debug_missing_external_preserves_external_source_span_async() {
    let (program, package_debug_info, mut host, expected_span, source_file) =
        missing_external_package_source_debug_fixture();

    let err = FastProcessor::new(StackInputs::default())
        .execute_with_package_debug_info(&program, &package_debug_info, &mut host)
        .await
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::ProcedureNotFound {
            label,
            source_file: Some(actual_source_file),
            ..
        } if label == expected_span && actual_source_file.id() == source_file.id()
    );
}

#[test]
fn test_stack_write_word_max_start_idx() {
    let stack_inputs = StackInputs::new(&[]).unwrap();
    let mut processor = FastProcessor::new(stack_inputs);

    let word =
        Word::from([Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)]);
    let start_idx = MIN_STACK_DEPTH - WORD_SIZE;

    processor.stack_write_word(start_idx, &word);

    assert_eq!(processor.stack_get_word(start_idx), word);
}

/// Tests that `ExecutionError::CycleLimitExceeded` is correctly emitted when a program exceeds the
/// number of allowed cycles.
#[test]
fn test_cycle_limit_exceeded() {
    let mut host = DefaultHost::default();

    let options = ExecutionOptions::new(
        Some(MIN_TRACE_LEN as u32),
        MIN_TRACE_LEN as u32,
        ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
    )
    .unwrap();

    // Note: when executing, the processor executes `SPAN`, `END` and `HALT` operations, and hence
    // the total number of operations is certain to be greater than `MIN_TRACE_LEN`.
    let program = simple_program_with_ops(vec![Operation::Swap; MIN_TRACE_LEN]);

    let processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");
    let err = processor.execute_sync(&program, &mut host).unwrap_err();

    assert_matches!(err, ExecutionError::CycleLimitExceeded(max_cycles) if max_cycles == MIN_TRACE_LEN as u32);
}

/// Tests that a program using exactly `max_cycles` cycles succeeds.
///
/// This is a regression test for the off-by-one error where the cycle limit check used `>=`
/// instead of `>`, causing programs that used exactly `max_cycles` cycles to fail.
#[test]
fn test_cycle_limit_exactly_max_cycles_succeeds() {
    let mut host = DefaultHost::default();

    // With 2018 Noop operations, the program uses exactly MIN_TRACE_LEN (2048) cycles.
    // 2018 operations result in 29 operation batches, and this requires executing 28 `RESPAN`
    // operations. So, we get 2018 + 28 = 2046. All of these operations are executed in a single
    // basic block, and we need 2 more operations for block start (`BEGIN`) and block end (`END`).
    // Before the fix (clk >= max_cycles): this failed because 2048 >= 2048 is true.
    // After the fix (clk > max_cycles): this succeeds because 2048 > 2048 is false.
    const NUM_OPS: usize = 2018;
    let program = simple_program_with_ops(vec![Operation::Noop; NUM_OPS]);

    let options = ExecutionOptions::new(
        Some(2048),
        MIN_TRACE_LEN as u32,
        ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
    )
    .unwrap();

    let processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");
    let result = processor.execute_sync(&program, &mut host);

    // The program should succeed since it uses exactly max_cycles cycles.
    assert!(
        result.is_ok(),
        "Program using exactly max_cycles should succeed, but got: {result:?}"
    );
}

#[test]
fn test_assert() {
    let mut host = DefaultHost::default();

    // Case 1: the stack top is ONE
    {
        let stack_inputs = StackInputs::new(&[ONE]).unwrap();
        let program = simple_program_with_ops(vec![Operation::Assert(ZERO)]);

        let processor = FastProcessor::new(stack_inputs);
        let result = processor.execute_sync(&program, &mut host);

        // Check that the execution succeeds
        assert!(result.is_ok());
    }

    // Case 2: the stack top is not ONE
    {
        let stack_inputs = StackInputs::new(&[ZERO]).unwrap();
        let program = simple_program_with_ops(vec![Operation::Assert(ZERO)]);

        let processor = FastProcessor::new(stack_inputs);
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
    let processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
    let stack_outputs = processor.execute_sync(&program, &mut host).unwrap().stack;

    assert_eq!(stack_outputs.get_num_elements(1)[0], expected_output);
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
    let processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
    let stack_outputs = processor.execute_sync(&program, &mut host).unwrap().stack;

    assert_eq!(stack_outputs.get_num_elements(1)[0], expected_output);
}

/// Tests a valid set of inputs for the `Frie2f4` operation. This test reuses most of the logic of
/// `op_fri_ext2fold4` in `Process`.
#[test]
fn test_frie2f4() {
    let mut host = DefaultHost::default();

    // --- build stack inputs ---------------------------------------------
    // FastProcessor::new expects inputs in natural order: first element goes to top.
    // After Push(42), the stack layout becomes:
    //   [v0, v1, v2, v3, v4, v5, v6, v7, f_pos, p, poe, pe0, pe1, a0, a1, cptr, ...]
    //    ^0   1   2   3   4   5   6   7    8     9  10   11   12   13  14   15
    //
    // p is the bit-reversed tree index; the instruction computes d_seg = p & 3.
    // With p=38 (d_seg=2, f_pos=9), query_values[2] = (v4, v5) must equal prev_value = (pe0, pe1).
    let previous_value: [Felt; 2] = [Felt::from_u32(10), Felt::from_u32(11)];
    let stack_inputs = StackInputs::new(&[
        Felt::from_u32(16), // pos 0 -> pos 1 (v1) after push
        Felt::from_u32(15), // pos 1 -> pos 2 (v2) after push
        Felt::from_u32(14), // pos 2 -> pos 3 (v3) after push
        previous_value[0],  // pos 3 -> pos 4 (v4) after push: must match pe0
        previous_value[1],  // pos 4 -> pos 5 (v5) after push: must match pe1
        Felt::from_u32(11), // pos 5 -> pos 6 (v6) after push
        Felt::from_u32(10), // pos 6 -> pos 7 (v7) after push
        Felt::from_u32(9),  // pos 7 -> pos 8 (f_pos) after push
        Felt::from_u32(38), // pos 8 -> pos 9 (p=4*9+2=38, d_seg=2) after push
        Felt::from_u32(7),  // pos 9 -> pos 10 (poe) after push
        previous_value[0],  // pos 10 -> pos 11 (pe0) after push
        previous_value[1],  // pos 11 -> pos 12 (pe1) after push
        Felt::from_u32(2),  // pos 12 -> pos 13 (a0) after push
        Felt::from_u32(3),  // pos 13 -> pos 14 (a1) after push
        Felt::from_u32(1),  // pos 14 -> pos 15 (cptr) after push
        Felt::from_u32(0),  // pos 15 -> overflow after push
    ])
    .unwrap();

    let program = simple_program_with_ops(vec![
        Operation::Push(Felt::new_unchecked(42_u64)),
        Operation::FriE2F4,
    ]);

    // fast processor
    let fast_processor = FastProcessor::new(stack_inputs);
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
        let foo_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut program)
            .unwrap();

        // before call
        let push10_push20_id = BasicBlockNodeBuilder::new(vec![
            Operation::Push(Felt::from_u32(10)),
            Operation::Push(Felt::from_u32(20)),
        ])
        .add_to_forest(&mut program)
        .unwrap();

        // call
        let call_node_id = CallNodeBuilder::new(foo_id).add_to_forest(&mut program).unwrap();
        // after call
        let swap_drop_swap_drop = BasicBlockNodeBuilder::new(vec![
            Operation::Swap,
            Operation::Drop,
            Operation::Swap,
            Operation::Drop,
        ])
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
    let mut processor = FastProcessor::new(
        StackInputs::new(&[
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
        ])
        .unwrap(),
    );

    // Execute the program
    let result = processor.execute_mut_sync(&program, &mut host).unwrap();

    assert_eq!(
        result.get_num_elements(16),
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

#[test]
fn stack_depth_default_limit_exact_boundary_succeeds() {
    let mut host = DefaultHost::default();

    let pushes_to_default_limit = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH;
    let program = simple_program_with_ops(pad_then_drop_ops(pushes_to_default_limit));

    FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .expect("using the full default stack depth limit should succeed");
}

#[test]
fn stack_depth_default_limit_exceeded_returns_typed_error() {
    let mut host = DefaultHost::default();

    let pushes_past_default_limit = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + 1;
    let program = simple_program_with_ops(vec![Operation::Pad; pushes_past_default_limit]);

    let err = FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .expect_err("pushing past the default stack depth limit should fail");

    assert_matches!(
        err,
        ExecutionError::StackDepthLimitExceeded {
            depth,
            max: DEFAULT_MAX_STACK_DEPTH,
        } if depth == DEFAULT_MAX_STACK_DEPTH + 1
    );
}

#[test]
fn stack_depth_small_custom_limit_fails_before_buffer_growth() {
    let mut host = DefaultHost::default();
    let max_stack_depth = MIN_STACK_DEPTH + 1;
    let program = simple_program_with_ops(vec![Operation::Pad; 2]);
    let options = ExecutionOptions::default().with_max_stack_depth(max_stack_depth).unwrap();

    let err =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits")
            .execute_sync(&program, &mut host)
            .expect_err("small configured stack depth limit should fail before buffer growth");

    assert_matches!(
        err,
        ExecutionError::StackDepthLimitExceeded {
            depth,
            max,
        } if depth == max_stack_depth + 1 && max == max_stack_depth
    );
}

#[test]
fn issue_2818_fast_processor_stack_grows_past_initial_buffer_by_multiple_elements() {
    const GROWTH_MARGIN: usize = 4;

    let mut host = DefaultHost::default();

    let pushes_past_initial_buffer = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + GROWTH_MARGIN;
    let program = simple_program_with_ops(pad_then_drop_ops(pushes_past_initial_buffer));
    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH + GROWTH_MARGIN)
        .unwrap();

    FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
        .expect("processor advice inputs should fit advice map limits")
        .execute_sync(&program, &mut host)
        .expect("stack growth multiple elements past the initial buffer should succeed");
}

#[test]
fn issue_2818_traced_execution_stack_grows_past_initial_buffer() {
    const GROWTH_MARGIN: usize = 2;

    let mut host = DefaultHost::default();

    let pushes_past_initial_buffer = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + GROWTH_MARGIN;
    let program = simple_program_with_ops(pad_then_drop_ops(pushes_past_initial_buffer));
    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH + GROWTH_MARGIN)
        .unwrap();

    let trace_inputs =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits")
            .execute_trace_inputs_sync(&program, &mut host)
            .expect("traced execution should grow the stack buffer past the initial buffer");

    crate::trace::build_trace(trace_inputs)
        .expect("trace replay should accept the same operand stack depth limit");
}

#[test]
fn issue_2818_step_execution_stack_grows_past_initial_buffer() {
    const GROWTH_MARGIN: usize = 2;

    let mut host = DefaultHost::default();

    let pushes_past_initial_buffer = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + GROWTH_MARGIN;
    let program = simple_program_with_ops(pad_then_drop_ops(pushes_past_initial_buffer));
    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH + GROWTH_MARGIN)
        .unwrap();

    FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
        .expect("processor advice inputs should fit advice map limits")
        .execute_by_step_sync(&program, &mut host)
        .expect("step execution should grow the stack buffer past the initial buffer");
}

#[test]
fn issue_2818_restore_context_grows_stack_buffer_for_suspended_caller() {
    let caller_overflow_len = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + 1;
    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH + 1)
        .unwrap();
    let mut processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");

    assert_eq!(processor.stack.len(), INITIAL_STACK_BUFFER_SIZE);
    processor
        .stack_overflow_save_stack
        .push(vec![Felt::from_u32(42); caller_overflow_len]);
    processor.system_call_state_stack.push(SystemCallState {
        ctx: processor.ctx,
        caller_hash: processor.caller_hash,
    });

    // The active callee context is still at the minimum stack depth and the storage has not grown.
    // Restoring this suspended caller is what requires moving the active stack and growing storage.
    StackInterface::restore_context(&mut processor)
        .expect("restoring a suspended caller should grow the stack buffer when needed");
    SystemInterface::restore_call_state(&mut processor)
        .expect("restoring system call state should succeed");
    assert!(
        processor.stack.len() > INITIAL_STACK_BUFFER_SIZE,
        "context restore should have grown the stack buffer"
    );
    assert_eq!(processor.stack_size(), MIN_STACK_DEPTH + caller_overflow_len);
}

#[test]
fn stack_buffer_is_not_preallocated_to_operand_stack_depth_limit() {
    const GROWTH_MARGIN: usize = 2;

    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH + GROWTH_MARGIN)
        .unwrap();
    let mut processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");

    assert_eq!(
        processor.stack.len(),
        INITIAL_STACK_BUFFER_SIZE,
        "processor should start with the initial stack buffer, not the full depth limit"
    );

    let mut host = DefaultHost::default();
    processor
        .execute_mut_sync(
            &simple_program_with_ops(vec![Operation::Pad, Operation::Drop]),
            &mut host,
        )
        .expect("ordinary shallow stack use should succeed");
    assert_eq!(
        processor.stack.len(),
        INITIAL_STACK_BUFFER_SIZE,
        "ordinary shallow stack use should not grow the buffer"
    );

    let pushes_past_initial_buffer = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + GROWTH_MARGIN;
    let program = simple_program_with_ops(pad_then_drop_ops(pushes_past_initial_buffer));
    let mut processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");
    let mut host = DefaultHost::default();

    processor
        .execute_mut_sync(&program, &mut host)
        .expect("deep stack use should grow the buffer on demand");
    assert!(
        processor.stack.len() > INITIAL_STACK_BUFFER_SIZE,
        "deep stack use should grow the buffer only when needed"
    );
}

#[test]
fn stack_growth_recenters_shallow_context_when_requested_len_exceeds_allocation_cap() {
    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH)
        .unwrap();
    let mut processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");

    // This models a callee that has only the minimum live stack depth, but is still positioned at
    // the end of the current stack buffer after the caller filled the buffer and entered a new
    // context. The next push requests one slot past the allocation cap using the old position, but
    // growth can still succeed because it recenters the live stack before the push.
    processor.stack_top_idx = INITIAL_STACK_BUFFER_SIZE - 1;
    processor.stack_bot_idx = processor.stack_top_idx - MIN_STACK_DEPTH;

    processor
        .ensure_stack_capacity_for_push()
        .expect("recentered shallow context push should fit within the stack depth limit");

    assert_eq!(processor.stack_bot_idx, STACK_BUFFER_BASE_IDX);
    assert_eq!(processor.stack_top_idx, STACK_BUFFER_BASE_IDX + MIN_STACK_DEPTH);
    assert_eq!(processor.stack.len(), INITIAL_STACK_BUFFER_SIZE);
}

fn previous_growth_len(
    stack_len: usize,
    live_len: usize,
    requested_min_len: usize,
    max_len: usize,
) -> usize {
    let recentered_min_len = STACK_BUFFER_BASE_IDX.saturating_add(live_len).saturating_add(2);
    let required_len = requested_min_len.min(max_len).max(recentered_min_len);

    let mut new_len = stack_len;
    while new_len < required_len {
        let next_len = new_len.saturating_mul(2);
        if next_len <= new_len {
            return required_len;
        }
        new_len = next_len.min(max_len);
    }

    new_len
}

fn new_growth_len(live_len: usize, requested_min_len: usize, max_len: usize) -> usize {
    let target_len = STACK_BUFFER_BASE_IDX
        .saturating_add(live_len)
        .saturating_add(2)
        .saturating_mul(2);

    target_len.max(requested_min_len).min(max_len)
}

#[derive(Debug, PartialEq, Eq)]
struct GrowthSemantics {
    new_stack_bot_idx: usize,
    new_stack_top_idx: usize,
    covers_requested_len: bool,
    covers_recentered_len: bool,
    within_max_len: bool,
}

fn growth_semantics(
    new_len: usize,
    live_len: usize,
    requested_min_len: usize,
    max_len: usize,
) -> GrowthSemantics {
    let recentered_min_len = STACK_BUFFER_BASE_IDX.saturating_add(live_len).saturating_add(2);

    GrowthSemantics {
        new_stack_bot_idx: STACK_BUFFER_BASE_IDX,
        new_stack_top_idx: STACK_BUFFER_BASE_IDX + live_len,
        covers_requested_len: new_len >= requested_min_len,
        covers_recentered_len: new_len >= recentered_min_len,
        within_max_len: new_len <= max_len,
    }
}

#[test]
fn new_stack_growth_algorithm_is_vm_equivalent_to_previous_algorithm() {
    let max_depth = DEFAULT_MAX_STACK_DEPTH * 4;
    let max_len = STACK_BUFFER_BASE_IDX.saturating_add(max_depth).saturating_add(1);

    for stack_len in [INITIAL_STACK_BUFFER_SIZE, INITIAL_STACK_BUFFER_SIZE * 2] {
        // Push growth is called when the next push would need one slot past the current buffer.
        let live_len = stack_len - STACK_BUFFER_BASE_IDX - 1;
        let requested_min_len = stack_len + 1;

        let previous_len = previous_growth_len(stack_len, live_len, requested_min_len, max_len);
        let new_len = new_growth_len(live_len, requested_min_len, max_len);

        assert_eq!(
            growth_semantics(previous_len, live_len, requested_min_len, max_len),
            growth_semantics(new_len, live_len, requested_min_len, max_len)
        );
    }

    for overflow_len in 0..=(max_depth - MIN_STACK_DEPTH) {
        // Restore growth is called from a callee with only the minimum live stack, but the
        // requested length must cover the caller overflow stack being restored.
        let requested_min_len =
            INITIAL_STACK_TOP_IDX.saturating_add(overflow_len).saturating_add(1);
        let previous_len = previous_growth_len(
            INITIAL_STACK_BUFFER_SIZE,
            MIN_STACK_DEPTH,
            requested_min_len,
            max_len,
        );
        let new_len = new_growth_len(MIN_STACK_DEPTH, requested_min_len, max_len);

        assert_eq!(
            growth_semantics(previous_len, MIN_STACK_DEPTH, requested_min_len, max_len),
            growth_semantics(new_len, MIN_STACK_DEPTH, requested_min_len, max_len)
        );
    }
}

#[test]
fn new_stack_growth_algorithm_allocation_differences_are_intentional() {
    let max_depth = DEFAULT_MAX_STACK_DEPTH * 4;
    let max_len = STACK_BUFFER_BASE_IDX.saturating_add(max_depth).saturating_add(1);

    let push_live_len = INITIAL_STACK_BUFFER_SIZE - STACK_BUFFER_BASE_IDX - 1;
    let push_requested_min_len = INITIAL_STACK_BUFFER_SIZE + 1;
    assert_eq!(
        previous_growth_len(
            INITIAL_STACK_BUFFER_SIZE,
            push_live_len,
            push_requested_min_len,
            max_len,
        ),
        INITIAL_STACK_BUFFER_SIZE * 2
    );
    assert_eq!(
        new_growth_len(push_live_len, push_requested_min_len, max_len),
        INITIAL_STACK_BUFFER_SIZE * 2 + 2
    );

    let restore_requested_min_len = INITIAL_STACK_BUFFER_SIZE + 1;
    assert_eq!(
        previous_growth_len(
            INITIAL_STACK_BUFFER_SIZE,
            MIN_STACK_DEPTH,
            restore_requested_min_len,
            max_len,
        ),
        INITIAL_STACK_BUFFER_SIZE * 2
    );
    assert_eq!(
        new_growth_len(MIN_STACK_DEPTH, restore_requested_min_len, max_len),
        restore_requested_min_len
    );
}

#[test]
fn new_stack_growth_algorithm_preserves_required_bounds() {
    let max_depth = DEFAULT_MAX_STACK_DEPTH * 4;
    let max_len = STACK_BUFFER_BASE_IDX.saturating_add(max_depth).saturating_add(1);

    for live_len in MIN_STACK_DEPTH..max_depth {
        let recentered_min_len = STACK_BUFFER_BASE_IDX.saturating_add(live_len).saturating_add(2);
        let requested_min_len = recentered_min_len.max(INITIAL_STACK_BUFFER_SIZE + 1);
        let new_len = new_growth_len(live_len, requested_min_len, max_len);

        assert!(new_len >= requested_min_len);
        assert!(new_len >= recentered_min_len);
        assert!(new_len <= max_len);
    }

    for overflow_len in 0..=(max_depth - MIN_STACK_DEPTH) {
        let requested_min_len =
            INITIAL_STACK_TOP_IDX.saturating_add(overflow_len).saturating_add(1);
        let new_len = new_growth_len(MIN_STACK_DEPTH, requested_min_len, max_len);

        assert!(new_len >= requested_min_len);
        assert!(new_len <= max_len);
    }
}

#[test]
fn stack_depth_limit_exceeded() {
    let mut host = DefaultHost::default();
    let program = simple_program_with_ops(vec![Operation::Pad]);
    let options = ExecutionOptions::default().with_max_stack_depth(MIN_STACK_DEPTH).unwrap();

    let err =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits")
            .execute_sync(&program, &mut host)
            .expect_err("pushing past the configured stack depth should fail");

    assert_matches!(
        err,
        ExecutionError::StackDepthLimitExceeded {
            depth,
            max: MIN_STACK_DEPTH,
        } if depth == MIN_STACK_DEPTH + 1
    );
}

/// Tests that `ExecutionError::Internal` is correctly emitted when the continuation stack grows
/// past the maximum allowed size.
#[test]
fn test_continuation_stack_limit_exceeded() {
    let mut host = DefaultHost::default();

    // Build a program with deeply nested join nodes. Each join node pushes 2 continuations
    // (FinishJoin + StartNode) onto the continuation stack before executing its first child.
    // With `depth` levels of nesting, the continuation stack will grow to approximately
    // `2 * depth` entries.
    let program = {
        let mut forest = MastForest::new();

        // Create a simple leaf basic block (just a noop).
        let leaf_id = BasicBlockNodeBuilder::new(vec![Operation::Noop])
            .add_to_forest(&mut forest)
            .unwrap();

        // Nest join nodes: join(join(join(..., leaf), leaf), leaf)
        // Each level adds ~2 continuations to the stack.
        let depth = 10;
        let mut current = leaf_id;
        for _ in 0..depth {
            current = JoinNodeBuilder::new([current, leaf_id]).add_to_forest(&mut forest).unwrap();
        }

        forest.make_root(current);
        Program::new(forest.into(), current)
    };

    // Set a very small continuation stack limit that will be exceeded by the nested joins.
    let options = ExecutionOptions::default().with_max_num_continuations(3);

    let processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");
    let err = processor.execute_sync(&program, &mut host).unwrap_err();

    assert_matches!(err, ExecutionError::Internal(msg) if msg.contains("continuation stack"));
}

/// Tests that a continuation stack size exactly equal to `max_num_continuations` succeeds.
#[test]
fn test_continuation_stack_limit_exactly_max_continuations_succeeds() {
    let mut host = DefaultHost::default();

    let program = {
        let mut forest = MastForest::new();

        let leaf_id = BasicBlockNodeBuilder::new(vec![Operation::Noop])
            .add_to_forest(&mut forest)
            .unwrap();

        let root = JoinNodeBuilder::new([leaf_id, leaf_id]).add_to_forest(&mut forest).unwrap();
        forest.make_root(root);
        Program::new(forest.into(), root)
    };

    // A single join peaks at three continuations after the join start step:
    // FinishJoin(root), StartNode(second), StartNode(first).
    let options = ExecutionOptions::default().with_max_num_continuations(3);

    let processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");

    processor.execute_sync(&program, &mut host).unwrap();
}

// TEST HELPERS
// -----------------------------------------------------------------------------------------------

fn simple_program_with_ops(ops: Vec<Operation>) -> Program {
    let program: Program = {
        let mut program = MastForest::new();
        let root_id = BasicBlockNodeBuilder::new(ops).add_to_forest(&mut program).unwrap();
        program.make_root(root_id);

        Program::new(program.into(), root_id)
    };

    program
}

fn pad_then_drop_ops(num_pads: usize) -> Vec<Operation> {
    let mut ops = vec![Operation::Pad; num_pads];
    ops.extend(vec![Operation::Drop; num_pads]);
    ops
}
