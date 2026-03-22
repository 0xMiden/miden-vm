use alloc::{string::String, sync::Arc};

use miden_air::trace::{
    AUX_TRACE_RAND_CHALLENGES, DECODER_TRACE_OFFSET,
    chiplets::hasher::HASH_CYCLE_LEN,
    decoder::{HASHER_STATE_OFFSET, NUM_OP_BITS, OP_BITS_OFFSET},
};
use miden_core::{
    Felt, Word,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder,
        JoinNodeBuilder, LoopNodeBuilder, MastForest, MastForestContributor, MastNodeExt,
        SplitNodeBuilder,
    },
    operations::{Operation, opcodes},
    program::{Kernel, Program, ProgramInfo, StackInputs},
};
use miden_utils_testing::{get_column_name, rand::rand_array};
use pretty_assertions::assert_eq;
use rstest::{fixture, rstest};

use super::*;
use crate::{
    AdviceInputs, DefaultHost, ExecutionOptions, FastProcessor, HostLibrary, TraceBuildInputs,
    trace::trace_state::MemoryReadsReplay,
};

const DEFAULT_STACK: &[Felt] = &[Felt::new(1), Felt::new(2), Felt::new(3)];

/// A sentinel value mainly used to catch when a ZERO is dropped from the stack but shouldn't have
/// been. That is, if the stack is only ZEROs, we can't tell if a ZERO was dropped or not. Using a
/// sentinel value makes it obvious when an unexpected ZERO is dropped.
const SENTINEL_VALUE: Felt = Felt::new(9999);

/// Returns the procedure hash that DYN and DYNCALL will call.
/// The digest is computed dynamically from the target basic block (single SWAP operation).
fn dyn_target_proc_hash() -> &'static [Felt] {
    use std::sync::LazyLock;
    static HASH: LazyLock<Vec<Felt>> = LazyLock::new(|| {
        // Build the same target basic block as in dyn_program/dyncall_program
        let mut forest = MastForest::new();
        let target = BasicBlockNodeBuilder::new(vec![Operation::Swap], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        // FastProcessor::new now expects first element to be top of stack
        forest.get_node_by_id(target).unwrap().digest().iter().copied().collect()
    });
    HASH.as_slice()
}

/// Returns the digest of the external library procedure (double SWAP), computed dynamically.
/// This matches the procedure created by `create_simple_library()`.
fn external_lib_proc_digest() -> Word {
    use std::sync::LazyLock;
    static DIGEST: LazyLock<Word> = LazyLock::new(|| {
        let mut forest = MastForest::new();
        let swap_block =
            BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap], Vec::new())
                .add_to_forest(&mut forest)
                .unwrap();
        forest.get_node_by_id(swap_block).unwrap().digest()
    });
    *DIGEST
}

/// Returns the external library procedure digest elements for stack inputs.
/// FastProcessor::new now expects first element to be top of stack.
fn external_lib_proc_hash_for_stack() -> &'static [Felt] {
    use std::sync::LazyLock;
    static HASH: LazyLock<Vec<Felt>> =
        LazyLock::new(|| external_lib_proc_digest().iter().copied().collect());
    HASH.as_slice()
}

/// This test verifies that the trace generated when executing a program in multiple fragments (for
/// all possible fragment boundaries) is identical to the trace generated when executing the same
/// program in a single fragment. This ensures that the logic for generating trace rows at fragment
/// boundaries is correct, given that we test elsewhere the correctness of the trace generated in a
/// single fragment.
#[rstest]
// Case 1: Tests the trace fragment generation for when a fragment starts in the start phase of a
// Join node (i.e. clk 4). Execution:
//  0: JOIN
//  1:   BLOCK MUL END
//  4:   JOIN
//  5:     BLOCK ADD END
//  8:     BLOCK SWAP END
// 11:   END
// 12: END
// 13: HALT
#[case(join_program(), 4, DEFAULT_STACK)]
// Case 2: Tests the trace fragment generation for when a fragment starts in the finish phase of a
// Join node. Same execution as previous case, but we want the 2nd fragment to start at clk=11,
// which is the END of the inner Join node.
#[case(join_program(), 11, DEFAULT_STACK)]
// Case 3: Tests the trace fragment generation for when a fragment starts in the start phase of a
// Split node (i.e. clk 5). Execution:
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   SPLIT
//  6:     BLOCK ADD END
//  9:   END
// 10: END
// 11: HALT
#[case(split_program(), 5, &[ONE])]
// Case 4: Similar to previous case, but we take the other branch of the Split node.
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   SPLIT
//  6:     BLOCK SWAP END
//  9:   END
// 10: END
// 11: HALT
#[case(split_program(), 5, &[ZERO, SENTINEL_VALUE])]
// Case 5: Tests the trace fragment generation for when a fragment starts in the finish phase of a
// Join node. Same execution as case 3, but we want the 2nd fragment to start at the END of the
// SPLIT node.
#[case(split_program(), 9, &[ONE])]
// Case 6: Tests the trace fragment generation for when a fragment starts in the finish phase of a
// Join node. Same execution as case 4, but we want the 2nd fragment to start at the END of the
// SPLIT node.
#[case(split_program(), 9, &[ZERO, SENTINEL_VALUE])]
// Case 7: LOOP start
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP END
//  7: END
//  8: HALT
#[case(loop_program(), 5, &[ZERO, SENTINEL_VALUE])]
// Case 8: LOOP END, when loop was not entered
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP END
//  7: END
//  8: HALT
#[case(loop_program(), 6, &[ZERO, SENTINEL_VALUE])]
// Case 9: LOOP END, when loop was entered
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP
//  6:     BLOCK PAD DROP END
// 10:   END
// 11: END
// 12: HALT
#[case(loop_program(), 10, &[ONE, ZERO, SENTINEL_VALUE])]
// Case 10: LOOP REPEAT
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP
//  6:     BLOCK PAD DROP END
// 10:   REPEAT
// 11:     BLOCK PAD DROP END
// 15:   END
// 16: END
// 17: HALT
#[case(loop_program(), 10, &[ONE, ONE, ZERO, SENTINEL_VALUE])]
// Case 11: CALL START
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   CALL
//  6:     BLOCK SWAP SWAP END
// 10:   END
// 11: END
// 12: HALT
#[case(call_program(), 5, DEFAULT_STACK)]
// Case 12: CALL END
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   CALL
//  6:     BLOCK SWAP SWAP END
// 10:   END
// 11: END
// 12: HALT
#[case(call_program(), 10, DEFAULT_STACK)]
// Case 13: SYSCALL START
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   SYSCALL
//  6:     BLOCK SWAP SWAP END
// 10:   END
// 11: END
// 12: HALT
#[case(syscall_program(), 5, DEFAULT_STACK)]
// Case 14: SYSCALL END
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   SYSCALL
//  6:     BLOCK SWAP SWAP END
// 10:   END
// 11: END
// 12: HALT
#[case(syscall_program(), 10, DEFAULT_STACK)]
// Case 15: BASIC BLOCK START
//  0: JOIN
//  1:   BLOCK SWAP PUSH NOOP END
//  6:   BLOCK DROP END
//  9: END
// 10: HALT
#[case(basic_block_program_small(), 1, DEFAULT_STACK)]
// Case 16: BASIC BLOCK FIRST OP
//  0: JOIN
//  1:   BLOCK SWAP PUSH NOOP END
//  6:   BLOCK DROP END
//  9: END
// 10: HALT
#[case(basic_block_program_small(), 2, DEFAULT_STACK)]
// Case 17: BASIC BLOCK SECOND OP
//  0: JOIN
//  1:   BLOCK SWAP PUSH NOOP END
//  6:   BLOCK DROP END
//  9: END
// 10: HALT
#[case(basic_block_program_small(), 3, DEFAULT_STACK)]
// Case 18: BASIC BLOCK INSERTED NOOP
//  0: JOIN
//  1:   BLOCK SWAP PUSH NOOP END
//  6:   BLOCK DROP END
//  9: END
// 10: HALT
#[case(basic_block_program_small(), 4, DEFAULT_STACK)]
// Case 19: BASIC BLOCK END
//  0: JOIN
//  1:   BLOCK SWAP PUSH NOOP END
//  6:   BLOCK DROP END
//  9: END
// 10: HALT
#[case(basic_block_program_small(), 5, DEFAULT_STACK)]
// Case 20: BASIC BLOCK RESPAN
//  0: JOIN
//  1:   BLOCK
//  2:     <72 SWAPs>
// 74:   RESPAN
// 75:     <8 SWAPs>
// 83:   END
// 84:   BLOCK DROP END
// 87: END
// 88: HALT
#[case(basic_block_program_multiple_batches(), 74, DEFAULT_STACK)]
// Case 21: BASIC BLOCK OP IN 2nd BATCH
//  0: JOIN
//  1:   BLOCK
//  2:     <72 SWAPs>
// 74:   RESPAN
// 75:     <8 SWAPs>
// 83:   END
// 84:   BLOCK DROP END
// 87: END
// 88: HALT
#[case(basic_block_program_multiple_batches(), 76, DEFAULT_STACK)]
// Case 22: DYN START
//  0: JOIN
//  1:   BLOCK
//  2:     PUSH MStoreW DROP DROP DROP DROP PUSH NOOP NOOP
// 11:   END
// 12:   DYN
// 13:     BLOCK SWAP END
// 16:   END
// 17: END
// 18: HALT
#[case(dyn_program(), 12, dyn_target_proc_hash())]
// Case 23: DYN END
//  0: JOIN
//  1:   BLOCK
//  2:     PUSH MStoreW DROP DROP DROP DROP PUSH NOOP NOOP
// 11:   END
// 12:   DYN
// 13:     BLOCK SWAP END
// 16:   END
// 17: END
// 18: HALT
#[case(dyn_program(), 16, dyn_target_proc_hash())]
// Case 24: DYNCALL START
//  0: JOIN
//  1:   BLOCK
//  2:     PUSH MStoreW DROP DROP DROP DROP PUSH NOOP NOOP
// 11:   END
// 12:   DYNCALL
// 13:     BLOCK SWAP END
// 16:   END
// 17: END
// 18: HALT
#[case(dyncall_program(), 12, dyn_target_proc_hash())]
// Case 25: DYNCALL END
//  0: JOIN
//  1:   BLOCK
//  2:     PUSH MStoreW DROP DROP DROP DROP PUSH NOOP NOOP
// 11:   END
// 12:   DYNCALL
// 13:     BLOCK SWAP END
// 16:   END
// 17: END
// 18: HALT
#[case(dyncall_program(), 16, dyn_target_proc_hash())]
// Case 26: EXTERNAL NODE
//  0: JOIN
//  1:   BLOCK PAD DROP END
//  5:   EXTERNAL                 # NOTE: doesn't consume clock cycle
//  5:     BLOCK SWAP SWAP END
//  9:   END
// 10: END
// 11: HALT
#[case(external_program(), 5, DEFAULT_STACK)]
// Case 27: DYN START (EXTERNAL PROCEDURE)
//  0: JOIN
//  1:   BLOCK
//  2:     PUSH MStoreW DROP DROP DROP DROP PUSH NOOP NOOP
// 11:   END
// 12:   DYN
// 13:     BLOCK SWAP SWAP END
// 17:   END
// 18: END
// 19: HALT
#[case(dyn_program(), 12, external_lib_proc_hash_for_stack())]
fn test_trace_generation_at_fragment_boundaries(
    testname: String,
    #[case] program: Program,
    #[case] fragment_size: usize,
    #[case] stack_inputs: &[Felt],
) {
    /// We make the fragment size large enough here to avoid fragmenting the trace in multiple
    /// fragments, but still not too large so as to not cause memory allocation issues.
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    let trace_from_fragments = {
        let processor = FastProcessor::new_with_options(
            StackInputs::new(stack_inputs).unwrap(),
            AdviceInputs::default(),
            ExecutionOptions::default()
                .with_core_trace_fragment_size(fragment_size)
                .unwrap(),
        );
        let mut host = DefaultHost::default();
        host.load_library(create_simple_library()).unwrap();
        let trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();
        build_trace(trace_inputs).unwrap()
    };

    let trace_from_single_fragment = {
        let processor = FastProcessor::new_with_options(
            StackInputs::new(stack_inputs).unwrap(),
            AdviceInputs::default(),
            ExecutionOptions::default()
                .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
                .unwrap(),
        );
        let mut host = DefaultHost::default();
        host.load_library(create_simple_library()).unwrap();
        let trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();
        assert!(trace_inputs.trace_generation_context().core_trace_contexts.len() == 1);

        build_trace(trace_inputs).unwrap()
    };

    // Ensure that the trace generated from multiple fragments is identical to the one generated
    // from a single fragment.
    for (col_idx, (col_from_fragments, col_from_single_fragment)) in trace_from_fragments
        .main_trace()
        .columns()
        .zip(trace_from_single_fragment.main_trace().columns())
        .enumerate()
    {
        if col_from_fragments != col_from_single_fragment {
            // Find the first row where the columns disagree
            for (row_idx, (val_from_fragments, val_from_single_fragment)) in
                col_from_fragments.iter().zip(col_from_single_fragment.iter()).enumerate()
            {
                if val_from_fragments != val_from_single_fragment {
                    panic!(
                        "Trace columns do not match between trace generated as multiple fragments vs a single fragment at column {} ({}) row {}: multiple={}, single={}",
                        col_idx,
                        get_column_name(col_idx),
                        row_idx,
                        val_from_fragments,
                        val_from_single_fragment
                    );
                }
            }
            // If we reach here, the columns have different lengths
            panic!(
                "Trace columns do not match between trace generated as multiple fragments vs a single fragment at column {} ({}): different lengths (fragments={}, single={})",
                col_idx,
                get_column_name(col_idx),
                col_from_fragments.len(),
                col_from_single_fragment.len()
            );
        }
    }

    // Verify stack outputs match.
    assert_eq!(trace_from_fragments.stack_outputs(), trace_from_single_fragment.stack_outputs(),);

    // Verify program info and trace length summary match.
    assert_eq!(trace_from_fragments.program_info(), trace_from_single_fragment.program_info(),);
    assert_eq!(
        trace_from_fragments.trace_len_summary(),
        trace_from_single_fragment.trace_len_summary(),
    );

    // Verify merkle store data match deterministically.
    let merkle_nodes_from_fragments: alloc::collections::BTreeMap<_, _> = trace_from_fragments
        .advice_provider()
        .merkle_store()
        .inner_nodes()
        .map(|info| (info.value, (info.left, info.right)))
        .collect();
    let merkle_nodes_from_single: alloc::collections::BTreeMap<_, _> = trace_from_single_fragment
        .advice_provider()
        .merkle_store()
        .inner_nodes()
        .map(|info| (info.value, (info.left, info.right)))
        .collect();
    assert_eq!(merkle_nodes_from_fragments, merkle_nodes_from_single,);

    // Verify aux trace columns match.
    let rand_elements = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_from_fragments = trace_from_fragments.build_aux_trace(&rand_elements).unwrap();
    let aux_from_single_fragment =
        trace_from_single_fragment.build_aux_trace(&rand_elements).unwrap();
    let aux_from_fragments =
        aux_from_fragments.columns().map(|col| col.to_vec()).collect::<Vec<_>>();
    let aux_from_single_fragment =
        aux_from_single_fragment.columns().map(|col| col.to_vec()).collect::<Vec<_>>();
    assert_eq!(aux_from_fragments, aux_from_single_fragment,);

    // Compare deterministic traces as a compact sanity check and to keep the snapshot stable.
    assert_eq!(
        format!("{:?}", DeterministicTrace(&trace_from_fragments)),
        format!("{:?}", DeterministicTrace(&trace_from_single_fragment)),
        "Deterministic trace mismatch between fragments and single fragment"
    );

    // Snapshot testing to ensure that future changes don't unexpectedly change the trace.
    // We use DeterministicTrace to produce stable Debug output, since ExecutionTrace contains
    // a MerkleStore backed by HashMap whose iteration order is non-deterministic.
    insta::assert_compact_debug_snapshot!(testname, DeterministicTrace(&trace_from_fragments));
}

#[test]
fn test_nested_loop_end_flags_stable_across_fragmentation() {
    // Small fragment size is chosen so that the fragment boundaries land on the outer loop replay:
    // rows [0..6], [7..13], [14..].
    //
    // Execution for the chosen stack inputs:
    //  0: LOOP
    //  1:   LOOP
    //  2:     BLOCK PAD DROP END
    //  6:   END
    //  7: REPEAT
    //  8:   LOOP
    //  9:     BLOCK PAD DROP END
    // 13:   END
    // 14: END
    // 15: HALT
    //
    // Stack inputs, top first:
    //  1) enter outer loop
    //  2) enter inner loop
    //  3) exit inner loop
    //  4) repeat outer loop
    //  5) enter inner loop
    //  6) exit inner loop
    //  7) exit outer loop
    const SMALL_FRAGMENT_SIZE: usize = 7;
    const LARGE_FRAGMENT_SIZE: usize = 1 << 20;

    let program = nested_loop_program();
    let stack_inputs = &[ONE, ONE, ZERO, ONE, ONE, ZERO, ZERO, SENTINEL_VALUE];

    let trace_from_fragments = build_trace_for_program(&program, stack_inputs, SMALL_FRAGMENT_SIZE);
    let trace_from_single_fragment =
        build_trace_for_program(&program, stack_inputs, LARGE_FRAGMENT_SIZE);

    let columns_from_fragments = trace_from_fragments
        .main_trace()
        .columns()
        .map(|col| col.to_vec())
        .collect::<Vec<_>>();
    let columns_from_single_fragment = trace_from_single_fragment
        .main_trace()
        .columns()
        .map(|col| col.to_vec())
        .collect::<Vec<_>>();

    assert_eq!(
        columns_from_fragments, columns_from_single_fragment,
        "nested-loop trace changed across fragment boundaries"
    );

    let end_flags = collect_end_flags(&trace_from_fragments);
    assert!(
        end_flags.contains(&[ONE, ZERO, ZERO, ZERO].into()),
        "expected an END row for loop body basic block (is_loop_body=1)"
    );
    assert!(
        end_flags.contains(&[ONE, ONE, ZERO, ZERO].into()),
        "expected an END row for inner loop node (is_loop_body=1, loop_entered=1)"
    );
    assert!(
        end_flags.contains(&[ZERO, ONE, ZERO, ZERO].into()),
        "expected an END row for outer loop node (is_loop_body=0, loop_entered=1)"
    );
}

#[test]
fn test_partial_last_fragment_exists_for_h0_inversion_path() {
    // Keep this > 1 and non-dividing for join_program() to guarantee a short final fragment.
    const FRAGMENT_SIZE: usize = 11;

    let program = join_program();
    let processor = FastProcessor::new_with_options(
        StackInputs::new(DEFAULT_STACK).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    host.load_library(create_simple_library()).unwrap();

    let trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    assert!(
        trace_inputs.trace_generation_context().core_trace_contexts.len() > 1,
        "repro precondition requires multiple fragments"
    );

    let trace = build_trace(trace_inputs).unwrap();
    let total_rows_without_halt = trace.main_trace().num_rows() - 1;

    assert_ne!(
        total_rows_without_halt % FRAGMENT_SIZE,
        0,
        "repro precondition requires a short final fragment"
    );
}

#[cfg(miri)]
#[test]
fn miri_repro_uninitialized_tail_read_during_h0_inversion() {
    // This reproducer intentionally constructs a short final fragment. Before the fix in
    // generate_core_trace_columns(), miri should flag an uninitialized read in the inversion pass.
    const FRAGMENT_SIZE: usize = 11;

    let program = join_program();
    let processor = FastProcessor::new_with_options(
        StackInputs::new(DEFAULT_STACK).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    host.load_library(create_simple_library()).unwrap();
    let trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    assert!(trace_inputs.trace_generation_context().core_trace_contexts.len() > 1);

    let _ = build_trace(trace_inputs);
}

/// Creates a library with a single procedure containing just a SWAP operation.
fn create_simple_library() -> HostLibrary {
    let mut mast_forest = MastForest::new();
    let swap_block = BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(swap_block);
    HostLibrary::from(Arc::new(mast_forest))
}

/// (join (
///     (block mul)
///     (join (block add) (block swap))
/// )
fn join_program() -> Program {
    let mut program = MastForest::new();

    let basic_block_mul = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
        .add_to_forest(&mut program)
        .unwrap();
    let basic_block_add = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut program)
        .unwrap();
    let basic_block_swap = BasicBlockNodeBuilder::new(vec![Operation::Swap], Vec::new())
        .add_to_forest(&mut program)
        .unwrap();

    let target_join_node = JoinNodeBuilder::new([basic_block_add, basic_block_swap])
        .add_to_forest(&mut program)
        .unwrap();

    let root_join_node = JoinNodeBuilder::new([basic_block_mul, target_join_node])
        .add_to_forest(&mut program)
        .unwrap();
    program.make_root(root_join_node);

    Program::new(Arc::new(program), root_join_node)
}

/// (join (
///     (block swap swap)
///     (split (block add) (block swap))
/// )
fn split_program() -> Program {
    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block_swap_swap =
            BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap], Vec::new())
                .add_to_forest(&mut program)
                .unwrap();

        let target_split_node = {
            let basic_block_add = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
                .add_to_forest(&mut program)
                .unwrap();
            let basic_block_swap = BasicBlockNodeBuilder::new(vec![Operation::Swap], Vec::new())
                .add_to_forest(&mut program)
                .unwrap();

            SplitNodeBuilder::new([basic_block_add, basic_block_swap])
                .add_to_forest(&mut program)
                .unwrap()
        };

        JoinNodeBuilder::new([basic_block_swap_swap, target_split_node])
            .add_to_forest(&mut program)
            .unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}

/// (join (
///     (block swap swap)
///     (loop (block pad drop))
/// )
fn loop_program() -> Program {
    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block_swap_swap =
            BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap], Vec::new())
                .add_to_forest(&mut program)
                .unwrap();

        let target_loop_node = {
            let basic_block_pad_drop =
                BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop], Vec::new())
                    .add_to_forest(&mut program)
                    .unwrap();

            LoopNodeBuilder::new(basic_block_pad_drop).add_to_forest(&mut program).unwrap()
        };

        JoinNodeBuilder::new([basic_block_swap_swap, target_loop_node])
            .add_to_forest(&mut program)
            .unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}

/// (loop (loop (block pad drop)))
fn nested_loop_program() -> Program {
    let mut program = MastForest::new();

    let inner_loop = {
        let basic_block_pad_drop =
            BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop], Vec::new())
                .add_to_forest(&mut program)
                .unwrap();

        LoopNodeBuilder::new(basic_block_pad_drop).add_to_forest(&mut program).unwrap()
    };

    let outer_loop = LoopNodeBuilder::new(inner_loop).add_to_forest(&mut program).unwrap();

    program.make_root(outer_loop);
    Program::new(Arc::new(program), outer_loop)
}

/// (join (
///     (block swap swap)
///     (call (<previous block>))
/// )
fn call_program() -> Program {
    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block_swap_swap =
            BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap], Vec::new())
                .add_to_forest(&mut program)
                .unwrap();

        let target_call_node =
            CallNodeBuilder::new(basic_block_swap_swap).add_to_forest(&mut program).unwrap();

        JoinNodeBuilder::new([basic_block_swap_swap, target_call_node])
            .add_to_forest(&mut program)
            .unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}

/// (join (
///     (block swap swap)
///     (syscall (<previous block>))
/// )
fn syscall_program() -> Program {
    let mut program = MastForest::new();

    let (root_join_node, kernel_proc_digest) = {
        // In this test, we also include this procedure in the kernel so that it can be syscall'ed.
        let basic_block_swap_swap =
            BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap], Vec::new())
                .add_to_forest(&mut program)
                .unwrap();

        let target_call_node = CallNodeBuilder::new_syscall(basic_block_swap_swap)
            .add_to_forest(&mut program)
            .unwrap();

        let root_join_node = JoinNodeBuilder::new([basic_block_swap_swap, target_call_node])
            .add_to_forest(&mut program)
            .unwrap();

        (root_join_node, program[basic_block_swap_swap].digest())
    };

    program.make_root(root_join_node);

    Program::with_kernel(
        Arc::new(program),
        root_join_node,
        Kernel::new(&[kernel_proc_digest]).unwrap(),
    )
}

/// (join (
///     (block swap push(42) noop)
///     (block drop)
/// )
fn basic_block_program_small() -> Program {
    let mut program = MastForest::new();

    let root_join_node = {
        let target_basic_block = BasicBlockNodeBuilder::new(
            vec![Operation::Swap, Operation::Push(Felt::from_u32(42))],
            Vec::new(),
        )
        .add_to_forest(&mut program)
        .unwrap();
        let basic_block_drop = BasicBlockNodeBuilder::new(vec![Operation::Drop], Vec::new())
            .add_to_forest(&mut program)
            .unwrap();

        JoinNodeBuilder::new([target_basic_block, basic_block_drop])
            .add_to_forest(&mut program)
            .unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}

/// (join (
///     (block <80 swaps>)
///     (block drop)
/// )
fn basic_block_program_multiple_batches() -> Program {
    /// Number of swaps should be greater than the max number of operations per batch (72), to
    /// ensure that we have at least one RESPAN.
    const NUM_SWAPS: usize = 80;
    let mut program = MastForest::new();

    let root_join_node = {
        let target_basic_block =
            BasicBlockNodeBuilder::new(vec![Operation::Swap; NUM_SWAPS], Vec::new())
                .add_to_forest(&mut program)
                .unwrap();
        let basic_block_drop = BasicBlockNodeBuilder::new(vec![Operation::Drop], Vec::new())
            .add_to_forest(&mut program)
            .unwrap();

        JoinNodeBuilder::new([target_basic_block, basic_block_drop])
            .add_to_forest(&mut program)
            .unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}

/// (join (
///     (block push(40) mem_storew_le drop drop drop drop push(40) noop noop)
///     (dyn)
/// )
fn dyn_program() -> Program {
    const HASH_ADDR: Felt = Felt::new(40);

    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block = BasicBlockNodeBuilder::new(
            vec![
                Operation::Push(HASH_ADDR),
                Operation::MStoreW,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                Operation::Push(HASH_ADDR),
            ],
            Vec::new(),
        )
        .add_to_forest(&mut program)
        .unwrap();

        let dyn_node = DynNodeBuilder::new_dyn().add_to_forest(&mut program).unwrap();

        JoinNodeBuilder::new([basic_block, dyn_node])
            .add_to_forest(&mut program)
            .unwrap()
    };
    program.make_root(root_join_node);

    // Add the procedure that DYN will call. Its digest is computed by dyn_target_proc_hash().
    let target = BasicBlockNodeBuilder::new(vec![Operation::Swap], Vec::new())
        .add_to_forest(&mut program)
        .unwrap();
    program.make_root(target);

    Program::new(Arc::new(program), root_join_node)
}

/// (join (
///     (block push(40) mem_storew_le drop drop drop drop push(40) noop noop)
///     (dyncall)
/// )
fn dyncall_program() -> Program {
    const HASH_ADDR: Felt = Felt::new(40);

    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block = BasicBlockNodeBuilder::new(
            vec![
                Operation::Push(HASH_ADDR),
                Operation::MStoreW,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                Operation::Push(HASH_ADDR),
            ],
            Vec::new(),
        )
        .add_to_forest(&mut program)
        .unwrap();

        let dyncall_node = DynNodeBuilder::new_dyncall().add_to_forest(&mut program).unwrap();

        JoinNodeBuilder::new([basic_block, dyncall_node])
            .add_to_forest(&mut program)
            .unwrap()
    };
    program.make_root(root_join_node);

    // Add the procedure that DYNCALL will call. Its digest is computed by dyn_target_proc_hash().
    let target = BasicBlockNodeBuilder::new(vec![Operation::Swap], Vec::new())
        .add_to_forest(&mut program)
        .unwrap();
    program.make_root(target);

    Program::new(Arc::new(program), root_join_node)
}

/// (join (
///     (block pad drop)
///     (call external(<external library procedure>))
/// )
///
/// external procedure: (block swap swap)
fn external_program() -> Program {
    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block_pad_drop =
            BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop], Vec::new())
                .add_to_forest(&mut program)
                .unwrap();

        let external_node = ExternalNodeBuilder::new(external_lib_proc_digest())
            .add_to_forest(&mut program)
            .unwrap();

        JoinNodeBuilder::new([basic_block_pad_drop, external_node])
            .add_to_forest(&mut program)
            .unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}

/// Verifies that `build_trace` returns `Err` (instead of panicking) when a
/// `CoreTraceFragmentContext` has an empty memory-reads replay for a program that actually reads
/// memory (the DYN program reads the callee hash from memory).
#[test]
fn test_build_trace_returns_err_on_empty_memory_reads_replay() {
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    let program = dyn_program();
    let stack_inputs = dyn_target_proc_hash();

    let processor = FastProcessor::new_with_options(
        StackInputs::new(stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    let mut trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    // Clear the memory reads replay so the replay processor will fail when the DYN node tries to
    // read the callee hash from memory.
    for ctx in &mut trace_inputs.trace_generation_context_mut().core_trace_contexts {
        ctx.replay.memory_reads = MemoryReadsReplay::default();
    }

    let result = build_trace(trace_inputs);
    assert!(
        result.is_err(),
        "build_trace should return Err when hasher replay has bad node ID"
    );
}

/// Verifies that `build_trace` returns `Err` (instead of panicking) when the hasher chiplet replay
/// contains a `HashBasicBlock` entry whose `MastNodeId` does not exist in the associated
/// `MastForest`.
#[test]
fn test_build_trace_returns_err_on_bad_node_id_in_hasher_replay() {
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    let program = basic_block_program_small();

    let processor = FastProcessor::new_with_options(
        StackInputs::new(DEFAULT_STACK).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    let mut trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    // Inject a HashBasicBlock entry with a node ID that points to a non-existent node in an empty
    // forest.
    let empty_forest = Arc::new(MastForest::new());
    // Build a small forest just to get a valid MastNodeId, then pair it with the empty forest.
    let mut temp_forest = MastForest::new();
    let valid_id = BasicBlockNodeBuilder::new(vec![Operation::Noop], Vec::new())
        .add_to_forest(&mut temp_forest)
        .unwrap();
    trace_inputs
        .trace_generation_context_mut()
        .hasher_for_chiplet
        .record_hash_basic_block(empty_forest, valid_id, [ZERO; 4].into());

    let result = build_trace(trace_inputs);
    assert!(
        result.is_err(),
        "build_trace should return Err when hasher replay has bad node ID"
    );
}

/// Verifies that `build_trace` rejects tampered `ProgramInfo` even when the rest of the trace
/// inputs came from a valid execution.
#[test]
fn test_build_trace_returns_err_on_mismatched_program_info() {
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    let program = basic_block_program_small();
    let other_program = join_program();

    let processor = FastProcessor::new_with_options(
        StackInputs::new(DEFAULT_STACK).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    let (execution_output, trace_generation_context) =
        processor.execute_trace_inputs_sync(&program, &mut host).unwrap().into_parts();

    let result = build_trace(TraceBuildInputs::with_program_info(
        &program,
        execution_output,
        trace_generation_context,
        other_program.to_info(),
    ));

    assert!(
        matches!(result, Err(ExecutionError::Internal("trace inputs do not match program info"))),
        "expected program-info mismatch error, got: {result:?}"
    );
}

/// Verifies that `build_trace` accepts a compatibility bundle created via `TraceBuildInputs::new`
/// when it reuses an authentic execution context and matching `ProgramInfo`.
#[test]
#[allow(deprecated)]
fn test_build_trace_accepts_bound_trace_build_inputs_new() {
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    let program = basic_block_program_small();

    let processor = FastProcessor::new_with_options(
        StackInputs::new(DEFAULT_STACK).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    let (execution_output, trace_generation_context) =
        processor.execute_trace_inputs_sync(&program, &mut host).unwrap().into_parts();

    let trace = build_trace(TraceBuildInputs::new(
        execution_output,
        trace_generation_context,
        program.to_info(),
    ))
    .unwrap();

    assert!(
        trace.program_hash() == &program.hash(),
        "expected compatibility constructor to preserve the executed program binding"
    );
}

/// Verifies that `build_trace` rejects tampered `ProgramInfo` even when it preserves the same
/// entrypoint hash but swaps in a different kernel.
#[test]
fn test_build_trace_returns_err_on_mismatched_kernel_with_same_program_hash() {
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    let program = basic_block_program_small();
    let other_program =
        ProgramInfo::new(program.hash(), Kernel::new(&[join_program().hash()]).unwrap());

    let processor = FastProcessor::new_with_options(
        StackInputs::new(DEFAULT_STACK).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    let (execution_output, trace_generation_context) =
        processor.execute_trace_inputs_sync(&program, &mut host).unwrap().into_parts();

    let result = build_trace(TraceBuildInputs::with_program_info(
        &program,
        execution_output,
        trace_generation_context,
        other_program,
    ));

    assert!(
        matches!(result, Err(ExecutionError::Internal("trace inputs do not match program info"))),
        "expected program-info mismatch error, got: {result:?}"
    );
}

/// Verifies that `build_trace` rejects compatibility bundles created via `from_program()` when the
/// supplied program does not match the authentic execution context.
#[test]
#[allow(deprecated)]
fn test_build_trace_rejects_mismatched_trace_build_inputs_from_program() {
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    let program = basic_block_program_small();
    let other_program = join_program();

    let processor = FastProcessor::new_with_options(
        StackInputs::new(DEFAULT_STACK).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    let (execution_output, trace_generation_context) =
        processor.execute_trace_inputs_sync(&program, &mut host).unwrap().into_parts();

    let result = build_trace(TraceBuildInputs::from_program(
        &other_program,
        execution_output,
        trace_generation_context,
    ));

    assert!(
        matches!(result, Err(ExecutionError::Internal("trace inputs do not match program info"))),
        "expected program-info mismatch error, got: {result:?}"
    );
}

/// Tests `build_trace_with_max_len` behavior at various `max_trace_len` boundaries relative to the
/// core trace length. `core_trace_len` is the number of core trace rows including the HALT row
/// appended by `build_trace_with_max_len`.
///
/// `max_trace_len_offset_from_core_trace_len` is added to `core_trace_len` to compute
/// `max_trace_len`.
#[rstest]
// Case 1: max_trace_len is 1 less than core_trace_len, so the core trace check should fail.
#[case(-1, false)]
// Case 2: max_trace_len is equal to core_trace_len, so the core trace check should pass (not
// strictly greater), and the function should succeed.
#[case(0, true)]
fn test_build_trace_with_max_len_corner_cases(
    #[case] max_trace_len_offset_from_core_trace_len: isize,
    #[case] build_trace_succeeds: bool,
) {
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    let program = basic_block_program_small();

    let processor = FastProcessor::new_with_options(
        StackInputs::new(DEFAULT_STACK).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    let trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    // Compute the number of core trace rows generated, which includes the HALT row inserted by
    // `build_trace_with_max_len`.
    let core_trace_len = trace_inputs.trace_generation_context().core_trace_contexts.len()
        * trace_inputs.trace_generation_context().fragment_size
        + 1;

    let max_trace_len = core_trace_len
        .checked_add_signed(max_trace_len_offset_from_core_trace_len)
        .unwrap();
    let result = build_trace_with_max_len(trace_inputs, max_trace_len);

    assert_eq!(
        result.is_ok(),
        build_trace_succeeds,
        "with max_trace_len={max_trace_len} (core_trace_len={core_trace_len}), \
         expected build_trace_succeeds={build_trace_succeeds}"
    );

    // Additionally, if we expect an error, verify that it's the expected `TraceLenExceeded` error
    // with the correct `max_len`.
    if !build_trace_succeeds {
        assert!(
            matches!(result, Err(ExecutionError::TraceLenExceeded(max_len)) if max_len == max_trace_len),
            "expected TraceLenExceeded({max_trace_len}), got: {result:?}"
        );
    }
}

/// Verifies that `build_trace_with_max_len` returns `TraceLenExceeded` (instead of panicking due
/// to arithmetic overflow) when `core_trace_contexts.len() * fragment_size` overflows `usize`.
#[test]
fn test_build_trace_returns_err_on_fragment_size_overflow() {
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    let program = basic_block_program_small();

    let processor = FastProcessor::new_with_options(
        StackInputs::new(DEFAULT_STACK).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    let mut trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    // Set fragment_size to usize::MAX so that `len() * fragment_size` overflows.
    trace_inputs.trace_generation_context_mut().fragment_size = usize::MAX;

    let result = build_trace_with_max_len(trace_inputs, usize::MAX);

    assert!(
        matches!(result, Err(ExecutionError::TraceLenExceeded(_))),
        "expected TraceLenExceeded on overflow, got: {result:?}"
    );
}

/// Verifies that `build_trace_with_max_len` returns `TraceLenExceeded` when the chiplets trace
/// (hasher + memory rows) exceeds `max_trace_len`, even though the core trace rows fit.
#[test]
fn test_build_trace_returns_err_when_chiplets_trace_exceeds_max_len() {
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    // Use the DYN program because it exercises both hasher and memory chiplets.
    let program = dyn_program();
    let stack_inputs = dyn_target_proc_hash();

    let processor = FastProcessor::new_with_options(
        StackInputs::new(stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    let mut trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    // Note: the last fragment may have fewer rows than the fragment size, so this is really an
    // upper bound on the number of core trace rows
    let core_trace_rows = trace_inputs.trace_generation_context().core_trace_contexts.len()
        * trace_inputs.trace_generation_context().fragment_size;

    // Inject enough hasher permutations so the chiplets trace exceeds core_trace_rows.
    // Each permute adds HASH_CYCLE_LEN rows to the hasher chiplet trace, so we need
    // core_trace_rows / HASH_CYCLE_LEN + 1 permutations to guarantee the chiplets trace exceeds the
    // limit.
    let num_permutations = core_trace_rows / HASH_CYCLE_LEN + 1;
    for _ in 0..num_permutations {
        trace_inputs
            .trace_generation_context_mut()
            .hasher_for_chiplet
            .record_permute_input([ZERO; 12]);
    }

    // Set max_trace_len equal to core_trace_rows. The core trace check passes (not strictly
    // greater), but the inflated chiplets trace will exceed it.
    let max_trace_len = core_trace_rows;

    let result = build_trace_with_max_len(trace_inputs, max_trace_len);

    assert!(
        matches!(result, Err(ExecutionError::TraceLenExceeded(_))),
        "expected TraceLenExceeded, got: {result:?}"
    );
}

/// Verifies that `build_trace` returns `ExecutionError::Internal` when `core_trace_contexts` is
/// empty, since `push_halt_opcode_row` expects at least one fragment to have been processed.
#[test]
fn test_build_trace_returns_err_on_empty_core_trace_contexts() {
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    let program = basic_block_program_small();

    let processor = FastProcessor::new_with_options(
        StackInputs::new(DEFAULT_STACK).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    let mut trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    // Clear core_trace_contexts to simulate an empty trace.
    trace_inputs.trace_generation_context_mut().core_trace_contexts.clear();

    let result = build_trace(trace_inputs);

    assert!(
        matches!(result, Err(ExecutionError::Internal(_))),
        "expected ExecutionError::Internal, got: {result:?}"
    );
}

// Workaround to make insta and rstest work together.
// See: https://github.com/la10736/rstest/issues/183#issuecomment-1564088329
#[fixture]
fn testname() -> String {
    // Replace `::` with `__` to make snapshot file names Windows-compatible.
    // Windows does not allow `:` in file names.
    std::thread::current().name().unwrap().replace("::", "__")
}

fn build_trace_for_program(
    program: &Program,
    stack_inputs: &[Felt],
    fragment_size: usize,
) -> ExecutionTrace {
    let processor = FastProcessor::new_with_options(
        StackInputs::new(stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(fragment_size)
            .unwrap(),
    );
    let mut host = DefaultHost::default();
    host.load_library(create_simple_library()).unwrap();
    let trace_inputs = processor.execute_trace_inputs_sync(program, &mut host).unwrap();

    build_trace(trace_inputs).unwrap()
}

fn collect_end_flags(trace: &ExecutionTrace) -> Vec<Word> {
    let main_trace = trace.main_trace();

    (0..main_trace.num_rows())
        .filter_map(|row_idx| {
            if read_opcode(main_trace, row_idx) == opcodes::END {
                Some(
                    [
                        main_trace.get_column(DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 4)
                            [row_idx],
                        main_trace.get_column(DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 5)
                            [row_idx],
                        main_trace.get_column(DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 6)
                            [row_idx],
                        main_trace.get_column(DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 7)
                            [row_idx],
                    ]
                    .into(),
                )
            } else {
                None
            }
        })
        .collect()
}

fn read_opcode(main_trace: &MainTrace, row_idx: usize) -> u8 {
    let mut result = 0;
    for i in 0..NUM_OP_BITS {
        let op_bit = main_trace.get_column(DECODER_TRACE_OFFSET + OP_BITS_OFFSET + i)[row_idx]
            .as_canonical_u64();
        assert!(op_bit <= 1, "invalid op bit");
        result += op_bit << i;
    }
    result as u8
}

/// Wrapper around `ExecutionTrace` that produces deterministic `Debug` output.
///
/// `ExecutionTrace` contains a `MerkleStore` backed by `HashMap`, whose iteration order is
/// non-deterministic. This wrapper formats the Merkle store nodes sorted by key, making the
/// output stable across runs for snapshot testing.
struct DeterministicTrace<'a>(&'a ExecutionTrace);

impl core::fmt::Debug for DeterministicTrace<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let trace = self.0;

        // Collect merkle store nodes into a sorted BTreeMap for deterministic output
        let sorted_nodes: alloc::collections::BTreeMap<_, _> = trace
            .advice_provider()
            .merkle_store()
            .inner_nodes()
            .map(|info| (info.value, (info.left, info.right)))
            .collect();

        f.debug_struct("ExecutionTrace")
            .field("main_trace", trace.main_trace())
            .field("program_info", &trace.program_info())
            .field("stack_outputs", &trace.stack_outputs())
            .field("merkle_store_nodes", &sorted_nodes)
            .field("trace_len_summary", &trace.trace_len_summary())
            .finish()
    }
}
