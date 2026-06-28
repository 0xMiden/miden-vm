use alloc::{string::String, sync::Arc};

use miden_air::{
    MidenAir,
    lookup::build_logup_aux_trace,
    trace::{RowIndex, chiplets::hasher::HASH_CYCLE_LEN},
};
use miden_core::{
    Felt, Word,
    field::QuadFelt,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder,
        JoinNodeBuilder, LoopNodeBuilder, MastForest, MastForestContributor, MastForestId,
        MastNodeExt, MastNodeId, SplitNodeBuilder,
    },
    operations::{Operation, opcodes},
    program::{Kernel, Program, StackInputs},
};
use miden_utils_testing::{get_column_name, rand::rand_array};
use pretty_assertions::assert_eq;
use rstest::{fixture, rstest};

use super::*;
use crate::{
    AdviceInputs, DefaultHost, ExecutionOptions, FastProcessor, HostLibrary,
    trace::trace_state::MemoryReadsReplay,
};

const DEFAULT_STACK: &[Felt] =
    &[Felt::new_unchecked(1), Felt::new_unchecked(2), Felt::new_unchecked(3)];

/// A sentinel value mainly used to catch when a ZERO is dropped from the stack but shouldn't have
/// been. That is, if the stack is only ZEROs, we can't tell if a ZERO was dropped or not. Using a
/// sentinel value makes it obvious when an unexpected ZERO is dropped.
const SENTINEL_VALUE: Felt = Felt::new_unchecked(9999);

/// Returns the procedure hash that DYN and DYNCALL will call.
/// The digest is computed dynamically from the target basic block (single SWAP operation).
fn dyn_target_proc_hash() -> &'static [Felt] {
    use std::sync::LazyLock;
    static HASH: LazyLock<Vec<Felt>> = LazyLock::new(|| {
        // Build the same target basic block as in dyn_program/dyncall_program
        let mut forest = MastForest::new();
        let target = BasicBlockNodeBuilder::new(vec![Operation::Swap])
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
        let swap_block = BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
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
// Case 7: LOOP start — fragment boundary lands on the LOOP row. The LOOP is do-while: with
// stack `[ZERO, SENTINEL]` the body runs once (Pad+Drop is net-zero, so the trailing condition
// at the body's exit is the same `ZERO` that drove entry), then END exits the loop.
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP                <-- fragment boundary
//  6:     BLOCK PAD DROP END
// 10:   END
// 11: END
// 12: HALT
#[case(loop_program(), 5, &[ZERO, SENTINEL_VALUE])]
// Case 8: fragment boundary one row inside the loop body (SPAN of body) — same execution as
// Case 7, just a different boundary.
#[case(loop_program(), 6, &[ZERO, SENTINEL_VALUE])]
// Case 9: LOOP REPEAT — `[ONE, ZERO, SENTINEL]` makes the body run twice (first iteration
// trailing condition is ONE, second is ZERO).
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP
//  6:     BLOCK PAD DROP END
// 10:   REPEAT              <-- fragment boundary
// 11:     BLOCK PAD DROP END
// 15:   END
// 16: END
// 17: HALT
#[case(loop_program(), 10, &[ONE, ZERO, SENTINEL_VALUE])]
// Case 10: LOOP REPEAT (deeper) — `[ONE, ONE, ZERO, SENTINEL]` makes the body run three times.
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP
//  6:     BLOCK PAD DROP END
// 10:   REPEAT              <-- fragment boundary
// 11:     BLOCK PAD DROP END
// 15:   REPEAT
// 16:     BLOCK PAD DROP END
// 20:   END
// 21: END
// 22: HALT
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
        )
        .expect("processor advice inputs should fit advice map limits");
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
        )
        .expect("processor advice inputs should fit advice map limits");
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

    // Verify deferred proof data match deterministically.
    assert_eq!(
        trace_from_fragments.deferred_state().root(),
        trace_from_single_fragment.deferred_state().root(),
    );

    // Compare deterministic traces as a compact sanity check and to keep the snapshot stable.
    assert_eq!(
        format!("{:?}", DeterministicTrace(&trace_from_fragments)),
        format!("{:?}", DeterministicTrace(&trace_from_single_fragment)),
        "Deterministic trace mismatch between fragments and single fragment"
    );

    // Build the LogUp aux trace from each main trace under identical random challenges and
    // verify every column matches row-for-row. Catches fragment-boundary nondeterminism in
    // lookup collection that `DeterministicTrace` (main-trace only) would miss.
    let raw = rand_array::<Felt, 4>();
    let challenges = [QuadFelt::new([raw[0], raw[1]]), QuadFelt::new([raw[2], raw[3]])];
    let (core_from_fragments, chip_from_fragments) =
        trace_from_fragments.main_trace().to_core_chiplets_matrices();
    let (core_from_single, chip_from_single) =
        trace_from_single_fragment.main_trace().to_core_chiplets_matrices();
    for (label, air_frag, air_single) in [
        ("Core", &core_from_fragments, &core_from_single),
        ("Chiplets", &chip_from_fragments, &chip_from_single),
    ] {
        let (aux_frag, committed_frag, aux_single, committed_single) = if label == "Core" {
            let (a, c) = build_logup_aux_trace(&MidenAir::CORE, air_frag, &challenges);
            let (b, d) = build_logup_aux_trace(&MidenAir::CORE, air_single, &challenges);
            (a, c, b, d)
        } else {
            let (a, c) = build_logup_aux_trace(&MidenAir::CHIPLETS, air_frag, &challenges);
            let (b, d) = build_logup_aux_trace(&MidenAir::CHIPLETS, air_single, &challenges);
            (a, c, b, d)
        };
        assert_eq!(
            aux_frag.values, aux_single.values,
            "{label} LogUp aux trace mismatch between fragments and single fragment"
        );
        assert_eq!(
            committed_frag, committed_single,
            "{label} LogUp committed finals mismatch between fragments and single fragment"
        );
    }

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
        "expected an END row for inner loop node (is_loop_body=1, is_loop=1)"
    );
    assert!(
        end_flags.contains(&[ZERO, ONE, ZERO, ZERO].into()),
        "expected an END row for outer loop node (is_loop_body=0, is_loop=1)"
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
    )
    .expect("processor advice inputs should fit advice map limits");
    let mut host = DefaultHost::default();
    host.load_library(create_simple_library()).unwrap();

    let trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    assert!(
        trace_inputs.trace_generation_context().core_trace_contexts.len() > 1,
        "repro precondition requires multiple fragments"
    );

    let trace = build_trace(trace_inputs).unwrap();
    let total_rows_without_halt = trace.main_trace().core_height() - 1;

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
    )
    .expect("processor advice inputs should fit advice map limits");
    let mut host = DefaultHost::default();
    host.load_library(create_simple_library()).unwrap();
    let trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    assert!(trace_inputs.trace_generation_context().core_trace_contexts.len() > 1);

    let _ = build_trace(trace_inputs);
}

/// Creates a library with a single procedure containing just a SWAP operation.
fn create_simple_library() -> HostLibrary {
    let mut mast_forest = MastForest::new();
    let swap_block = BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
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

    let basic_block_mul = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut program)
        .unwrap();
    let basic_block_add = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut program)
        .unwrap();
    let basic_block_swap = BasicBlockNodeBuilder::new(vec![Operation::Swap])
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
            BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
                .add_to_forest(&mut program)
                .unwrap();

        let target_split_node = {
            let basic_block_add = BasicBlockNodeBuilder::new(vec![Operation::Add])
                .add_to_forest(&mut program)
                .unwrap();
            let basic_block_swap = BasicBlockNodeBuilder::new(vec![Operation::Swap])
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
            BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
                .add_to_forest(&mut program)
                .unwrap();

        let target_loop_node = {
            let basic_block_pad_drop =
                BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop])
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
            BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop])
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
            BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
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
            BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
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
        let target_basic_block =
            BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Push(Felt::from_u32(42))])
                .add_to_forest(&mut program)
                .unwrap();
        let basic_block_drop = BasicBlockNodeBuilder::new(vec![Operation::Drop])
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
        let target_basic_block = BasicBlockNodeBuilder::new(vec![Operation::Swap; NUM_SWAPS])
            .add_to_forest(&mut program)
            .unwrap();
        let basic_block_drop = BasicBlockNodeBuilder::new(vec![Operation::Drop])
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
    const HASH_ADDR: Felt = Felt::new_unchecked(40);

    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block = BasicBlockNodeBuilder::new(vec![
            Operation::Push(HASH_ADDR),
            Operation::MStoreW,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Push(HASH_ADDR),
        ])
        .add_to_forest(&mut program)
        .unwrap();

        let dyn_node = DynNodeBuilder::new_dyn().add_to_forest(&mut program).unwrap();

        JoinNodeBuilder::new([basic_block, dyn_node])
            .add_to_forest(&mut program)
            .unwrap()
    };
    program.make_root(root_join_node);

    // Add the procedure that DYN will call. Its digest is computed by dyn_target_proc_hash().
    let target = BasicBlockNodeBuilder::new(vec![Operation::Swap])
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
    const HASH_ADDR: Felt = Felt::new_unchecked(40);

    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block = BasicBlockNodeBuilder::new(vec![
            Operation::Push(HASH_ADDR),
            Operation::MStoreW,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Push(HASH_ADDR),
        ])
        .add_to_forest(&mut program)
        .unwrap();

        let dyncall_node = DynNodeBuilder::new_dyncall().add_to_forest(&mut program).unwrap();

        JoinNodeBuilder::new([basic_block, dyncall_node])
            .add_to_forest(&mut program)
            .unwrap()
    };
    program.make_root(root_join_node);

    // Add the procedure that DYNCALL will call. Its digest is computed by dyn_target_proc_hash().
    let target = BasicBlockNodeBuilder::new(vec![Operation::Swap])
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
            BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop])
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
    )
    .expect("processor advice inputs should fit advice map limits");
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
    )
    .expect("processor advice inputs should fit advice map limits");
    let mut host = DefaultHost::default();
    let mut trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    // Inject a HashBasicBlock entry that references the executed program's forest (id 0 in the
    // store, which the tracer always populates with the entrypoint's forest) with a node ID that
    // is well past any node actually in the sparse forest.
    let bogus_node_id = MastNodeId::new_unchecked(u32::MAX);
    let forest_id = MastForestId::from(0u32);
    trace_inputs
        .trace_generation_context_mut()
        .hasher_for_chiplet
        .record_hash_basic_block(forest_id, bogus_node_id, [ZERO; 4].into());

    let result = build_trace(trace_inputs);
    assert!(
        result.is_err(),
        "build_trace should return Err when hasher replay has bad node ID"
    );
}

/// Where to tamper with a [`miden_core::mast::MastForestId`] in a [`TraceBuildInputs`].
#[derive(Debug, Clone, Copy)]
enum BadForestIdLocation {
    /// Replace the first fragment's `initial_mast_forest_id`.
    InitialForestId,
    /// Replace the forest id of the first entry in the first fragment's `mast_forest_resolution`
    /// replay (DYN/External resolution path).
    ResolutionReplay,
}

/// Verifies that `build_trace` returns `Err` (instead of panicking) when a fragment carries a
/// [`miden_core::mast::MastForestId`] that does not exist in `mast_forest_store`.
///
/// `CoreTraceFragmentContext` can come from outside this process (e.g. when serialized and
/// rebuilt), and so its [`miden_core::mast::MastForestId`]s must be treated as
/// untrusted/attacker-controlled. Both the up-front ids (`initial_mast_forest_id`, continuation
/// stack) and the per-resolution ids in `mast_forest_resolution` (the DYN/External path that is
/// most likely to be hit when libraries are involved) must be validated rather than indexed
/// into, and the error must propagate up through `build_trace`.
#[rstest]
#[case::initial_forest_id(
    basic_block_program_small(),
    DEFAULT_STACK,
    false,
    BadForestIdLocation::InitialForestId
)]
#[case::dyn_resolution(
    dyn_program(),
    external_lib_proc_hash_for_stack(),
    true,
    BadForestIdLocation::ResolutionReplay
)]
#[case::external_resolution(
    external_program(),
    DEFAULT_STACK,
    true,
    BadForestIdLocation::ResolutionReplay
)]
fn test_build_trace_returns_err_on_invalid_mast_forest_id(
    #[case] program: Program,
    #[case] stack_inputs: &[Felt],
    #[case] load_library: bool,
    #[case] tamper_at: BadForestIdLocation,
) {
    const MAX_FRAGMENT_SIZE: usize = 1 << 20;

    let processor = FastProcessor::new_with_options(
        StackInputs::new(stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(MAX_FRAGMENT_SIZE)
            .unwrap(),
    )
    .expect("processor advice inputs should fit advice map limits");
    let mut host = DefaultHost::default();
    if load_library {
        host.load_library(create_simple_library()).unwrap();
    }
    let mut trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    let store_len = trace_inputs.trace_generation_context().mast_forest_store.len();
    let bogus_forest_id = MastForestId::from(store_len as u32);
    let ctx = &mut trace_inputs.trace_generation_context_mut().core_trace_contexts[0];
    match tamper_at {
        BadForestIdLocation::InitialForestId => {
            ctx.initial_mast_forest_id = bogus_forest_id;
        },
        BadForestIdLocation::ResolutionReplay => {
            let resolution = &mut ctx.replay.mast_forest_resolution;
            let mut entries = Vec::new();
            while let Ok(entry) = resolution.replay_resolution() {
                entries.push(entry);
            }
            assert!(!entries.is_empty(), "expected at least one resolution to tamper with");
            entries[0].1 = bogus_forest_id;
            for (node_id, forest_id) in entries {
                resolution.record_resolution(node_id, forest_id);
            }
        },
    }

    let result = build_trace(trace_inputs);
    assert!(
        result.is_err(),
        "build_trace should return Err when a fragment carries a MastForestId out of range of \
         the mast_forest_store"
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
    )
    .expect("processor advice inputs should fit advice map limits");
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
    )
    .expect("processor advice inputs should fit advice map limits");
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
    )
    .expect("processor advice inputs should fit advice map limits");
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
    )
    .expect("processor advice inputs should fit advice map limits");
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
    )
    .expect("processor advice inputs should fit advice map limits");
    let mut host = DefaultHost::default();
    host.load_library(create_simple_library()).unwrap();
    let trace_inputs = processor.execute_trace_inputs_sync(program, &mut host).unwrap();

    build_trace(trace_inputs).unwrap()
}

fn collect_end_flags(trace: &ExecutionTrace) -> Vec<Word> {
    let main_trace = trace.main_trace();

    (0..main_trace.core_height())
        .filter_map(|row_idx| {
            let idx = RowIndex::from(row_idx);
            if read_opcode(main_trace, idx) == opcodes::END {
                Some(main_trace.decoder_hasher_state_second_half(idx))
            } else {
                None
            }
        })
        .collect()
}

fn read_opcode(main_trace: &MainTrace, row_idx: RowIndex) -> u8 {
    let opcode = main_trace.get_op_code(row_idx).as_canonical_u64();
    assert!(opcode <= u8::MAX as u64, "invalid opcode");
    opcode as u8
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

        f.debug_struct("ExecutionTrace")
            .field("main_trace", trace.main_trace())
            .field("program_info", &trace.program_info())
            .field("stack_outputs", &trace.stack_outputs())
            .field("deferred_root", &trace.deferred_state().root())
            .field("trace_len_summary", &trace.trace_len_summary())
            .finish()
    }
}
