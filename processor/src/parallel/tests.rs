use alloc::{string::String, sync::Arc};
use std::string::ToString;

use miden_core::{
    Kernel, Operation, Program,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder,
        JoinNodeBuilder, LoopNodeBuilder, MastForest, MastForestContributor, MastNodeExt,
        SplitNodeBuilder,
    },
};
use miden_utils_testing::get_column_name;
use pretty_assertions::assert_eq;
use rstest::{fixture, rstest};
use winter_prover::Trace;

use super::*;
use crate::{DefaultHost, HostLibrary, fast::FastProcessor};

const DEFAULT_STACK: &[Felt] = &[Felt::new(1), Felt::new(2), Felt::new(3)];

/// The procedure that DYN and DYNCALL will call in the tests below. Its digest needs to be put on
/// the stack before the call.
const DYN_TARGET_PROC_HASH: &[Felt] = &[
    Felt::new(10995436151082118190),
    Felt::new(776663942277617877),
    Felt::new(3177713792132750309),
    Felt::new(10407898805173442467),
];

/// The digest of a procedure available to be called via an EXTERNAL node.
const EXTERNAL_LIB_PROC_DIGEST: Word = Word::new([
    Felt::new(9552974201798903089),
    Felt::new(993192251238261044),
    Felt::new(1885027269046469428),
    Felt::new(8558115384207742312),
]);

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
#[case(split_program(), 5, &[ZERO])]
// Case 5: Tests the trace fragment generation for when a fragment starts in the finish phase of a
// Join node. Same execution as case 3, but we want the 2nd fragment to start at the END of the
// SPLIT node.
#[case(split_program(), 9, &[ONE])]
// Case 6: Tests the trace fragment generation for when a fragment starts in the finish phase of a
// Join node. Same execution as case 4, but we want the 2nd fragment to start at the END of the
// SPLIT node.
#[case(split_program(), 9, &[ZERO])]
// Case 7: LOOP start
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP END
//  7: END
//  8: HALT
#[case(loop_program(), 5, &[ZERO])]
// Case 8: LOOP END, when loop was not entered
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP END
//  7: END
//  8: HALT
#[case(loop_program(), 6, &[ZERO])]
// Case 9: LOOP END, when loop was entered
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP
//  6:     BLOCK PAD DROP END
// 10:   END
// 11: END
// 12: HALT
#[case(loop_program(), 10, &[ONE])]
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
#[case(loop_program(), 10, &[ONE, ONE])]
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
#[case(dyn_program(), 12, DYN_TARGET_PROC_HASH)]
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
#[case(dyn_program(), 16, DYN_TARGET_PROC_HASH)]
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
#[case(dyncall_program(), 12, DYN_TARGET_PROC_HASH)]
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
#[case(dyncall_program(), 16, DYN_TARGET_PROC_HASH)]
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
#[case(dyn_program(), 12, EXTERNAL_LIB_PROC_DIGEST.as_elements())]
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
        let processor = FastProcessor::new(stack_inputs);
        let mut host = DefaultHost::default();
        host.load_library(create_simple_library()).unwrap();
        let (execution_output, trace_fragment_contexts) =
            processor.execute_for_trace_sync(&program, &mut host, fragment_size).unwrap();

        build_trace(
            execution_output,
            trace_fragment_contexts,
            program.hash(),
            program.kernel().clone(),
        )
    };

    let trace_from_single_fragment = {
        let processor = FastProcessor::new(stack_inputs);
        let mut host = DefaultHost::default();
        host.load_library(create_simple_library()).unwrap();
        let (execution_output, trace_fragment_contexts) = processor
            .execute_for_trace_sync(&program, &mut host, MAX_FRAGMENT_SIZE)
            .unwrap();
        assert!(trace_fragment_contexts.core_trace_contexts.len() == 1);

        build_trace(
            execution_output,
            trace_fragment_contexts,
            program.hash(),
            program.kernel().clone(),
        )
    };

    // Ensure that the trace generated from multiple fragments is identical to the one generated
    // from a single fragment.
    for (col_idx, (col_from_fragments, col_from_single_fragment)) in trace_from_fragments
        .main_segment()
        .columns()
        .zip(trace_from_single_fragment.main_segment().columns())
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
                "Trace columns do not match between trace generated as multiple fragments vs a single fragment at column {} ({}): different lengths (slow={}, parallel={})",
                col_idx,
                get_column_name(col_idx),
                col_from_fragments.len(),
                col_from_single_fragment.len()
            );
        }
    }

    // Sanity check to ensure that the traces are identical.
    assert_eq!(format!("{trace_from_fragments:?}"), format!("{trace_from_single_fragment:?}"));

    // Snapshot testing to ensure that future changes don't unexpectedly change the trace.
    insta::assert_compact_debug_snapshot!(testname, trace_from_fragments);
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
            vec![Operation::Swap, Operation::Push(42_u32.into())],
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
///     (block push(40) mem_storew_be drop drop drop drop push(40) noop noop)
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

    // Add the procedure that DYN will call. Its digest needs to be put on the stack at the start of
    // the program (stored in `DYN_TARGET_PROC_HASH`).
    let target = BasicBlockNodeBuilder::new(vec![Operation::Swap], Vec::new())
        .add_to_forest(&mut program)
        .unwrap();
    program.make_root(target);

    Program::new(Arc::new(program), root_join_node)
}

/// (join (
///     (block push(40) mem_storew_be drop drop drop drop push(40) noop noop)
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

    // Add the procedure that DYN will call. Its digest needs to be put on the stack at the start of
    // the program (stored in `DYN_TARGET_PROC_HASH`).
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

        let external_node = ExternalNodeBuilder::new(EXTERNAL_LIB_PROC_DIGEST)
            .add_to_forest(&mut program)
            .unwrap();

        JoinNodeBuilder::new([basic_block_pad_drop, external_node])
            .add_to_forest(&mut program)
            .unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}

// Workaround to make insta and rstest work together.
// See: https://github.com/la10736/rstest/issues/183#issuecomment-1564088329
#[fixture]
fn testname() -> String {
    std::thread::current().name().unwrap().to_string()
}
