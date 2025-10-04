use super::*;

/// Tests basic block fragment boundaries.
///
/// Basic blocks contain sequences of operations. These tests verify fragment boundaries work
/// correctly when fragments start at various points within basic block execution, including
/// operation boundaries and RESPAN points.

#[rstest]
// BASIC BLOCK START
//  0: JOIN
//  1:   BLOCK SWAP PUSH(42) NOOP END
//  6:   BLOCK DROP END
//  9: END
// 10: HALT
#[case(basic_block_program_small(), 1, DEFAULT_STACK)]
// BASIC BLOCK FIRST OP
//  0: JOIN
//  1:   BLOCK SWAP PUSH(42) NOOP END
//  6:   BLOCK DROP END
//  9: END
// 10: HALT
#[case(basic_block_program_small(), 2, DEFAULT_STACK)]
// BASIC BLOCK SECOND OP
//  0: JOIN
//  1:   BLOCK SWAP PUSH(42) NOOP END
//  6:   BLOCK DROP END
//  9: END
// 10: HALT
#[case(basic_block_program_small(), 3, DEFAULT_STACK)]
// BASIC BLOCK INSERTED NOOP
//  0: JOIN
//  1:   BLOCK SWAP PUSH(42) NOOP END
//  6:   BLOCK DROP END
//  9: END
// 10: HALT
#[case(basic_block_program_small(), 4, DEFAULT_STACK)]
// BASIC BLOCK END
//  0: JOIN
//  1:   BLOCK SWAP PUSH(42) NOOP END
//  6:   BLOCK DROP END
//  9: END
// 10: HALT
#[case(basic_block_program_small(), 5, DEFAULT_STACK)]
// BASIC BLOCK RESPAN
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
// BASIC BLOCK OP IN 2nd BATCH
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
fn test_basic_block_fragment_boundaries(
    testname: String,
    #[case] program: Program,
    #[case] fragment_size: usize,
    #[case] stack_inputs: &[Felt],
) {
    test_fragment_boundary_trace_consistency(&program, fragment_size, stack_inputs);
    insta::assert_compact_debug_snapshot!(testname, {
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
    });
}

/// (join (
///     (block swap push(42) noop)
///     (block drop)
/// )
pub fn basic_block_program_small() -> Program {
    let mut program = MastForest::new();

    let root_join_node = {
        let target_basic_block = program
            .add_block(vec![Operation::Swap, Operation::Push(42_u32.into())], Vec::new())
            .unwrap();
        let basic_block_drop = program.add_block(vec![Operation::Drop], Vec::new()).unwrap();

        program.add_join(target_basic_block, basic_block_drop).unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}

/// (join (
///     (block <80 swaps>)
///     (block drop)
/// )
pub fn basic_block_program_multiple_batches() -> Program {
    /// Number of swaps should be greater than the max number of operations per batch (72), to
    /// ensure that we have at least one RESPAN.
    const NUM_SWAPS: usize = 80;
    let mut program = MastForest::new();

    let root_join_node = {
        let target_basic_block =
            program.add_block(vec![Operation::Swap; NUM_SWAPS], Vec::new()).unwrap();
        let basic_block_drop = program.add_block(vec![Operation::Drop], Vec::new()).unwrap();

        program.add_join(target_basic_block, basic_block_drop).unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}
