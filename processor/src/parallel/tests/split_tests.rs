use super::*;

/// Tests SPLIT node fragment boundaries.
///
/// SPLIT nodes conditionally execute one of two child nodes based on a stack value.
/// These tests verify fragment boundaries work correctly for both true and false branches,
/// and for fragments starting at various points in SPLIT execution.

#[rstest]
// Tests the trace fragment generation for when a fragment starts in the start phase of a
// Split node (i.e. clk 5). Execution:
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   SPLIT
//  6:     BLOCK ADD END
//  9:   END
// 10: END
// 11: HALT
#[case(split_program(), 5, &[ONE])]
// Similar to previous case, but we take the other branch of the Split node.
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   SPLIT
//  6:     BLOCK SWAP END
//  9:   END
// 10: END
// 11: HALT
#[case(split_program(), 5, &[ZERO])]
// Tests the trace fragment generation for when a fragment starts in the finish phase of a
// Join node. Same execution as case 3, but we want the 2nd fragment to start at the END of the
// SPLIT node.
#[case(split_program(), 9, &[ONE])]
// Tests the trace fragment generation for when a fragment starts in the finish phase of a
// Join node. Same execution as case 4, but we want the 2nd fragment to start at the END of the
// SPLIT node.
#[case(split_program(), 9, &[ZERO])]
fn test_split_fragment_boundaries(
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
///     (block swap swap)
///     (split (block add) (block swap))
/// )
pub fn split_program() -> Program {
    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block_swap_swap =
            program.add_block(vec![Operation::Swap, Operation::Swap], Vec::new()).unwrap();

        let target_split_node = {
            let basic_block_add = program.add_block(vec![Operation::Add], Vec::new()).unwrap();
            let basic_block_swap = program.add_block(vec![Operation::Swap], Vec::new()).unwrap();

            program.add_split(basic_block_add, basic_block_swap).unwrap()
        };

        program.add_join(basic_block_swap_swap, target_split_node).unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}
