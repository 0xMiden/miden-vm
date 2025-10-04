use super::*;

/// Tests JOIN node fragment boundaries.
///
/// JOIN nodes execute two child nodes sequentially. These tests verify that fragment boundaries
/// work correctly when fragments start/end at various points within JOIN execution.

#[rstest]
// Tests the trace fragment generation for when a fragment starts in the start phase of a
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
// Tests the trace fragment generation for when a fragment starts in the finish phase of a
// Join node. Same execution as previous case, but we want the 2nd fragment to start at clk=11,
// which is the END of the inner Join node.
#[case(join_program(), 11, DEFAULT_STACK)]
fn test_join_fragment_boundaries(
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
///     (block mul)
///     (join (block add) (block swap))
/// )
pub fn join_program() -> Program {
    let mut program = MastForest::new();

    let basic_block_mul = program.add_block(vec![Operation::Mul], Vec::new()).unwrap();
    let basic_block_add = program.add_block(vec![Operation::Add], Vec::new()).unwrap();
    let basic_block_swap = program.add_block(vec![Operation::Swap], Vec::new()).unwrap();

    let target_join_node = program.add_join(basic_block_add, basic_block_swap).unwrap();

    let root_join_node = program.add_join(basic_block_mul, target_join_node).unwrap();
    program.make_root(root_join_node);

    Program::new(Arc::new(program), root_join_node)
}
