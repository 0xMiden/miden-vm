use super::*;

/// Tests CALL node fragment boundaries.
///
/// CALL nodes execute a procedure and return to the caller.
/// These tests verify fragment boundaries work correctly for call entry and return.

#[rstest]
// CALL START
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   CALL
//  6:     BLOCK SWAP SWAP END
// 10:   END
// 11: END
// 12: HALT
#[case(call_program(), 5, DEFAULT_STACK)]
// CALL END
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   CALL
//  6:     BLOCK SWAP SWAP END
// 10:   END
// 11: END
// 12: HALT
#[case(call_program(), 10, DEFAULT_STACK)]
fn test_call_fragment_boundaries(
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
///     (call (<previous block>))
/// )
pub fn call_program() -> Program {
    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block_swap_swap =
            program.add_block(vec![Operation::Swap, Operation::Swap], Vec::new()).unwrap();

        let target_call_node = program.add_call(basic_block_swap_swap).unwrap();

        program.add_join(basic_block_swap_swap, target_call_node).unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}
