use super::*;

/// Tests LOOP node fragment boundaries.
///
/// LOOP nodes repeatedly execute a body while a condition is true.
/// These tests verify fragment boundaries work correctly for loop entry, exit, and repetition.

#[rstest]
// LOOP start
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP END
//  7: END
//  8: HALT
#[case(loop_program(), 5, &[ZERO])]
// LOOP END, when loop was not entered
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP END
//  7: END
//  8: HALT
#[case(loop_program(), 6, &[ZERO])]
// LOOP END, when loop was entered
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   LOOP
//  6:     BLOCK PAD DROP END
// 10:   END
// 11: END
// 12: HALT
#[case(loop_program(), 10, &[ONE])]
// LOOP REPEAT
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
fn test_loop_fragment_boundaries(
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
///     (loop (block pad drop))
/// )
pub fn loop_program() -> Program {
    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block_swap_swap =
            program.add_block(vec![Operation::Swap, Operation::Swap], Vec::new()).unwrap();

        let target_loop_node = {
            let basic_block_pad_drop =
                program.add_block(vec![Operation::Pad, Operation::Drop], Vec::new()).unwrap();

            program.add_loop(basic_block_pad_drop).unwrap()
        };

        program.add_join(basic_block_swap_swap, target_loop_node).unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}
