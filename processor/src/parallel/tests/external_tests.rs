use super::*;

/// Tests EXTERNAL node fragment boundaries.
///
/// EXTERNAL nodes call procedures from external libraries.
/// These tests verify fragment boundaries work correctly for external procedure calls.

#[rstest]
// EXTERNAL NODE
//  0: JOIN
//  1:   BLOCK PAD DROP END
//  5:   EXTERNAL                 # NOTE: doesn't consume clock cycle
//  5:     BLOCK SWAP SWAP END
//  9:   END
// 10: END
// 11: HALT
#[case(external_program(), 5, DEFAULT_STACK)]
fn test_external_fragment_boundaries(
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
///     (block pad drop)
///     (call external(<external library procedure>))
/// )
///
/// external procedure: (block swap swap)
pub fn external_program() -> Program {
    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block_pad_drop =
            program.add_block(vec![Operation::Pad, Operation::Drop], Vec::new()).unwrap();

        let external_node = program.add_external(EXTERNAL_LIB_PROC_DIGEST).unwrap();

        program.add_join(basic_block_pad_drop, external_node).unwrap()
    };

    program.make_root(root_join_node);
    Program::new(Arc::new(program), root_join_node)
}
