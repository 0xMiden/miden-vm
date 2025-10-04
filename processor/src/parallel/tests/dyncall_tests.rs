use super::*;

/// Tests DYNCALL node fragment boundaries.
///
/// DYNCALL nodes are similar to DYN but also save/restore call context.
/// These tests verify fragment boundaries work correctly for dynamic calls with context management.

#[rstest]
// DYNCALL START
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
// DYNCALL END
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
fn test_dyncall_fragment_boundaries(
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
///     (block push(40) mem_storew drop drop drop drop push(40) noop noop)
///     (dyncall)
/// )
pub fn dyncall_program() -> Program {
    const HASH_ADDR: Felt = Felt::new(40);

    let mut program = MastForest::new();

    let root_join_node = {
        let basic_block = program
            .add_block(
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
            .unwrap();

        let dyncall_node = program.add_dyncall().unwrap();

        program.add_join(basic_block, dyncall_node).unwrap()
    };
    program.make_root(root_join_node);

    // Add the procedure that DYNCALL will call. Its digest needs to be put on the stack at the
    // start of the program (stored in `DYN_TARGET_PROC_HASH`).
    let target = program.add_block(vec![Operation::Swap], Vec::new()).unwrap();
    program.make_root(target);

    Program::new(Arc::new(program), root_join_node)
}
