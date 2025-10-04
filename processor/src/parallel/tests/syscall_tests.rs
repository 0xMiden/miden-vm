use super::*;

/// Tests SYSCALL node fragment boundaries.
///
/// SYSCALL nodes are similar to CALL but execute in a special kernel context.
/// These tests verify fragment boundaries work correctly for syscall entry and return.

#[rstest]
// SYSCALL START
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   SYSCALL
//  6:     BLOCK SWAP SWAP END
// 10:   END
// 11: END
// 12: HALT
#[case(syscall_program(), 5, DEFAULT_STACK)]
// SYSCALL END
//  0: JOIN
//  1:   BLOCK SWAP SWAP END
//  5:   SYSCALL
//  6:     BLOCK SWAP SWAP END
// 10:   END
// 11: END
// 12: HALT
#[case(syscall_program(), 10, DEFAULT_STACK)]
fn test_syscall_fragment_boundaries(
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
///     (syscall (<previous block>))
/// )
pub fn syscall_program() -> Program {
    let mut program = MastForest::new();

    let (root_join_node, kernel_proc_digest) = {
        // In this test, we also include this procedure in the kernel so that it can be syscall'ed.
        let basic_block_swap_swap =
            program.add_block(vec![Operation::Swap, Operation::Swap], Vec::new()).unwrap();

        let target_call_node = program.add_syscall(basic_block_swap_swap).unwrap();

        let root_join_node = program.add_join(basic_block_swap_swap, target_call_node).unwrap();

        (root_join_node, program[basic_block_swap_swap].digest())
    };

    program.make_root(root_join_node);

    Program::with_kernel(
        Arc::new(program),
        root_join_node,
        Kernel::new(&[kernel_proc_digest]).unwrap(),
    )
}
