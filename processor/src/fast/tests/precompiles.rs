use miden_core::deferred::{DeferredError, Node, PrecompileError, TRUE_DIGEST};

use super::*;

#[test]
fn clear_deferred_in_kernel_preserves_stack() {
    // Production epilogues must recursively verify the stack root before clearing it.
    let source_manager = Arc::new(DefaultSourceManager::default());
    let kernel =
        parse_kernel_source(source_manager.clone(), "pub proc epilogue clear_deferred end");
    let kernel_lib = Arc::<Package>::from(
        Assembler::new(source_manager.clone())
            .assemble_kernel("kernel", kernel, None)
            .unwrap(),
    );
    let program = Assembler::with_kernel(source_manager, kernel_lib.clone())
        .unwrap()
        .assemble_program(
            "program",
            "proc worker syscall.epilogue end begin log_deferred call.worker end",
        )
        .unwrap()
        .unwrap_program();
    let stack_inputs = [0, 0, 0, 0, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16].map(Felt::from_u32);
    let mut host = DefaultHost::default();
    host.load_library(kernel_lib.mast_forest()).unwrap();
    let output = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap())
        .execute_sync(&program, &mut host)
        .unwrap();

    assert_eq!(output.precompile_root(), TRUE_DIGEST);
    assert!(output.precompile_witness.is_none());
    assert_eq!(output.stack.get_word(0), Some(Node::and(TRUE_DIGEST, TRUE_DIGEST).digest()));
    for (offset, expected) in stack_inputs.iter().copied().enumerate().skip(4) {
        assert_eq!(output.stack.get_element(offset), Some(expected));
    }
}

#[test]
fn clear_deferred_rejects_invalid_context_or_root() {
    for source in [
        "proc worker clear_deferred end begin call.worker end",
        "begin push.1 clear_deferred end",
    ] {
        let program = Assembler::default()
            .assemble_program("program", source)
            .unwrap()
            .unwrap_program();
        let error = FastProcessor::new(StackInputs::default())
            .execute_sync(&program, &mut DefaultHost::default())
            .unwrap_err();
        assert_matches!(
            error,
            ExecutionError::OperationError {
                err: OperationError::ClearDeferredOutsideRootContext { .. }
                    | OperationError::Deferred(PrecompileError::Other(
                        DeferredError::InvalidDeferredRootReset { .. }
                    )),
                ..
            }
        );
    }
}
