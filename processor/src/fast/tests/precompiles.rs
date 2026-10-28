use miden_core::deferred::{DeferredError, PrecompileError, TRUE_DIGEST};

use super::*;

#[test]
fn clear_deferred_in_kernel_preserves_stack() {
    // Production epilogues must recursively verify the stack root before clearing it.
    let test = build_test!(
        "proc worker syscall.epilogue end
         begin
            push.1.2.3.4 padw log_deferred call.worker
            dropw push.1.2.3.4 assert_eqw
         end"
    )
    .with_kernel(
        "pub proc epilogue
            adv.push_deferred_root clear_deferred
            dupw dupw adv_loadw assert_eqw
        end",
    );
    let trace = test.execute().unwrap();
    assert_eq!(trace.precompile_root(), TRUE_DIGEST);
    assert_eq!(trace.stack_outputs().get_num_elements(16), &[ZERO; 16]);
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
