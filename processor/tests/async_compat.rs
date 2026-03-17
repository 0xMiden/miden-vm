use miden_assembly::Assembler;
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, Felt, StackInputs, advice::AdviceInputs,
};

fn simple_program() -> miden_processor::Program {
    Assembler::default()
        .assemble_program(
            r#"
            begin
                push.2
                add
            end
            "#,
        )
        .expect("program should compile")
}

#[tokio::test(flavor = "current_thread")]
async fn execute_async_matches_execute() {
    let program = simple_program();
    let stack_inputs = StackInputs::new(&[Felt::new(3)]).unwrap();
    let advice_inputs = AdviceInputs::default();

    let mut sync_host = DefaultHost::default();
    let sync_trace = miden_processor::execute(
        &program,
        stack_inputs,
        advice_inputs.clone(),
        &mut sync_host,
        ExecutionOptions::default(),
    )
    .unwrap();

    let mut async_host = DefaultHost::default();
    let async_trace = miden_processor::execute_async(
        &program,
        stack_inputs,
        advice_inputs,
        &mut async_host,
        ExecutionOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(sync_trace.stack_outputs(), async_trace.stack_outputs());
}

#[tokio::test(flavor = "current_thread")]
async fn fast_processor_execute_for_trace_async_matches_sync() {
    let program = simple_program();
    let stack_inputs = StackInputs::new(&[Felt::new(3)]).unwrap();

    let mut sync_host = DefaultHost::default();
    let (sync_output, sync_ctx) = FastProcessor::new(stack_inputs)
        .execute_for_trace(&program, &mut sync_host)
        .unwrap();

    let mut async_host = DefaultHost::default();
    let (async_output, async_ctx) = FastProcessor::new(stack_inputs)
        .execute_for_trace_async(&program, &mut async_host)
        .await
        .unwrap();

    assert_eq!(sync_output.stack, async_output.stack);
    assert_eq!(sync_ctx.fragment_size, async_ctx.fragment_size);
    assert_eq!(sync_ctx.core_trace_contexts.len(), async_ctx.core_trace_contexts.len());
}
