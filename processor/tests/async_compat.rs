use std::sync::Arc;

use miden_assembly::Assembler;
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    BaseHost, DefaultHost, ExecutionOptions, FastProcessor, Felt, FutureMaybeSend, Host,
    ProcessorState, StackInputs, Word,
    advice::{AdviceInputs, AdviceMutation},
    event::{EventError, EventName},
    mast::MastForest,
};

struct YieldingAsyncHost {
    event_calls: usize,
}

impl YieldingAsyncHost {
    fn new() -> Self {
        Self { event_calls: 0 }
    }
}

impl BaseHost for YieldingAsyncHost {
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl Host for YieldingAsyncHost {
    fn get_mast_forest(
        &self,
        _node_digest: &Word,
    ) -> impl FutureMaybeSend<Option<Arc<MastForest>>> {
        async { None }
    }

    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        self.event_calls += 1;
        async {
            tokio::task::yield_now().await;
            Ok(Vec::new())
        }
    }
}

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
    let sync_output = miden_processor::execute_sync(
        &program,
        stack_inputs,
        advice_inputs.clone(),
        &mut sync_host,
        ExecutionOptions::default(),
    )
    .unwrap();

    let mut async_host = DefaultHost::default();
    let async_output = miden_processor::execute(
        &program,
        stack_inputs,
        advice_inputs,
        &mut async_host,
        ExecutionOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(sync_output.stack, async_output.stack);
}

#[tokio::test(flavor = "current_thread")]
async fn fast_processor_execute_for_trace_async_matches_sync() {
    let program = simple_program();
    let stack_inputs = StackInputs::new(&[Felt::new(3)]).unwrap();

    let mut sync_host = DefaultHost::default();
    let sync_trace_inputs = FastProcessor::new(stack_inputs)
        .execute_trace_inputs_sync(&program, &mut sync_host)
        .unwrap();

    let mut async_host = DefaultHost::default();
    let async_trace_inputs = FastProcessor::new(stack_inputs)
        .execute_trace_inputs(&program, &mut async_host)
        .await
        .unwrap();

    assert_eq!(
        sync_trace_inputs.execution_output().stack,
        async_trace_inputs.execution_output().stack
    );
    assert_eq!(
        sync_trace_inputs.trace_generation_context().fragment_size,
        async_trace_inputs.trace_generation_context().fragment_size
    );
    assert_eq!(
        sync_trace_inputs.trace_generation_context().core_trace_contexts.len(),
        async_trace_inputs.trace_generation_context().core_trace_contexts.len()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn execute_async_supports_async_only_host_events() {
    let event_name = EventName::new("test::async::emit");
    let event_id = event_name.to_event_id().as_u64();
    let program = Assembler::default()
        .assemble_program(format!("begin push.{event_id} emit drop end"))
        .expect("program should compile");

    let mut host = YieldingAsyncHost::new();
    let output = FastProcessor::new(StackInputs::default())
        .execute(&program, &mut host)
        .await
        .expect("async execution should succeed");

    assert_eq!(host.event_calls, 1);
    assert_eq!(output.stack.get_num_elements(16).len(), 16);
}
