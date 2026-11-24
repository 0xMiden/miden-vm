use std::sync::Arc;

use miden_assembly::Assembler;
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    BaseHost, DefaultHost, ExecutionOptions, Felt, FutureMaybeSend, Host, LoadedMastForest,
    MastForestLoadError, Processor, ProcessorState, StackInputs, Word,
    advice::{AdviceInputs, AdviceMutation},
    event::{EventError, EventName, TraceError},
};

struct YieldingAsyncHost {
    event_calls: usize,
    trace_calls: usize,
}

impl YieldingAsyncHost {
    fn new() -> Self {
        Self { event_calls: 0, trace_calls: 0 }
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
    ) -> impl FutureMaybeSend<Result<Option<LoadedMastForest>, MastForestLoadError>> {
        async { Ok(None) }
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

    fn on_trace(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<(), TraceError>> {
        async move {
            tokio::task::yield_now().await;
            self.trace_calls += 1;
            Ok(())
        }
    }
}

fn simple_program() -> miden_processor::Program {
    Assembler::default()
        .assemble_program(
            "program",
            r#"
            begin
                push.2
                add
            end
            "#,
        )
        .expect("program should compile")
        .unwrap_program()
}

fn emit_trace_program() -> miden_processor::Program {
    let trace_name = "test::async::trace_emit";

    Assembler::default()
        .assemble_program("program", format!("begin trace.event(\"{trace_name}\") end"))
        .expect("program should compile")
        .unwrap_program()
}

#[tokio::test(flavor = "current_thread")]
async fn execute_async_matches_execute() {
    let program = simple_program();
    let stack_inputs = StackInputs::new(&[Felt::new_unchecked(3)]).unwrap();
    let execute = || Processor::new(&program).with_stack_inputs(stack_inputs).execute();
    let sync_output = execute().run_sync(&mut DefaultHost::default()).unwrap();
    let async_output = execute().run(&mut DefaultHost::default()).await.unwrap();

    assert_eq!(sync_output.stack, async_output.stack);
}

#[tokio::test(flavor = "current_thread")]
async fn witness_recording_async_matches_sync() {
    let program = simple_program();
    let stack_inputs = StackInputs::new(&[Felt::new_unchecked(3)]).unwrap();

    let mut sync_host = DefaultHost::default();
    let sync_witness = Processor::new(&program)
        .with_stack_inputs(stack_inputs)
        .record_witness()
        .run_sync(&mut sync_host)
        .map(|output| output.witness)
        .unwrap();

    let mut async_host = DefaultHost::default();
    let async_witness = Processor::new(&program)
        .with_stack_inputs(stack_inputs)
        .record_witness()
        .run(&mut async_host)
        .await
        .map(|output| output.witness)
        .unwrap();

    assert_eq!(sync_witness.claim().stack_outputs(), async_witness.claim().stack_outputs());
    let (sync_vm_witness, _) = sync_witness.into_parts();
    let (async_vm_witness, _) = async_witness.into_parts();
    let budget = miden_vm_stark::memory::default_budget();
    let sync_trace = sync_vm_witness.build_trace(&budget).unwrap();
    let async_trace = async_vm_witness.build_trace(&budget).unwrap();

    assert_eq!(sync_trace.public_inputs(), async_trace.public_inputs());
    assert_eq!(sync_trace.trace_len_summary(), async_trace.trace_len_summary());
    for (sync_column, async_column) in
        sync_trace.main_trace().columns().zip(async_trace.main_trace().columns())
    {
        assert_eq!(sync_column, async_column);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn trace_building_with_async_only_host_matches_buffered_sync() {
    let program = emit_trace_program();
    let budget = miden_vm_stark::memory::default_budget();
    let processor = || {
        Processor::new(&program)
            .with_advice(AdviceInputs::default().with_map([(Word::empty(), vec![Felt::ONE])]))
    };

    let sync_output = processor()
        .with_options(ExecutionOptions::default().with_overlapped_trace_build(false))
        .build_trace(budget)
        .run_sync(&mut DefaultHost::default())
        .unwrap();
    let mut async_host = YieldingAsyncHost::new();
    let async_output = processor().build_trace(budget).run(&mut async_host).await.unwrap();

    assert_eq!(async_host.trace_calls, 1);
    assert_eq!(async_output.claim, sync_output.claim);
    assert_eq!(async_output.advice, sync_output.advice);
    assert_eq!(
        async_output.advice.get_mapped_values(&Word::empty()),
        Some([Felt::ONE].as_slice())
    );
    assert_eq!(
        async_output.trace.into_vm_trace().into_air_matrices(),
        sync_output.trace.into_vm_trace().into_air_matrices(),
    );
}

#[tokio::test(flavor = "current_thread")]
async fn execute_async_supports_async_only_host_events() {
    let event_name = EventName::new("test::async::emit");
    let event_id = event_name.to_event_id().as_u64();
    let program = Assembler::default()
        .assemble_program("program", format!("begin push.{event_id} emit drop end"))
        .expect("program should compile")
        .unwrap_program();

    let mut host = YieldingAsyncHost::new();
    let output = Processor::new(&program)
        .execute()
        .run(&mut host)
        .await
        .expect("async execution should succeed");

    assert_eq!(host.event_calls, 1);
    assert_eq!(output.stack.get_num_elements(16).len(), 16);
}

#[tokio::test(flavor = "current_thread")]
async fn execute_async_supports_async_only_host_traces() {
    let program = emit_trace_program();

    let mut host = YieldingAsyncHost::new();
    let output = Processor::new(&program)
        .execute()
        .run(&mut host)
        .await
        .expect("async execution should succeed");

    assert_eq!(host.trace_calls, 1);
    assert_eq!(output.stack.get_num_elements(16).len(), 16);
}
