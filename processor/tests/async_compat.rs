use std::sync::Arc;

use miden_assembly::Assembler;
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    BaseHost, DefaultHost, ExecutionOptions, FastProcessor, Felt, FutureMaybeSend, Host,
    LoadedMastForest, ProcessorState, StackInputs, Word,
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
    ) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
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
    let advice_inputs = AdviceInputs::default();

    let mut sync_host = DefaultHost::default();
    let sync_output = FastProcessor::new_with_options(
        stack_inputs,
        advice_inputs.clone(),
        ExecutionOptions::default(),
    )
    .expect("failed to construct FastProcessor")
    .execute_sync(&program, &mut sync_host)
    .unwrap();

    let mut async_host = DefaultHost::default();
    let async_output =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .expect("failed to construct FastProcessor")
            .execute(&program, &mut async_host)
            .await
            .unwrap();

    assert_eq!(sync_output.stack, async_output.stack);
}

#[tokio::test(flavor = "current_thread")]
async fn fast_processor_execute_for_proving_async_matches_sync() {
    let program = simple_program();
    let stack_inputs = StackInputs::new(&[Felt::new_unchecked(3)]).unwrap();

    let mut sync_host = DefaultHost::default();
    let sync_witness = FastProcessor::new(stack_inputs)
        .execute_for_proving_sync(&program, &mut sync_host)
        .unwrap();

    let mut async_host = DefaultHost::default();
    let async_witness = FastProcessor::new(stack_inputs)
        .execute_for_proving(&program, &mut async_host)
        .await
        .unwrap();

    assert_eq!(sync_witness.claim().stack_outputs(), async_witness.claim().stack_outputs());
    let (sync_vm_witness, _) = sync_witness.into_parts();
    let (async_vm_witness, _) = async_witness.into_parts();
    let sync_trace = miden_processor::trace::build_trace(sync_vm_witness).unwrap();
    let async_trace = miden_processor::trace::build_trace(async_vm_witness).unwrap();

    assert_eq!(sync_trace.public_inputs(), async_trace.public_inputs());
    assert_eq!(sync_trace.trace_len_summary(), async_trace.trace_len_summary());
    for (sync_column, async_column) in
        sync_trace.main_trace().columns().zip(async_trace.main_trace().columns())
    {
        assert_eq!(sync_column, async_column);
    }
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
    let output = FastProcessor::new(StackInputs::default())
        .execute(&program, &mut host)
        .await
        .expect("async execution should succeed");

    assert_eq!(host.event_calls, 1);
    assert_eq!(output.stack.get_num_elements(16).len(), 16);
}

#[tokio::test(flavor = "current_thread")]
async fn execute_async_supports_async_only_host_traces() {
    let program = emit_trace_program();

    let mut host = YieldingAsyncHost::new();
    let output = FastProcessor::new(StackInputs::default())
        .execute(&program, &mut host)
        .await
        .expect("async execution should succeed");

    assert_eq!(host.trace_calls, 1);
    assert_eq!(output.stack.get_num_elements(16).len(), 16);
}

const BOOKKEEPING: EventName = EventName::new("test::bookkeeping");

struct PortableAsyncHost {
    handlers: miden_processor::event::HandlerRegistry,
    calls: Vec<(miden_event_handler::InvocationKind, Felt)>,
    before_await: usize,
}

impl BaseHost for PortableAsyncHost {
    fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl Host for PortableAsyncHost {
    fn get_mast_forest(&self, _: &Word) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
        async { None }
    }

    fn handle_event(
        &mut self,
        context: miden_event_handler::EventContext<'_>,
        advice: &mut miden_event_handler::AdviceRecorder<'_>,
    ) -> impl FutureMaybeSend<Result<(), EventError>> {
        let registered = self.handlers.handle_event(context.id(), context, advice);
        if matches!(&registered, Ok(false)) {
            self.before_await += 1;
        }
        async move {
            if registered? {
                return Ok(());
            }
            tokio::task::yield_now().await;
            self.calls.push((context.kind(), context.stack_item(0)));
            if context.kind() == miden_event_handler::InvocationKind::Event
                && context.id() != BOOKKEEPING.to_event_id()
            {
                advice.prepend_stack([context.stack_item(0)]);
                // Reads continue to see pre-callback state after writes and across await.
                tokio::task::yield_now().await;
                assert!(context.advice_stack().is_empty());
            }
            Ok(())
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn portable_async_borrows_and_trace_suppression_preserve_regular_delivery() {
    use miden_event_handler::InvocationKind;
    let program = Assembler::default()
        .assemble_program(
            "program",
            r#"
        begin push.7 emit.event("test::portable") trace.event("test::portable") drop end
    "#,
        )
        .unwrap()
        .unwrap_program();
    for trace_delivery in [true, false] {
        let mut host = PortableAsyncHost {
            handlers: Default::default(),
            calls: vec![],
            before_await: 0,
        };
        let output = FastProcessor::new_with_options(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default().with_trace_delivery(trace_delivery),
        )
        .unwrap()
        .execute(&program, &mut host)
        .await
        .unwrap();
        assert_eq!(host.calls[0], (InvocationKind::Event, Felt::from_u32(7)));
        assert_eq!(host.calls.len(), if trace_delivery { 2 } else { 1 });
        assert_eq!(host.before_await, host.calls.len());
        if trace_delivery {
            assert_eq!(host.calls[1], (InvocationKind::Trace, Felt::from_u32(7)));
        }
        assert_eq!(output.stack.get_num_elements(16).len(), 16);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn registry_runs_before_async_fallback_and_bookkeeping_survives_trace_suppression() {
    use miden_event_handler::{AdviceRecorder, EventContext, InvocationKind};
    let mut host = PortableAsyncHost {
        handlers: Default::default(),
        calls: vec![],
        before_await: 0,
    };
    host.handlers
        .register(
            EventName::new("test::registered"),
            |context: EventContext<'_>, advice: &mut AdviceRecorder<'_>| {
                context.kind().require(InvocationKind::Event)?;
                advice.prepend_stack([context.stack_item(0)]);
                Ok(())
            },
        )
        .unwrap();
    let program = Assembler::default()
        .assemble_program(
            "program",
            format!(
                r#"begin push.9 emit.event("test::registered") adv_push push.9 assert_eq drop
        emit.event("{BOOKKEEPING}") trace.event("test::registered") end"#
            ),
        )
        .unwrap()
        .unwrap_program();
    let output = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_trace_delivery(false),
    )
    .unwrap()
    .execute(&program, &mut host)
    .await
    .unwrap();
    assert_eq!(host.before_await, 1);
    assert_eq!(host.calls, [(InvocationKind::Event, Felt::ZERO)]);
    assert!(output.advice.stack().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn non_send_sync_host_adapts_to_native_send_future() {
    use std::{cell::Cell, rc::Rc};

    use miden_event_handler::{AdviceBatch, AdviceRecorder, EventContext, Invocation};
    use miden_processor::SyncHost;
    struct LocalHost(Rc<Cell<usize>>);
    impl BaseHost for LocalHost {
        fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
            (SourceSpan::UNKNOWN, None)
        }
    }
    impl SyncHost for LocalHost {
        fn get_mast_forest(&self, _: &Word) -> Option<LoadedMastForest> {
            None
        }
        fn handle_event(
            &mut self,
            _: EventContext<'_>,
            advice: &mut AdviceRecorder<'_>,
        ) -> Result<(), EventError> {
            self.0.set(self.0.get() + 1);
            advice.prepend_stack([Felt::ONE]);
            Ok(())
        }
    }
    fn assert_send<T: Send>(future: T) -> T {
        future
    }
    let processor = FastProcessor::new(StackInputs::default());
    let context = EventContext::new(
        &processor,
        Invocation::event(EventName::new("test::local").to_event_id(), 0, true),
    );
    let mut batch = AdviceBatch::new();
    let calls = Rc::new(Cell::new(0));
    let mut host = LocalHost(calls.clone());
    assert_send(Host::handle_event(&mut host, context, &mut batch.recorder()))
        .await
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(batch.into_parts().0.into_elements(), vec![Felt::ONE]);
}

#[cfg(feature = "testing")]
#[tokio::test(flavor = "current_thread")]
async fn cancelling_a_callback_discards_all_pending_advice() {
    use std::{
        future::{Future, pending},
        task::{Context, Poll, Waker},
    };

    use miden_event_handler::{AdviceRecorder, EventContext};
    use miden_processor::crypto::merkle::MerkleTree;
    struct PendingHost;
    impl BaseHost for PendingHost {
        fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
            (SourceSpan::UNKNOWN, None)
        }
    }
    impl Host for PendingHost {
        fn get_mast_forest(&self, _: &Word) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
            async { None }
        }
        fn handle_event(
            &mut self,
            _: EventContext<'_>,
            advice: &mut AdviceRecorder<'_>,
        ) -> impl FutureMaybeSend<Result<(), EventError>> {
            async move {
                advice.prepend_stack([Felt::ONE]);
                advice.insert_map_entry(Word::default(), vec![Felt::ONE]);
                let tree = MerkleTree::new([
                    Word::new([Felt::from_u32(3); 4]),
                    Word::new([Felt::from_u32(4); 4]),
                ])
                .unwrap();
                advice.extend_merkle_store(tree.inner_nodes());
                pending().await
            }
        }
    }
    let program = Assembler::default()
        .assemble_program("program", r#"begin emit.event("test::pending") end"#)
        .unwrap()
        .unwrap_program();
    let initial = FastProcessor::new(StackInputs::default()).into_parts().0;
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut host = PendingHost;
    {
        let mut future = std::pin::pin!(processor.execute_mut(&program, &mut host));
        assert!(matches!(
            future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
    }
    let actual = processor.into_parts().0;
    assert_eq!(actual, initial);
}

#[tokio::test(flavor = "current_thread")]
async fn forwarding_to_legacy_host_cannot_fall_back_after_staging_advice() {
    use miden_event_handler::{AdviceRecorder, EventContext};
    use miden_processor::SyncHost;
    struct ForwardingHost {
        inner: DefaultHost,
        legacy_calls: usize,
    }
    impl BaseHost for ForwardingHost {
        fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
            (SourceSpan::UNKNOWN, None)
        }
    }
    impl SyncHost for ForwardingHost {
        fn get_mast_forest(&self, _: &Word) -> Option<LoadedMastForest> {
            None
        }
        fn handle_event(
            &mut self,
            context: EventContext<'_>,
            advice: &mut AdviceRecorder<'_>,
        ) -> Result<(), EventError> {
            advice.prepend_stack([Felt::ONE]);
            SyncHost::handle_event(&mut self.inner, context, advice)
        }
        fn on_event(&mut self, _: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
            self.legacy_calls += 1;
            Ok(vec![])
        }
    }
    let program = Assembler::default()
        .assemble_program("program", r#"begin emit.event("test::fallback") end"#)
        .unwrap()
        .unwrap_program();
    for asynchronous in [false, true] {
        let mut host = ForwardingHost {
            inner: DefaultHost::default(),
            legacy_calls: 0,
        };
        let processor = FastProcessor::new(StackInputs::default());
        let result = if asynchronous {
            processor.execute(&program, &mut host).await
        } else {
            processor.execute_sync(&program, &mut host)
        };
        assert!(result.is_err());
        assert_eq!(host.legacy_calls, 0);
    }
}
