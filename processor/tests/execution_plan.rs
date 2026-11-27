use core::{
    future::Future,
    ops::ControlFlow,
    task::{Context, Poll, Waker},
};
use std::sync::Arc;

use miden_assembly::Assembler;
use miden_core::deferred::{PrecompileError, PrecompileLimitError, PrecompileLimits, TRUE_DIGEST};
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_mast_package::{
    Package,
    debug_info::{DebugSourceGraphLookupError, PackageDebugInfo},
};
use miden_processor::{
    BaseHost, DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, Felt,
    FutureMaybeSend, HaltedExecution, Host, LoadedMastForest, MastForestLoadError,
    PackageSourceDebugContext, Processor, ProcessorError, ProcessorState, RecordWitness,
    SessionUnavailableReason, SourceContextError, StepStatus, WitnessOutput, Word,
    advice::{AdviceError, AdviceInputs, AdviceMap, AdviceMutation, AdviceProvider},
    event::{EventError, EventName},
    operation::OperationError,
    serde::Serializable,
};

#[test]
fn async_execution_futures_preserve_mode_outputs_and_send_bounds() {
    fn assert_future<T>(_: impl FutureMaybeSend<Result<T, ExecutionError>>) {}

    let program = Assembler::default()
        .assemble_program("execution_plan", "begin nop end")
        .unwrap()
        .unwrap_program();
    let request = || Processor::new(&program);
    let mut host = DefaultHost::default();
    assert_future::<ExecutionOutput>(request().execute().run(&mut host));
    assert_future::<WitnessOutput>(request().record_witness().run(&mut host));
    assert_future::<WitnessOutput>(request().record_witness().start().unwrap().run(&mut host));

    let mut session = request().record_witness().start().unwrap();
    assert_future::<StepStatus>(session.step(&mut host));
    assert_future::<()>(session.run_until_halt(&mut host));
    assert_future::<HaltedExecution<RecordWitness>>(session.run_to_completion(&mut host));
}

#[test]
fn preparing_execution_validates_initial_advice_before_program_advice() {
    let program = Assembler::default()
        .assemble_program("execution_plan", "begin push.3 swap drop end")
        .unwrap()
        .unwrap_program();
    let advice_map = AdviceMap::from_iter([(Word::empty(), vec![Felt::ONE])]);
    let advice = AdviceInputs::from(advice_map.clone());
    let options = ExecutionOptions::default().with_max_advice_size_bytes(0);
    // Even empty inputs reserve space for the default Merkle store.
    let AdviceError::SizeBudgetExceeded { current: budget, .. } =
        AdviceProvider::new(AdviceInputs::default(), &options).unwrap_err()
    else {
        panic!("a zero advice limit should reject the default Merkle store");
    };
    let options = options.with_max_advice_size_bytes(budget);
    let request = || {
        Processor::new(&program)
            .with_advice(advice.clone())
            .with_options(options.clone())
    };
    assert!(matches!(
        request().execute().prepare().map_err(ExecutionError::into_kind),
        Err(ProcessorError::Advice(AdviceError::SizeBudgetExceeded { max, .. })) if max == budget
    ));
    assert!(matches!(
        request().execute().run_sync(&mut DefaultHost::default()).map_err(ExecutionError::into_kind),
        Err(ProcessorError::Advice(AdviceError::SizeBudgetExceeded { max, .. })) if max == budget
    ));

    let output = request()
        .with_options(ExecutionOptions::default())
        .execute()
        .run_sync(&mut DefaultHost::default())
        .unwrap();
    assert_eq!(output.advice.get_mapped_values(&Word::empty()), Some([Felt::ONE].as_slice()));

    let program = program.with_advice_map(advice_map);
    let prepared = Processor::new(&program).with_options(options).execute().prepare().unwrap();
    assert!(matches!(
        prepared.start().map_err(ExecutionError::into_kind),
        Err(ProcessorError::Advice(AdviceError::SizeBudgetExceeded { max, .. })) if max == budget
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_execution_accepts_empty_optional_debug_info() {
    let program = Assembler::default()
        .assemble_program("execution_plan", "begin push.3 swap drop end")
        .unwrap()
        .unwrap_program();
    let debug_info = PackageDebugInfo::default();
    for source in [None, Some(PackageSourceDebugContext::new_optional(&debug_info, None))] {
        let output = Processor::new(&program)
            .with_source_context(source)
            .execute()
            .run(&mut DefaultHost::default())
            .await
            .unwrap();
        assert_eq!(output.stack.get_element(0), Some(Felt::from_u32(3)));
    }
}

#[test]
fn paused_execution_preserves_witness_and_final_advice() {
    let program = Assembler::default()
        .assemble_program("execution_plan", "begin push.1 repeat.24 push.1 add end swap drop end")
        .unwrap()
        .unwrap_program();
    let advice = AdviceInputs::default().with_map([(Word::empty(), vec![Felt::ONE])]);
    let options = ExecutionOptions::default().with_core_trace_fragment_size(8).unwrap();

    // Preparing the VM before stepping preserves the witness and the final advice.
    let direct = Processor::new(&program)
        .with_advice(advice.clone())
        .with_options(options.clone())
        .record_witness()
        .run_sync(&mut DefaultHost::default())
        .unwrap();
    let mut session = Processor::new(&program)
        .with_advice(advice)
        .with_options(options)
        .record_witness()
        .prepare()
        .unwrap()
        .prepare()
        .unwrap()
        .start()
        .unwrap();
    drop(program);
    let mut host = DefaultHost::default();
    assert!(matches!(session.step_sync(&mut host).unwrap(), StepStatus::Running));
    session = match session.try_complete() {
        ControlFlow::Continue(session) => session,
        ControlFlow::Break(_) => panic!("a paused execution must retain its unfinished session"),
    };
    session.run_until_halt_sync(&mut host).unwrap();
    let halted_clock = session.state().clock();
    assert_eq!(session.state().get_stack_item(0), Felt::from_u32(25));
    assert_eq!(session.state().precompile_root(), TRUE_DIGEST);
    assert!(matches!(session.step_sync(&mut host).unwrap(), StepStatus::Finished));
    session.run_until_halt_sync(&mut host).unwrap();
    assert_eq!(session.state().clock(), halted_clock);
    let completed = match session.try_complete() {
        ControlFlow::Break(completed) => completed,
        ControlFlow::Continue(_) => panic!("a finished execution must yield its recorded output"),
    };
    assert_eq!(completed.state().clock(), halted_clock);
    assert_eq!(completed.state().get_stack_item(0), Felt::from_u32(25));
    assert_eq!(completed.state().advice_provider(), &direct.advice);
    let stepped = completed.finish().unwrap();

    assert_eq!(direct.claim, stepped.claim);
    assert_eq!(direct.advice, stepped.advice);
    assert_eq!(stepped.advice.get_mapped_values(&Word::empty()), Some([Felt::ONE].as_slice()));
    assert_eq!(direct.witness.to_bytes(), stepped.witness.to_bytes());
}

#[test]
fn completed_execution_defers_precompile_witness_export_until_finish() {
    let program = Assembler::default()
        .assemble_program("execution_plan", "begin log_deferred end")
        .unwrap()
        .unwrap_program();
    let options =
        ExecutionOptions::default().with_verification_precompile_limits(PrecompileLimits::new(0));
    let completed = Processor::new(&program)
        .with_options(options)
        .execute()
        .start()
        .unwrap()
        .run_to_completion_sync(&mut DefaultHost::default())
        .expect("VM termination must not export the precompile witness");

    assert_ne!(completed.state().precompile_root(), TRUE_DIGEST);
    assert!(matches!(
        completed.finish().map_err(ExecutionError::into_kind),
        Err(ProcessorError::Deferred(PrecompileError::Limit(PrecompileLimitError::Elements {
            actual, max: 0,
        }))) if actual > 0
    ));
}

#[test]
fn failed_execution_retains_state_without_resuming_or_completing() {
    let program = Assembler::default()
        .assemble_program("execution_plan", "begin log_deferred dropw push.17 push.0 assert end")
        .unwrap()
        .unwrap_program();
    let mut session = Processor::new(&program).execute().start().unwrap();
    let mut host = DefaultHost::default();
    let error = session.run_until_halt_sync(&mut host).expect_err("the assertion must fail");
    assert!(matches!(
        error.kind(),
        ProcessorError::Operation(OperationError::FailedAssertion { .. })
    ));
    let clock = session.state().clock();
    let root = session.state().precompile_root();
    assert_ne!(root, TRUE_DIGEST);
    assert_eq!(session.state().get_stack_word(0)[1], Felt::from_u32(17));
    let mut session = match session.try_complete() {
        ControlFlow::Continue(session) => session,
        ControlFlow::Break(_) => panic!("failed execution must not produce completion"),
    };
    assert!(matches!(
        session.step_sync(&mut host).map_err(ExecutionError::into_kind),
        Err(ProcessorError::SessionUnavailable(SessionUnavailableReason::PreviouslyFailed))
    ));
    assert_eq!(session.state().clock(), clock);
    assert_eq!(session.state().precompile_root(), root);
}

struct PendingHost {
    event_calls: usize,
}

impl BaseHost for PendingHost {
    fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl Host for PendingHost {
    fn get_mast_forest(
        &self,
        _: &Word,
    ) -> impl FutureMaybeSend<Result<Option<LoadedMastForest>, MastForestLoadError>> {
        async { Ok(None) }
    }

    fn on_event(
        &mut self,
        _: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        self.event_calls += 1;
        core::future::pending()
    }
}

fn emitting_package() -> Box<Package> {
    let event_id = EventName::new("test::execution_plan::pending").to_event_id().as_u64();
    Assembler::default()
        .assemble_program("execution_plan", format!("begin push.{event_id} emit drop end"))
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_source_context_fails_before_execution() {
    let event = EventName::new("test::execution_plan::pending").to_event_id().as_u64();
    let package = Assembler::default()
        .assemble_program(
            "source_context",
            format!("begin push.1 if.true push.{event} emit drop end end"),
        )
        .unwrap();
    let debug_info = package.debug_info().unwrap().unwrap();
    let program = package.unwrap_program();
    let (idx, node) = debug_info
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| node.exec_node != program.entrypoint())
        .expect("conditional has a child distinct from its entrypoint");
    let child = u32::try_from(idx).unwrap().into();
    let missing = 123_u32.into();
    let mut host = PendingHost { event_calls: 0 };
    for (source_node, expected) in [
        (
            missing,
            SourceContextError::Lookup(DebugSourceGraphLookupError::MissingSourceNode {
                source_node: missing,
            }),
        ),
        (
            child,
            SourceContextError::EntrypointMismatch {
                source_node: child,
                expected: program.entrypoint(),
                actual: node.exec_node,
            },
        ),
    ] {
        let source = PackageSourceDebugContext::new(&debug_info, source_node);
        let request = || Processor::new(&program).with_source_context(Some(source));
        for error in [
            request().execute().run_sync(&mut DefaultHost::default()).err(),
            request().record_witness().run(&mut host).await.err(),
            request().record_witness().start().err(),
            request().execute().prepare().unwrap().start().err(),
        ] {
            assert!(
                matches!(error.map(ExecutionError::into_kind), Some(ProcessorError::SourceContext(actual)) if actual == expected)
            );
        }
    }
    assert_eq!(host.event_calls, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_async_execution_cannot_be_resumed_or_completed() {
    let program = emitting_package().unwrap_program();
    for cancel_drain in [false, true] {
        let mut session = Processor::new(&program).record_witness().start().unwrap();
        let mut host = PendingHost { event_calls: 0 };
        let mut context = Context::from_waker(Waker::noop());

        if cancel_drain {
            let mut future = Box::pin(session.run_until_halt(&mut host));
            assert!(future.as_mut().poll(&mut context).is_pending());
        } else {
            let mut cancelled = false;
            for _ in 0..64 {
                let mut step = Box::pin(session.step(&mut host));
                match step.as_mut().poll(&mut context) {
                    Poll::Pending => {
                        cancelled = true;
                        break;
                    },
                    Poll::Ready(Ok(_)) => {},
                    Poll::Ready(Err(err)) => {
                        panic!("execution failed before the host callback: {err}")
                    },
                }
            }
            assert!(cancelled, "execution did not reach its pending callback");
        }
        assert_eq!(host.event_calls, 1);
        let clock = session.state().clock();
        assert!(u32::from(clock) > 0);
        let mut session = match session.try_complete() {
            ControlFlow::Break(_) => {
                panic!("a cancelled step cannot produce a completed execution")
            },
            ControlFlow::Continue(session) => session,
        };
        let error = if cancel_drain {
            session.run_until_halt_sync(&mut DefaultHost::default()).unwrap_err()
        } else {
            session.run_until_halt(&mut host).await.unwrap_err()
        };
        assert!(matches!(
            error.kind(),
            ProcessorError::SessionUnavailable(SessionUnavailableReason::Interrupted)
        ));
        assert_eq!(host.event_calls, 1);
        assert_eq!(session.state().clock(), clock);
        assert!(matches!(session.try_complete(), ControlFlow::Continue(_)));
    }
}
