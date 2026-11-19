use core::{
    future::Future,
    ops::ControlFlow,
    task::{Context, Poll, Waker},
};
use std::sync::Arc;

use miden_processor::{
    ExecutionRequest, Felt, LoadedMastForest, MastForestLoadError, ProcessorState,
    event::{EventError, EventName},
};
use miden_vm::{
    Assembler, BaseHost, CompleteProof, CompletedExecution, DefaultHost, Execute, Execution,
    ExecutionError, ExecutionOptions, ExecutionOutput, ExecutionProof, ExecutionSession,
    FutureMaybeSend, Host, Memory, PackageSourceDebugContext, PrecompileStatus, Processor, Program,
    ProveComplete, ProveDeferred, Prover, ProvingOutput, ProvingRunError, Trace, TraceOutput,
    Verifier, Witness, WitnessOutput, Word,
    advice::{AdviceInputs, AdviceMutation},
    assembly::debuginfo::{Location, SourceFile, SourceSpan},
    trace_memory,
};

fn program(source: &str) -> Program {
    Assembler::default()
        .assemble_program("typed_execution", source)
        .unwrap()
        .unwrap_program()
}

#[test]
fn task_outputs_errors_and_async_future_bounds() {
    fn accepts_future<O, E>(_: impl FutureMaybeSend<Result<O, E>>) {}

    let program = program("begin nop end");
    let prover = Prover::new();
    let processor = || Processor::new(&program);
    let mut host = DefaultHost::default();

    // Construct and drop these futures without polling: their types establish the contracts
    // without repeating trace construction or proof generation from the runtime tests below.
    let execute: Execution<'_, Execute> = processor().execute();
    accepts_future::<ExecutionOutput, ExecutionError>(execute.run(&mut host));
    let witness: Execution<'_, Witness> = processor().record_witness();
    accepts_future::<WitnessOutput, ExecutionError>(witness.run(&mut host));
    let trace: Execution<'_, Trace> = processor().build_trace(trace_memory::default_budget());
    accepts_future::<TraceOutput, ExecutionError>(trace.run(&mut host));
    let complete: Execution<'_, ProveComplete<'_>> = processor().prove_complete(&prover);
    accepts_future::<ProvingOutput<CompleteProof>, ProvingRunError>(complete.run(&mut host));
    let deferred: Execution<'_, ProveDeferred<'_>> = processor().prove_deferred(&prover);
    accepts_future::<ProvingOutput<ExecutionProof>, ProvingRunError>(deferred.run(&mut host));

    accepts_future::<ExecutionOutput, ExecutionError>(
        processor().execute().start().unwrap().run(&mut host),
    );
    accepts_future::<WitnessOutput, ExecutionError>(
        processor().record_witness().start().unwrap().run(&mut host),
    );
    accepts_future::<TraceOutput, ExecutionError>(
        processor()
            .build_trace(trace_memory::default_budget())
            .start()
            .unwrap()
            .run(&mut host),
    );
    accepts_future::<ProvingOutput<CompleteProof>, ProvingRunError>(
        processor().prove_complete(&prover).start().unwrap().run(&mut host),
    );
    accepts_future::<ProvingOutput<ExecutionProof>, ProvingRunError>(
        processor().prove_deferred(&prover).start().unwrap().run(&mut host),
    );
    let mut session: ExecutionSession<ProveComplete<'_>> =
        processor().prove_complete(&prover).start().unwrap();
    accepts_future::<(), ExecutionError>(session.run_until_halt(&mut host));
    accepts_future::<CompletedExecution<ProveComplete<'_>>, ExecutionError>(
        session.run_to_completion(&mut host),
    );

    // The facade and the processor request select the same execution types.
    let _: Execution<'_, Execute> = ExecutionRequest::new(&program).execute();
    let _: Execution<'_, Witness> = ExecutionRequest::new(&program).record_witness();

    // Ordinary execution exposes its memory type through the facade.
    let ExecutionOutput { memory, .. } = processor().execute().run_sync(&mut host).unwrap();
    let _: Memory = memory;
}

#[test]
fn raw_input_configuration_validates_final_options() {
    let program = program("begin nop end");
    let advice = AdviceInputs::default().with_map([(Word::empty(), vec![Felt::ONE])]);
    let options = ExecutionOptions::default().with_max_advice_size_bytes(0);
    let processor = || Processor::new(&program).with_options(options.clone());

    let mut session = processor()
        .with_advice(advice.clone())
        .with_options(ExecutionOptions::default())
        .execute()
        .start()
        .unwrap();
    let mut host = DefaultHost::default();
    session.step_sync(&mut host).unwrap();
    let output = session.run_sync(&mut host).unwrap();
    assert_eq!(output.advice.get_mapped_values(&Word::empty()), Some([Felt::ONE].as_slice()));

    let invalid = || processor().with_advice(advice.clone()).execute();
    assert!(matches!(invalid().prepare(), Err(ExecutionError::AdviceError { .. })));
    assert!(matches!(
        invalid().run_sync(&mut DefaultHost::default()),
        Err(ExecutionError::AdviceError { .. })
    ));
}

#[tokio::test]
async fn source_context_is_validated_for_every_terminal() {
    let package = Assembler::default()
        .assemble_program("source_context", "begin nop end")
        .unwrap();
    let debug_info = package.debug_info().unwrap().unwrap();
    let program = package.unwrap_program();
    let source = PackageSourceDebugContext::new(&debug_info, 123_u32.into());
    let request = || Processor::new(&program).with_source_context(Some(source));

    let errors = [
        request().execute().run_sync(&mut DefaultHost::default()).err(),
        request().record_witness().run(&mut DefaultHost::default()).await.err(),
        request().build_trace(trace_memory::default_budget()).start().err(),
        request().execute().prepare().unwrap().start().err(),
    ];
    for error in errors {
        assert!(matches!(
            error,
            Some(ExecutionError::Internal(
                "package debug source graph is missing the entrypoint source node"
            ))
        ));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn public_outputs_support_separate_witness_and_trace_proving() {
    let program = program("begin push.3 swap drop end");
    let processor = || Processor::new(&program);
    let prover = Prover::new();
    let inputs = AdviceInputs::default().with_map([(Word::empty(), vec![Felt::ONE])]);
    let mut session = processor().with_advice(inputs.clone()).record_witness().start().unwrap();
    let mut host = DefaultHost::default();
    session.step(&mut host).await.unwrap();
    let WitnessOutput { claim, witness, advice } = session.run(&mut host).await.unwrap();
    assert_eq!(advice.get_mapped_values(&Word::empty()), Some([Felt::ONE].as_slice()));
    assert_eq!(witness.claim(), claim);
    let trace = witness.build_trace(prover.trace_budget()).unwrap();
    let proof = prover.prove_trace(trace).unwrap();
    assert!(Verifier::new().verify(&claim, &proof).unwrap().is_complete());

    let TraceOutput { claim: trace_claim, trace, advice } = processor()
        .with_advice(inputs)
        .build_trace(prover.trace_budget())
        .run(&mut DefaultHost::default())
        .await
        .unwrap();
    assert_eq!(advice.get_mapped_values(&Word::empty()), Some([Felt::ONE].as_slice()));
    assert_eq!(trace_claim, claim);
    assert!(trace.precompile_witness().is_none());
    let proof = prover.prove_full_trace(trace).unwrap();
    assert!(Verifier::new().verify(&trace_claim, proof.as_inner()).unwrap().is_complete());
}

#[test]
fn stepped_trace_preserves_recording_until_completion() {
    let program = program("begin push.3 swap drop end");
    let session = Processor::new(&program)
        .build_trace(trace_memory::default_budget())
        .start()
        .unwrap();
    let mut session = match session.try_complete() {
        ControlFlow::Break(_) => panic!("an unstarted program cannot be complete"),
        ControlFlow::Continue(session) => session,
    };
    let mut host = DefaultHost::default();
    assert_eq!(u32::from(session.state().clock()), 0);
    session.step_sync(&mut host).unwrap();
    assert!(u32::from(session.state().clock()) > 0);
    let completed = session.run_to_completion_sync(&mut host).unwrap();
    assert_eq!(completed.state().get_stack_item(0), Felt::from_u32(3));
    let TraceOutput { claim, trace, .. } = completed.finish().unwrap();
    assert_eq!(*trace.vm_trace().program_hash(), program.hash());
    assert!(trace.precompile_witness().is_none());
    assert_eq!(claim.stack_outputs().get_element(0), Some(Felt::from_u32(3)));
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

fn emitting_program() -> Program {
    let event_id = EventName::new("test::typed_execution::pending").to_event_id().as_u64();
    program(&format!("begin push.{event_id} emit drop end"))
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_async_execution_cannot_be_resumed_or_completed() {
    let program = emitting_program();
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
            error,
            ExecutionError::Internal("execution session failed or a previous step was cancelled")
        ));
        assert_eq!(host.event_calls, 1);
        assert_eq!(session.state().clock(), clock);
        assert!(matches!(session.try_complete(), ControlFlow::Continue(_)));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn session_shortcuts_propagate_execution_errors() {
    let program = program("begin push.0 assert end");
    let processor = || Processor::new(&program);
    let error = processor()
        .execute()
        .start()
        .unwrap()
        .run_sync(&mut DefaultHost::default())
        .unwrap_err();
    assert!(matches!(error, ExecutionError::OperationError { .. }));

    let prover = Prover::new();
    let mut session = processor().prove_complete(&prover).start().unwrap();
    let result = session.run_until_halt(&mut DefaultHost::default()).await;
    assert!(matches!(result, Err(ExecutionError::OperationError { .. })));

    let error = processor()
        .prove_complete(&prover)
        .start()
        .unwrap()
        .run(&mut DefaultHost::default())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ProvingRunError::Execution(ExecutionError::OperationError { .. })
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn proving_source_failure_precedes_host_callbacks() {
    let package = Assembler::default()
        .assemble_program("source_context", "begin nop end")
        .unwrap();
    let debug_info = package.debug_info().unwrap().unwrap();
    let source = PackageSourceDebugContext::new(&debug_info, 123_u32.into());
    let program = emitting_program();
    let prover = Prover::new();
    let mut host = PendingHost { event_calls: 0 };
    let request = || {
        Processor::new(&program)
            .with_source_context(Some(source))
            .prove_deferred(&prover)
    };
    assert!(matches!(
        request().start(),
        Err(ExecutionError::Internal(
            "package debug source graph is missing the entrypoint source node"
        ))
    ));
    let result = request().run(&mut host).await;
    assert!(matches!(
        result,
        Err(ProvingRunError::Execution(ExecutionError::Internal(
            "package debug source graph is missing the entrypoint source node"
        )))
    ));
    assert_eq!(host.event_calls, 0);
}

fn precompile_program() -> Program {
    use miden_core::deferred::Node;
    use miden_precompiles::{UintDomain, UintPrecompile};

    let mut value = [Felt::ZERO; 8];
    value[0] = Felt::ONE;
    let value_digest = Node::value(UintPrecompile::value_frame(UintDomain::U256), value)
        .unwrap()
        .digest();
    let equality_cv = UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID).initial_chaining_word();
    let literal = |word: Word| {
        format!(
            "[{}, {}, {}, {}]",
            word[0].as_canonical_u64(),
            word[1].as_canonical_u64(),
            word[2].as_canonical_u64(),
            word[3].as_canonical_u64(),
        )
    };
    // Register and assert U256 equality using the registry's constant value node for one.
    program(&format!(
        "begin push.{} push.{} push.{} adv.register_deferred \
         movdnw.2 compress dropw dropw log_deferred dropw end",
        literal(value_digest),
        literal(value_digest),
        literal(equality_cv),
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn proving_tasks_preserve_nontrivial_precompile_work() {
    let program = precompile_program();
    let processor = || Processor::new(&program);
    let prover = Prover::new();
    let advice = AdviceInputs::default().with_map([(Word::empty(), vec![Felt::ONE])]);
    let ProvingOutput {
        claim: complete_claim,
        proof,
        advice: complete_advice,
    } = processor()
        .with_advice(advice.clone())
        .prove_complete(&prover)
        .run_sync(&mut DefaultHost::default())
        .unwrap();
    let _: &CompleteProof = &proof;
    assert!(matches!(proof.as_inner().precompile(), PrecompileStatus::Proven(_)));
    assert!(Verifier::new().verify(&complete_claim, proof.as_inner()).unwrap().is_complete());
    assert_eq!(complete_advice.get_mapped_values(&Word::empty()), Some([Felt::ONE].as_slice()));

    let ProvingOutput { claim, proof, advice } = processor()
        .with_advice(advice)
        .prove_deferred(&prover)
        .run(&mut DefaultHost::default())
        .await
        .unwrap();
    let _: &ExecutionProof = &proof;
    assert_eq!(claim, complete_claim);
    assert_eq!(advice.get_mapped_values(&Word::empty()), Some([Felt::ONE].as_slice()));
    assert!(matches!(proof.precompile(), PrecompileStatus::Deferred(_)));
    let outcome = Verifier::new().verify(&claim, &proof).unwrap();
    assert!(!outcome.is_complete());
    assert_eq!(outcome.outstanding_precompile_root(), Some(proof.vm().precompile_root));
}

#[tokio::test(flavor = "current_thread")]
async fn stepped_proving_verifies_across_recording_fragments() {
    let program = program("begin repeat.64 swap dup.1 add end end");
    let inputs = miden_vm::StackInputs::new(&[Felt::ZERO, Felt::ONE]).unwrap();
    let options = ExecutionOptions::default().with_core_trace_fragment_size(8).unwrap();
    let processor = || Processor::new(&program).with_options(options.clone());
    let prover = Prover::new();
    let advice = AdviceInputs::default().with_map([(Word::empty(), vec![Felt::ONE])]);

    let mut sync_host = DefaultHost::default();
    let mut sync_session = processor()
        .with_stack_inputs(inputs)
        .with_advice(advice.clone())
        .prove_complete(&prover)
        .start()
        .unwrap();
    assert!(!sync_session.step_sync(&mut sync_host).unwrap().is_finished());
    let sync = sync_session.run_sync(&mut sync_host).unwrap();

    let mut async_host = DefaultHost::default();
    let mut async_session = processor()
        .with_stack_inputs(inputs)
        .with_advice(advice)
        .prove_complete(&prover)
        .start()
        .unwrap();
    assert!(!async_session.step(&mut async_host).await.unwrap().is_finished());
    let asynchronous = async_session.run(&mut async_host).await.unwrap();

    assert_eq!(sync.claim, asynchronous.claim);
    assert_eq!(sync.advice, asynchronous.advice);
    for ProvingOutput { claim, proof, advice } in [sync, asynchronous] {
        assert_eq!(advice.get_mapped_values(&Word::empty()), Some([Felt::ONE].as_slice()));
        assert!(Verifier::new().verify(&claim, proof.as_inner()).unwrap().is_complete());
    }
}
