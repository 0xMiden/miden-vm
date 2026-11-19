use core::{cell::Cell, ops::ControlFlow};

use miden_assembly::Assembler;
use miden_core::deferred::{PrecompileError, PrecompileLimitError, PrecompileLimits, TRUE_DIGEST};
use miden_mast_package::debug_info::PackageDebugInfo;
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, ExecutionRequest, ExecutionTask, ExecutionTrace,
    Felt, PackageSourceDebugContext, PrecompileWitness, StepStatus, Witness, WitnessOutput, Word,
    advice::{AdviceError, AdviceInputs, AdviceMap, AdviceProvider},
    operation::OperationError,
};

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
        ExecutionRequest::new(&program)
            .with_advice(advice.clone())
            .with_options(options.clone())
            .execute()
    };
    for error in [request().prepare().err(), request().run_sync(&mut DefaultHost::default()).err()]
    {
        assert!(matches!(
            error,
            Some(ExecutionError::AdviceError {
                err: AdviceError::SizeBudgetExceeded { max, .. },
                ..
            }) if max == budget
        ));
    }

    let program = program.with_advice_map(advice_map);
    let prepared = ExecutionRequest::new(&program)
        .with_options(options)
        .execute()
        .prepare()
        .unwrap();
    assert!(matches!(
        prepared.start(),
        Err(ExecutionError::AdviceError {
            err: AdviceError::SizeBudgetExceeded { max, .. },
            ..
        }) if max == budget
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
        let output = ExecutionRequest::new(&program)
            .with_source_context(source)
            .execute()
            .prepare()
            .unwrap()
            .run(&mut DefaultHost::default())
            .await
            .unwrap();
        assert_eq!(output.stack.get_element(0), Some(Felt::from_u32(3)));
    }
}

#[test]
fn paused_execution_preserves_trace_and_final_advice() {
    let program = Assembler::default()
        .assemble_program("execution_plan", "begin push.1 repeat.24 push.1 add end swap drop end")
        .unwrap()
        .unwrap_program();
    let advice = AdviceInputs::default().with_map([(Word::empty(), vec![Felt::ONE])]);
    let options = ExecutionOptions::default().with_core_trace_fragment_size(8).unwrap();
    let budget = miden_vm_stark::memory::default_budget();

    // Preparing the VM before stepping preserves the trace and the final advice.
    let direct = ExecutionRequest::new(&program)
        .with_advice(advice.clone())
        .with_options(options.clone())
        .build_trace(budget)
        .run_sync(&mut DefaultHost::default())
        .unwrap();
    let mut session = ExecutionRequest::new(&program)
        .with_advice(advice)
        .with_options(options)
        .build_trace(budget)
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
    assert!(direct.trace.precompile_witness().is_none());
    assert!(stepped.trace.precompile_witness().is_none());
    assert_eq!(
        direct.trace.into_vm_trace().into_air_matrices(),
        stepped.trace.into_vm_trace().into_air_matrices()
    );
}

#[test]
fn custom_task_finalization_waits_for_successful_artifact_preparation() {
    #[derive(Debug)]
    enum TaskError {
        Execution(ExecutionError),
        Finalization,
    }

    impl From<ExecutionError> for TaskError {
        fn from(error: ExecutionError) -> Self {
            Self::Execution(error)
        }
    }

    struct RejectOutput<'a>(&'a Cell<u32>);

    impl ExecutionTask for RejectOutput<'_> {
        type Mode = Witness;
        type Output = ();
        type Error = TaskError;

        fn mode(&self) -> Self::Mode {
            Witness
        }

        fn finish(self, output: WitnessOutput) -> Result<(), Self::Error> {
            assert_eq!(output.witness.claim(), output.claim);
            assert_eq!(self.0.replace(1), 0, "finalization must consume the task exactly once");
            Err(TaskError::Finalization)
        }
    }

    let assemble = |source: &str| {
        Assembler::default()
            .assemble_program("execution_task", source)
            .unwrap()
            .unwrap_program()
    };
    let program = assemble("begin push.3 swap drop end");
    for stepped in [false, true] {
        let finalizations = Cell::new(0);
        let execution = ExecutionRequest::new(&program).select(RejectOutput(&finalizations));
        let result = if stepped {
            let mut session = execution.start().unwrap();
            session.step_sync(&mut DefaultHost::default()).unwrap();
            assert_eq!(finalizations.get(), 0);
            let completed = session.run_to_completion_sync(&mut DefaultHost::default()).unwrap();
            assert_eq!(completed.state().get_stack_item(0), Felt::from_u32(3));
            assert_eq!(finalizations.get(), 0);
            completed.finish()
        } else {
            execution.run_sync(&mut DefaultHost::default())
        };
        assert!(matches!(result, Err(TaskError::Finalization)));
        assert_eq!(finalizations.get(), 1);
    }

    // Neither a VM error nor a later artifact-export error may reach the finalizer.
    for (source, options) in [
        ("begin push.0 assert end", ExecutionOptions::default()),
        (
            "begin log_deferred end",
            ExecutionOptions::default()
                .with_verification_precompile_limits(PrecompileLimits::new(0)),
        ),
    ] {
        let program = assemble(source);
        let finalizations = Cell::new(0);
        let result = ExecutionRequest::new(&program)
            .with_options(options)
            .select(RejectOutput(&finalizations))
            .run_sync(&mut DefaultHost::default());
        assert!(matches!(
            result,
            Err(TaskError::Execution(ExecutionError::OperationError { .. }))
        ));
        assert_eq!(finalizations.get(), 0);
    }
}

#[test]
fn completed_execution_defers_precompile_witness_export_until_finish() {
    let program = Assembler::default()
        .assemble_program("execution_plan", "begin log_deferred end")
        .unwrap()
        .unwrap_program();
    let options =
        ExecutionOptions::default().with_verification_precompile_limits(PrecompileLimits::new(0));
    let completed = ExecutionRequest::new(&program)
        .with_options(options)
        .execute()
        .start()
        .unwrap()
        .run_to_completion_sync(&mut DefaultHost::default())
        .expect("VM termination must not export the precompile witness");

    assert_ne!(completed.state().precompile_root(), TRUE_DIGEST);
    assert!(matches!(
        completed.finish(),
        Err(ExecutionError::OperationError {
            err: OperationError::Deferred(PrecompileError::Limit(
                PrecompileLimitError::Elements { actual, max: 0 }
            )),
            ..
        }) if actual > 0
    ));
}

#[test]
fn failed_execution_retains_state_without_resuming_or_completing() {
    let program = Assembler::default()
        .assemble_program("execution_plan", "begin log_deferred dropw push.17 push.0 assert end")
        .unwrap()
        .unwrap_program();
    let mut session = ExecutionRequest::new(&program).execute().start().unwrap();
    let mut host = DefaultHost::default();
    let error = session.run_until_halt_sync(&mut host).expect_err("the assertion must fail");
    assert!(matches!(
        error,
        ExecutionError::OperationError {
            err: OperationError::FailedAssertion { .. },
            ..
        }
    ));
    let clock = session.state().clock();
    let root = session.state().precompile_root();
    assert_ne!(root, TRUE_DIGEST);
    assert_eq!(session.state().get_stack_word(0)[1], Felt::from_u32(17));
    let mut session = match session.try_complete() {
        ControlFlow::Continue(session) => session,
        ControlFlow::Break(_) => panic!("failed execution must not produce completion"),
    };
    assert!(matches!(session.step_sync(&mut host), Err(ExecutionError::Internal(_))));
    assert_eq!(session.state().clock(), clock);
    assert_eq!(session.state().precompile_root(), root);
}

#[test]
fn reconstructed_execution_traces_check_precompile_obligations() {
    let build_trace = |source: &str| {
        let program = Assembler::default()
            .assemble_program("execution_trace", source)
            .unwrap()
            .unwrap_program();
        ExecutionRequest::new(&program)
            .build_trace(miden_vm_stark::memory::default_budget())
            .run_sync(&mut DefaultHost::default())
            .unwrap()
            .trace
    };

    let trace = build_trace("begin nop end");
    assert!(trace.precompile_witness().is_none());
    let (vm_trace, witness) = trace.into_parts();
    assert!(ExecutionTrace::try_new(vm_trace, witness).is_ok());

    // Logging TRUE creates an actual nonempty authenticated graph and portable witness.
    let trace = build_trace("begin log_deferred end");
    let expected_root = trace.vm_trace().precompile_root();
    let (vm_trace, witness) = trace.into_parts();
    let witness = witness.expect("logged work must carry a witness");
    assert_ne!(expected_root, TRUE_DIGEST);
    assert!(ExecutionTrace::try_new(vm_trace, Some(witness.clone())).is_ok());

    let vm_trace = build_trace("begin log_deferred end").into_vm_trace();
    assert!(matches!(
        ExecutionTrace::try_new(vm_trace, None),
        Err(ExecutionError::MissingPrecompileWitness)
    ));

    let vm_trace = build_trace("begin nop end").into_vm_trace();
    assert!(matches!(
        ExecutionTrace::try_new(vm_trace, Some(witness.clone())),
        Err(ExecutionError::UnexpectedPrecompileWitness)
    ));

    let vm_trace = build_trace("begin log_deferred log_deferred end").into_vm_trace();
    let different_root = vm_trace.precompile_root();
    assert_ne!(different_root, expected_root);
    assert!(matches!(
        ExecutionTrace::try_new(vm_trace, Some(witness)),
        Err(ExecutionError::PrecompileRootMismatch { expected, actual })
            if expected == different_root && actual == expected_root
    ));

    let vm_trace = build_trace("begin log_deferred end").into_vm_trace();
    let malformed = PrecompileWitness::from_entries(Vec::new()).unwrap();
    assert!(matches!(
        ExecutionTrace::try_new(vm_trace, Some(malformed)),
        Err(ExecutionError::InvalidPrecompileWitness(_))
    ));
}
