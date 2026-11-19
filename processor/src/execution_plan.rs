//! Typed execution requests, tasks, and resumable execution for the processor engine.
//!
//! Execution modes select the VM recorder. Tasks finalize a successfully prepared artifact, which
//! lets higher-level crates add proving without duplicating execution or session mechanics.

use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{deferred::TRUE_DIGEST, mast::MastForest};
use tracing::{Instrument, Span};

use crate::{
    AdviceInputs, AdviceProvider, ExecutionClaim, ExecutionError, ExecutionOptions,
    ExecutionOutput, ExecutionWitness, FastProcessor, Host, KernelDescriptor,
    PackageSourceDebugContext, PrecompileWitness, ProcessorState, Program, ProgramInfo,
    ResumeContext, StackInputs, StackOutputs, SyncHost, Word,
    errors::MapExecErrNoCtx,
    fast::{NoopTracer, ResumeOutcome},
    trace::{VmTrace, build_trace, execution_tracer::ExecutionTracer},
    tracer::Tracer,
};

/// The VM relation's trace-building memory model and caller-selected byte limit.
pub type VmTraceBudget =
    miden_stark::memory::ProvingBudget<{ miden_air_definitions::vm::MIDEN_AIR_COUNT }>;

/// Program-bound configuration before selecting an execution task.
///
/// Configuration setters retain raw inputs. Advice is validated against the final execution
/// options when execution is prepared, run, or started, independently of setter order.
pub struct ExecutionRequest<'p> {
    program: &'p Program,
    inputs: ExecutionInputs,
    source_context: Option<PackageSourceDebugContext<'p>>,
}

struct ExecutionInputs {
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    options: ExecutionOptions,
}

impl<'p> ExecutionRequest<'p> {
    /// Binds a program with empty inputs and default execution options.
    pub fn new(program: &'p Program) -> Self {
        Self {
            program,
            inputs: ExecutionInputs {
                stack_inputs: StackInputs::default(),
                advice_inputs: AdviceInputs::default(),
                options: ExecutionOptions::default(),
            },
            source_context: None,
        }
    }

    pub fn with_stack_inputs(mut self, inputs: StackInputs) -> Self {
        self.inputs.stack_inputs = inputs;
        self
    }

    pub fn with_advice(mut self, advice: AdviceInputs) -> Self {
        self.inputs.advice_inputs = advice;
        self
    }

    pub fn with_options(mut self, options: ExecutionOptions) -> Self {
        self.inputs.options = options;
        self
    }

    /// Supplies package debug information and its optional exact entrypoint occurrence together.
    /// An explicit occurrence is checked against this program before invoking the host.
    pub fn with_source_context<'s>(
        self,
        source_context: Option<PackageSourceDebugContext<'s>>,
    ) -> ExecutionRequest<'s>
    where
        'p: 's,
    {
        ExecutionRequest {
            program: self.program,
            inputs: self.inputs,
            source_context,
        }
    }

    /// Selects ordinary execution without replay recording.
    pub fn execute(self) -> Execution<'p, Execute> {
        self.select(Execute)
    }

    /// Selects a compact execution witness with its claim and final advice.
    pub fn record_witness(self) -> Execution<'p, Witness> {
        self.select(Witness)
    }

    /// Selects VM trace construction under the supplied relation-compatible budget.
    pub fn build_trace(self, budget: VmTraceBudget) -> Execution<'p, Trace> {
        self.select(Trace::new(budget))
    }

    /// Selects a task that finalizes the artifact produced by a supported VM execution mode.
    ///
    /// This is the composition point for higher-level tasks such as proving. The processor owns
    /// the execution lifecycle and invokes task finalization only after artifact preparation.
    pub fn select<T: ExecutionTask>(self, task: T) -> Execution<'p, T> {
        Execution {
            processor: ProcessorSource::Inputs(self.inputs),
            program: self.program,
            source_context: self.source_context,
            task,
        }
    }
}

// Keep an initialized machine inline so entering the shared pipeline adds no heap allocation.
#[allow(clippy::large_enum_variant)]
enum ProcessorSource {
    Inputs(ExecutionInputs),
    Initialized(FastProcessor),
}

impl ProcessorSource {
    fn into_processor(self) -> Result<FastProcessor, ExecutionError> {
        match self {
            Self::Inputs(inputs) => FastProcessor::new_with_options(
                inputs.stack_inputs,
                inputs.advice_inputs,
                inputs.options,
            )
            .map_exec_err_no_ctx(),
            Self::Initialized(processor) => Ok(processor),
        }
    }
}

/// A program and processor configuration bound to one execution task.
///
/// Running or starting consumes this value. Continuing an execution requires the returned session,
/// which retains the recorder selected for this task.
pub struct Execution<'p, T: ExecutionTask> {
    processor: ProcessorSource,
    program: &'p Program,
    source_context: Option<PackageSourceDebugContext<'p>>,
    task: T,
}

impl<'p, T: ExecutionTask> Execution<'p, T> {
    /// Binds a test fixture's initialized machine before its first cycle.
    #[cfg(test)]
    pub(crate) fn from_processor(
        processor: FastProcessor,
        program: &'p Program,
        task: T,
    ) -> Result<Self, ExecutionError> {
        if u32::from(processor.state().clock()) != 0 {
            return Err(ExecutionError::Internal("an execution plan requires a fresh processor"));
        }
        Ok(Self {
            processor: ProcessorSource::Initialized(processor),
            program,
            source_context: None,
            task,
        })
    }

    /// Initializes the VM and validates the initial advice against the configured options.
    ///
    /// Use this to report initialization failures early or to keep initialization outside a
    /// timed run. A subsequent preparation, run, or start reuses the initialized machine.
    /// Program advice, source context, and recorder setup happen when execution runs or starts.
    /// Host callbacks occur during execution.
    pub fn prepare(mut self) -> Result<Self, ExecutionError> {
        self.processor = ProcessorSource::Initialized(self.processor.into_processor()?);
        Ok(self)
    }

    pub fn run_sync(self, host: &mut impl SyncHost) -> Result<T::Output, T::Error> {
        let _span = self.task.run_span().entered();
        let mode = self.task.mode();
        let processor = self.processor.into_processor()?;
        // Full synchronous execution retains each mode's optimized path, including overlapped
        // hasher trace construction. Stepped execution deliberately uses buffered recording.
        let output = private::ExecutionModeImpl::run_sync(
            mode,
            processor,
            self.program,
            self.source_context,
            host,
        )?;
        self.task.finish(output)
    }

    /// Awaits host callbacks, then prepares the artifact and finalizes the task on this thread.
    ///
    /// A task may perform synchronous CPU work during finalization, such as proof generation.
    pub async fn run(self, host: &mut impl Host) -> Result<T::Output, T::Error> {
        let span = self.task.run_span();
        async move {
            let mode = self.task.mode();
            let processor = self.processor.into_processor()?;
            let output = private::ExecutionModeImpl::run(
                mode,
                processor,
                self.program,
                self.source_context,
                host,
            )
            .await?;
            self.task.finish(output)
        }
        .instrument(span)
        .await
    }

    /// Starts a session without invoking the host. The recorder is retained across pauses.
    pub fn start(self) -> Result<ExecutionSession<T>, ExecutionError> {
        let mut processor = self.processor.into_processor()?;
        let context = processor.start_context(self.program, self.source_context)?;
        let program_hash = self.program.hash();
        let mode = self.task.mode();
        let stack_inputs = processor.initial_stack_inputs();
        let recorder = private::ExecutionModeImpl::recorder(&mode, &processor);
        Ok(ExecutionSession {
            task: self.task,
            mode,
            processor,
            program_hash,
            stack_inputs,
            recorder,
            state: SessionState::Ready(context),
        })
    }
}

/// A task finalizing the output of one supported VM execution mode.
///
/// Execution modes are sealed and retain ownership of recorder selection and artifact preparation.
/// Higher-level crates can implement this trait to transform prepared artifacts, for example by
/// proving a trace. Task finalization runs once, after successful VM termination and artifact
/// preparation. It cannot construct completion tokens or alter the session's execution state.
pub trait ExecutionTask: Sized {
    type Mode: ExecutionMode;
    type Output;
    type Error: From<ExecutionError>;

    fn mode(&self) -> Self::Mode;

    /// A span around VM execution, artifact preparation, and finalization in a single run.
    #[doc(hidden)]
    fn run_span(&self) -> Span {
        Span::none()
    }

    fn finish(
        self,
        input: <Self::Mode as ExecutionMode>::Output,
    ) -> Result<Self::Output, Self::Error>;
}

/// Ordinary execution without replay recording.
///
/// This mode returns the final processor output.
#[derive(Debug, Clone, Copy)]
pub struct Execute;

/// Execution producing a portable replay witness and final advice.
#[derive(Debug, Clone, Copy)]
pub struct Witness;

/// Execution producing a VM trace under a supplied memory budget.
///
/// Synchronous full runs may overlap hasher building with execution when execution options allow
/// it. Async execution and stepped sessions prepare the same trace from buffered replay.
#[derive(Debug, Clone, Copy)]
pub struct Trace {
    budget: VmTraceBudget,
}

impl Trace {
    pub fn new(budget: VmTraceBudget) -> Self {
        Self { budget }
    }
}

/// A portable replay witness with its claim and final advice from the same execution.
#[derive(Debug)]
pub struct WitnessOutput {
    pub claim: ExecutionClaim,
    pub witness: ExecutionWitness,
    pub advice: AdviceProvider,
}

/// A materialized execution trace with its claim and final advice.
#[derive(Debug)]
pub struct TraceOutput {
    pub claim: ExecutionClaim,
    pub trace: ExecutionTrace,
    pub advice: AdviceProvider,
}

impl<M: ExecutionMode + Copy> ExecutionTask for M {
    type Mode = M;
    type Output = <M as ExecutionMode>::Output;
    type Error = ExecutionError;

    fn mode(&self) -> Self::Mode {
        *self
    }

    fn finish(
        self,
        output: <M as ExecutionMode>::Output,
    ) -> Result<<Self as ExecutionTask>::Output, Self::Error> {
        Ok(output)
    }
}

/// An execution mode owned by the processor crate.
///
/// The sealed implementation selects a recorder and prepares its output. [`Execute`], [`Witness`],
/// and [`Trace`] can be selected directly or used as the mode of a higher-level execution task.
pub trait ExecutionMode: private::ExecutionModeImpl {
    type Output;
}

impl ExecutionMode for Execute {
    type Output = ExecutionOutput;
}

impl ExecutionMode for Witness {
    type Output = WitnessOutput;
}

impl ExecutionMode for Trace {
    type Output = TraceOutput;
}

/// The VM trace and its matching optional portable precompile witness.
#[derive(Debug)]
pub struct ExecutionTrace {
    vm: VmTrace,
    precompile: Option<PrecompileWitness>,
}

impl ExecutionTrace {
    /// Reconstructs an execution trace while checking its authenticated precompile obligation.
    ///
    /// A nonempty trace root requires a witness with the same root. An empty root must not carry
    /// a witness. This checks graph structure and the pairing. Precompile admission, semantic
    /// validity, and proof validity are checked when preparing and verifying the corresponding
    /// proofs.
    pub fn try_new(
        vm: VmTrace,
        precompile: Option<PrecompileWitness>,
    ) -> Result<Self, ExecutionError> {
        let expected = vm.precompile_root();
        match &precompile {
            None if expected != TRUE_DIGEST => {
                return Err(ExecutionError::MissingPrecompileWitness);
            },
            Some(_) if expected == TRUE_DIGEST => {
                return Err(ExecutionError::UnexpectedPrecompileWitness);
            },
            Some(witness) => {
                let actual =
                    witness.compute_root().map_err(ExecutionError::InvalidPrecompileWitness)?;
                if actual != expected {
                    return Err(ExecutionError::PrecompileRootMismatch { expected, actual });
                }
            },
            None => {},
        }
        Ok(Self { vm, precompile })
    }

    /// Borrows the VM trace.
    pub fn vm_trace(&self) -> &VmTrace {
        &self.vm
    }

    /// Borrows the witness for authenticated precompile work, when present.
    pub fn precompile_witness(&self) -> Option<&PrecompileWitness> {
        self.precompile.as_ref()
    }

    /// Extracts the VM trace and discards the precompile witness.
    pub fn into_vm_trace(self) -> VmTrace {
        self.vm
    }

    /// Separates the trace from its optional precompile witness.
    pub fn into_parts(self) -> (VmTrace, Option<PrecompileWitness>) {
        (self.vm, self.precompile)
    }
}

/// Reports progress; the session retains the state required to obtain [`CompletedExecution`].
#[derive(Debug)]
pub enum StepStatus {
    Running,
    Finished,
}

impl StepStatus {
    pub fn is_finished(&self) -> bool {
        matches!(self, Self::Finished)
    }
}

enum SessionState {
    Ready(ResumeContext),
    Busy,
    Finished {
        stack: StackOutputs,
        kernel: KernelDescriptor,
    },
    Failed,
}

/// A resumable execution retaining its continuation context, recorder, and selected task.
///
/// The session owns the VM context prepared at startup. Dropping an in-flight async step or drive
/// leaves the session busy and prevents further execution. The VM state remains inspectable.
pub struct ExecutionSession<T: ExecutionTask> {
    task: T,
    mode: T::Mode,
    processor: FastProcessor,
    program_hash: Word,
    stack_inputs: StackInputs,
    recorder: <T::Mode as private::ExecutionModeImpl>::Recorder,
    state: SessionState,
}

impl<T: ExecutionTask> ExecutionSession<T> {
    /// Returns the VM state for inspection, including after termination, failure, or cancellation.
    pub fn state(&self) -> ProcessorState<'_> {
        self.processor.state()
    }

    /// Drives one step. A halted session returns [`StepStatus::Finished`] without invoking the
    /// host.
    pub fn step_sync(&mut self, host: &mut impl SyncHost) -> Result<StepStatus, ExecutionError> {
        let Some(context) = self.before_step()? else {
            return Ok(StepStatus::Finished);
        };
        let result = self.processor.step_with_tracer_sync(host, context, &mut self.recorder);
        self.after_step(result)
    }

    /// Drives one step with an asynchronous host. See [`Self::step_sync`] for halt behavior.
    pub async fn step(&mut self, host: &mut impl Host) -> Result<StepStatus, ExecutionError> {
        let Some(context) = self.before_step()? else {
            return Ok(StepStatus::Finished);
        };
        let result = self.processor.step_with_tracer(host, context, &mut self.recorder).await;
        self.after_step(result)
    }

    fn before_step(&mut self) -> Result<Option<ResumeContext>, ExecutionError> {
        match core::mem::replace(&mut self.state, SessionState::Busy) {
            SessionState::Ready(context) => Ok(Some(context)),
            finished @ SessionState::Finished { .. } => {
                self.state = finished;
                Ok(None)
            },
            SessionState::Busy | SessionState::Failed => {
                self.state = SessionState::Failed;
                Err(ExecutionError::Internal(
                    "execution session failed or a previous step was cancelled",
                ))
            },
        }
    }

    fn after_step(
        &mut self,
        result: Result<ResumeOutcome, ExecutionError>,
    ) -> Result<StepStatus, ExecutionError> {
        match result {
            Ok(ResumeOutcome::Suspended(context)) => {
                self.state = SessionState::Ready(context);
                Ok(StepStatus::Running)
            },
            Ok(ResumeOutcome::Halted { stack, kernel }) => {
                self.state = SessionState::Finished { stack, kernel };
                Ok(StepStatus::Finished)
            },
            Err(error) => {
                self.state = SessionState::Failed;
                Err(error)
            },
        }
    }

    /// Runs the remaining execution, prepares its artifact, and finalizes the selected task.
    pub fn run_sync(self, host: &mut impl SyncHost) -> Result<T::Output, T::Error> {
        let _span = self.task.run_span().entered();
        self.run_to_completion_sync(host)?.finish()
    }

    /// Awaits host callbacks, then prepares the artifact and finalizes the task on this thread.
    pub async fn run(self, host: &mut impl Host) -> Result<T::Output, T::Error> {
        let span = self.task.run_span();
        async move { self.run_to_completion(host).await?.finish() }
            .instrument(span)
            .await
    }

    /// Runs the remaining VM execution, leaving the session available for inspection or completion.
    pub fn run_until_halt_sync(&mut self, host: &mut impl SyncHost) -> Result<(), ExecutionError> {
        if let Some(context) = self.before_step()? {
            let result = self.processor.drive_to_halt_sync(host, context, &mut self.recorder);
            self.after_step(result)?;
        }
        Ok(())
    }

    /// Awaits the remaining VM execution, leaving the session available for inspection or
    /// completion.
    pub async fn run_until_halt(&mut self, host: &mut impl Host) -> Result<(), ExecutionError> {
        if let Some(context) = self.before_step()? {
            let result = self.processor.drive_to_halt(host, context, &mut self.recorder).await;
            self.after_step(result)?;
        }
        Ok(())
    }

    pub fn run_to_completion_sync(
        mut self,
        host: &mut impl SyncHost,
    ) -> Result<CompletedExecution<T>, ExecutionError> {
        self.run_until_halt_sync(host)?;
        let ControlFlow::Break(completed) = self.try_complete() else {
            unreachable!("successful run completed the session")
        };
        Ok(completed)
    }

    pub async fn run_to_completion(
        mut self,
        host: &mut impl Host,
    ) -> Result<CompletedExecution<T>, ExecutionError> {
        self.run_until_halt(host).await?;
        let ControlFlow::Break(completed) = self.try_complete() else {
            unreachable!("successful run completed the session")
        };
        Ok(completed)
    }

    /// Returns `Break` with a completion token after successful termination, or `Continue` with
    /// the session when it has not completed successfully.
    pub fn try_complete(self) -> ControlFlow<CompletedExecution<T>, Self> {
        let SessionState::Finished { stack, kernel } = self.state else {
            return ControlFlow::Continue(self);
        };
        ControlFlow::Break(CompletedExecution {
            task: self.task,
            mode: self.mode,
            processor: self.processor,
            program_info: ProgramInfo::new(self.program_hash, kernel),
            stack_inputs: self.stack_inputs,
            stack,
            recorder: self.recorder,
        })
    }
}

/// Successfully terminated execution whose artifact and selected task may now be finalized.
///
/// The constructor is private. Only successful VM termination yields a completion value.
pub struct CompletedExecution<T: ExecutionTask> {
    task: T,
    mode: T::Mode,
    processor: FastProcessor,
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack: StackOutputs,
    recorder: <T::Mode as private::ExecutionModeImpl>::Recorder,
}

impl<T: ExecutionTask> CompletedExecution<T> {
    /// Returns the halted VM state before output packaging consumes the processor.
    pub fn state(&self) -> ProcessorState<'_> {
        self.processor.state()
    }

    /// Packages the output, prepares the selected artifact, then finalizes the task.
    ///
    /// Successful VM termination does not guarantee that precompile witness export, trace
    /// construction, or task finalization will succeed under their configured limits.
    pub fn finish(self) -> Result<T::Output, T::Error> {
        let output = self.processor.into_execution_output(self.stack)?;
        let artifact = private::ExecutionModeImpl::prepare_output(
            self.mode,
            || self.program_info,
            self.stack_inputs,
            output,
            self.recorder,
        )?;
        self.task.finish(artifact)
    }
}

mod private {
    use super::*;

    pub trait ExecutionModeImpl: Sized {
        // This sealed driver deliberately keeps the VM tracer contract internal.
        #[allow(private_bounds)]
        type Recorder: Tracer<Processor = FastProcessor, Forest = Arc<MastForest>>;

        fn recorder(&self, processor: &FastProcessor) -> Self::Recorder;

        fn prepare_output(
            self,
            program_info: impl FnOnce() -> ProgramInfo,
            stack_inputs: StackInputs,
            output: ExecutionOutput,
            recorder: Self::Recorder,
        ) -> Result<<Self as ExecutionMode>::Output, ExecutionError>
        where
            Self: ExecutionMode;

        fn run_sync(
            self,
            processor: FastProcessor,
            program: &Program,
            source_context: Option<PackageSourceDebugContext<'_>>,
            host: &mut impl SyncHost,
        ) -> Result<<Self as ExecutionMode>::Output, ExecutionError>
        where
            Self: ExecutionMode,
        {
            let stack_inputs = processor.initial_stack_inputs();
            let mut recorder = self.recorder(&processor);
            let output =
                processor.run_with_tracer_sync(program, source_context, host, &mut recorder)?;
            self.prepare_output(|| program.to_info(), stack_inputs, output, recorder)
        }

        fn run(
            self,
            processor: FastProcessor,
            program: &Program,
            source_context: Option<PackageSourceDebugContext<'_>>,
            host: &mut impl Host,
        ) -> impl Future<Output = Result<<Self as ExecutionMode>::Output, ExecutionError>>
        where
            Self: ExecutionMode,
        {
            async move {
                let stack_inputs = processor.initial_stack_inputs();
                let mut recorder = self.recorder(&processor);
                let output =
                    processor.run_with_tracer(program, source_context, host, &mut recorder).await?;
                self.prepare_output(|| program.to_info(), stack_inputs, output, recorder)
            }
        }
    }

    impl ExecutionModeImpl for Execute {
        type Recorder = NoopTracer;
        fn recorder(&self, _: &FastProcessor) -> Self::Recorder {
            NoopTracer
        }
        fn prepare_output(
            self,
            _: impl FnOnce() -> ProgramInfo,
            _: StackInputs,
            output: ExecutionOutput,
            _: NoopTracer,
        ) -> Result<ExecutionOutput, ExecutionError> {
            Ok(output)
        }
    }

    impl ExecutionModeImpl for Witness {
        type Recorder = ExecutionTracer;
        fn recorder(&self, processor: &FastProcessor) -> Self::Recorder {
            processor.new_tracer()
        }
        fn prepare_output(
            self,
            program_info: impl FnOnce() -> ProgramInfo,
            stack_inputs: StackInputs,
            output: ExecutionOutput,
            recorder: ExecutionTracer,
        ) -> Result<WitnessOutput, ExecutionError> {
            let (witness, advice) = FastProcessor::execution_witness_from_parts(
                program_info(),
                stack_inputs,
                output,
                recorder,
            );
            let claim = witness.claim();
            Ok(WitnessOutput { claim, witness, advice })
        }
    }

    impl ExecutionModeImpl for Trace {
        type Recorder = ExecutionTracer;
        fn recorder(&self, processor: &FastProcessor) -> Self::Recorder {
            processor.new_tracer()
        }
        fn prepare_output(
            self,
            program_info: impl FnOnce() -> ProgramInfo,
            stack_inputs: StackInputs,
            output: ExecutionOutput,
            recorder: ExecutionTracer,
        ) -> Result<TraceOutput, ExecutionError> {
            let WitnessOutput { claim, witness, advice } =
                Witness.prepare_output(program_info, stack_inputs, output, recorder)?;
            // These components come from the same VM execution. Preserve that trusted handoff
            // without reconstructing precompile roots before the prover applies its admission
            // limits. Imported full witnesses use ExecutionWitness::build_trace instead.
            let (vm_witness, precompile) = witness.into_parts();
            let vm = build_trace(vm_witness, &self.budget)?;
            Ok(TraceOutput {
                claim,
                trace: ExecutionTrace { vm, precompile },
                advice,
            })
        }

        #[cfg(feature = "std")]
        fn run_sync(
            self,
            processor: FastProcessor,
            program: &Program,
            source_context: Option<PackageSourceDebugContext<'_>>,
            host: &mut impl SyncHost,
        ) -> Result<TraceOutput, ExecutionError> {
            let stack_inputs = processor.initial_stack_inputs();
            if processor.overlapped_trace_build() {
                let (vm, precompile, advice) =
                    processor.build_trace_sync(program, source_context, host, &self.budget)?;
                let claim = ExecutionClaim::from_program_info(
                    program.to_info(),
                    stack_inputs,
                    *vm.stack_outputs(),
                );
                return Ok(TraceOutput {
                    claim,
                    trace: ExecutionTrace { vm, precompile },
                    advice,
                });
            }
            let mut recorder = self.recorder(&processor);
            let output =
                processor.run_with_tracer_sync(program, source_context, host, &mut recorder)?;
            self.prepare_output(|| program.to_info(), stack_inputs, output, recorder)
        }
    }
}
