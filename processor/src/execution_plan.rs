//! Typed execution requests and resumable execution for the processor engine.
//!
//! Execution modes select the VM recorder and the output produced after successful execution.

use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::mast::MastForest;

use crate::{
    AdviceInputs, AdviceProvider, ExecutionClaim, ExecutionError, ExecutionOptions,
    ExecutionOutput, ExecutionWitness, FastProcessor, Host, KernelDescriptor,
    PackageSourceDebugContext, PrecompileWitness, ProcessorState, Program, ProgramInfo,
    ResumeContext, StackInputs, StackOutputs, SyncHost, Word,
    errors::MapExecErrNoCtx,
    fast::{NoopTracer, ResumeOutcome},
    trace::{VmTrace, execution_tracer::ExecutionTracer},
    tracer::Tracer,
};

/// The VM relation's trace-building memory model and caller-selected byte limit.
pub type VmTraceBudget =
    miden_stark::memory::ProvingBudget<{ miden_air_definitions::vm::MIDEN_AIR_COUNT }>;

/// Program-bound configuration before selecting an execution mode.
///
/// Configuration setters retain raw inputs. Advice is validated against the final execution
/// options when execution is prepared, run, or started, independently of setter order.
pub struct Processor<'p> {
    program: &'p Program,
    inputs: ExecutionInputs,
    source_context: Option<PackageSourceDebugContext<'p>>,
}

struct ExecutionInputs {
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    options: ExecutionOptions,
}

impl<'p> Processor<'p> {
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
    ) -> Processor<'s>
    where
        'p: 's,
    {
        Processor {
            program: self.program,
            inputs: self.inputs,
            source_context,
        }
    }

    /// Selects ordinary execution without replay recording.
    pub fn execute(self) -> ExecutionPlan<'p, Execute> {
        self.with_mode(Execute)
    }

    /// Selects a compact execution witness with its claim and final advice.
    pub fn record_witness(self) -> ExecutionPlan<'p, RecordWitness> {
        self.with_mode(RecordWitness)
    }

    /// Selects VM trace construction under the supplied relation-compatible budget.
    pub fn build_trace(self, budget: VmTraceBudget) -> ExecutionPlan<'p, BuildTrace> {
        self.with_mode(BuildTrace { budget })
    }

    fn with_mode<M: ExecutionMode>(self, mode: M) -> ExecutionPlan<'p, M> {
        ExecutionPlan {
            processor: ProcessorSource::Inputs(self.inputs),
            program: self.program,
            source_context: self.source_context,
            mode,
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

/// A program and processor configuration bound to one execution mode.
///
/// Running or starting consumes this value. Continuing an execution requires the returned session,
/// which retains the recorder selected for this mode.
pub struct ExecutionPlan<'p, M: ExecutionMode> {
    processor: ProcessorSource,
    program: &'p Program,
    source_context: Option<PackageSourceDebugContext<'p>>,
    mode: M,
}

impl<'p, M: ExecutionMode> ExecutionPlan<'p, M> {
    /// Binds a test fixture's initialized machine before its first cycle.
    #[cfg(test)]
    pub(crate) fn from_processor(
        processor: FastProcessor,
        program: &'p Program,
        mode: M,
    ) -> Result<Self, ExecutionError> {
        if u32::from(processor.state().clock()) != 0 {
            return Err(ExecutionError::Internal("an execution plan requires a fresh processor"));
        }
        Ok(Self {
            processor: ProcessorSource::Initialized(processor),
            program,
            source_context: None,
            mode,
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

    /// Runs to completion with a synchronous host.
    ///
    /// A host that only implements [`Host`] must use [`Self::run`].
    ///
    /// ```compile_fail
    /// use miden_processor::{Host, Processor, Program};
    ///
    /// fn run(program: &Program, host: &mut impl Host) {
    ///     let _ = Processor::new(program).execute().run_sync(host);
    /// }
    /// ```
    pub fn run_sync(self, host: &mut impl SyncHost) -> Result<M::Output, ExecutionError> {
        let processor = self.processor.into_processor()?;
        // Full synchronous execution retains each mode's optimized path, including overlapped
        // hasher trace construction. Stepped execution deliberately uses buffered recording.
        private::ExecutionModeImpl::run_sync(
            self.mode,
            processor,
            self.program,
            self.source_context,
            host,
        )
    }

    /// Awaits host callbacks, then prepares the mode's output on the calling thread.
    /// Trace construction uses buffered replay after execution.
    pub async fn run(self, host: &mut impl Host) -> Result<M::Output, ExecutionError> {
        let processor = self.processor.into_processor()?;
        private::ExecutionModeImpl::run(
            self.mode,
            processor,
            self.program,
            self.source_context,
            host,
        )
        .await
    }

    /// Starts a session without invoking the host. The recorder is retained across pauses.
    pub fn start(self) -> Result<ExecutionSession<M>, ExecutionError> {
        let mut processor = self.processor.into_processor()?;
        let context = processor.start_context(self.program, self.source_context)?;
        let program_hash = self.program.hash();
        let stack_inputs = processor.initial_stack_inputs();
        let recorder = private::ExecutionModeImpl::recorder(&self.mode, &processor);
        Ok(ExecutionSession {
            mode: self.mode,
            processor,
            program_hash,
            stack_inputs,
            recorder,
            state: SessionState::Ready(context),
        })
    }
}

/// Ordinary execution without replay recording.
///
/// This mode returns the final processor output.
#[derive(Debug, Clone, Copy)]
pub struct Execute;

/// Execution producing a portable replay witness and final advice.
#[derive(Debug, Clone, Copy)]
pub struct RecordWitness;

/// Execution producing a VM trace under a supplied memory budget.
///
/// Synchronous full runs may overlap hasher building with execution when execution options allow
/// it. Async execution and stepped sessions prepare the same trace from buffered replay.
#[derive(Debug, Clone, Copy)]
pub struct BuildTrace {
    budget: VmTraceBudget,
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

/// An execution mode owned by the processor crate.
///
/// Select a mode through [`Processor::execute`], [`Processor::record_witness`],
/// or [`Processor::build_trace`]. The sealed implementation selects a recorder and prepares
/// the output.
pub trait ExecutionMode: private::ExecutionModeImpl {
    type Output;
}

impl ExecutionMode for Execute {
    type Output = ExecutionOutput;
}

impl ExecutionMode for RecordWitness {
    type Output = WitnessOutput;
}

impl ExecutionMode for BuildTrace {
    type Output = TraceOutput;
}

/// The VM trace and its optional portable precompile witness from the same execution.
///
/// Produced by the execution mode selected with [`Processor::build_trace`].
#[derive(Debug)]
pub struct ExecutionTrace {
    vm: VmTrace,
    precompile: Option<PrecompileWitness>,
}

impl ExecutionTrace {
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

/// Reports progress; the session retains the state required to obtain [`HaltedExecution`].
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

/// A resumable execution retaining its continuation context and recorder.
///
/// The session owns the VM context prepared at startup. Dropping an in-flight async step or drive
/// leaves the session busy and prevents further execution. The VM state remains inspectable.
///
/// Only a [`HaltedExecution`] can export the selected artifact with `finish`.
///
/// ```compile_fail
/// use miden_processor::{ExecutionSession, RecordWitness};
///
/// fn finish(session: ExecutionSession<RecordWitness>) {
///     let _ = session.finish();
/// }
/// ```
pub struct ExecutionSession<M: ExecutionMode> {
    mode: M,
    processor: FastProcessor,
    program_hash: Word,
    stack_inputs: StackInputs,
    recorder: M::Recorder,
    state: SessionState,
}

impl<M: ExecutionMode> ExecutionSession<M> {
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

    /// Runs the remaining execution and prepares the mode's output.
    pub fn run_sync(self, host: &mut impl SyncHost) -> Result<M::Output, ExecutionError> {
        self.run_to_completion_sync(host)?.finish()
    }

    /// Awaits host callbacks, then prepares the mode's output on the calling thread.
    pub async fn run(self, host: &mut impl Host) -> Result<M::Output, ExecutionError> {
        self.run_to_completion(host).await?.finish()
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
    ) -> Result<HaltedExecution<M>, ExecutionError> {
        self.run_until_halt_sync(host)?;
        let ControlFlow::Break(completed) = self.try_complete() else {
            unreachable!("successful run completed the session")
        };
        Ok(completed)
    }

    pub async fn run_to_completion(
        mut self,
        host: &mut impl Host,
    ) -> Result<HaltedExecution<M>, ExecutionError> {
        self.run_until_halt(host).await?;
        let ControlFlow::Break(completed) = self.try_complete() else {
            unreachable!("successful run completed the session")
        };
        Ok(completed)
    }

    /// Returns `Break` with a completion token after successful termination, or `Continue` with
    /// the session when it has not completed successfully.
    pub fn try_complete(self) -> ControlFlow<HaltedExecution<M>, Self> {
        let SessionState::Finished { stack, kernel } = self.state else {
            return ControlFlow::Continue(self);
        };
        ControlFlow::Break(HaltedExecution {
            mode: self.mode,
            processor: self.processor,
            program_info: ProgramInfo::new(self.program_hash, kernel),
            stack_inputs: self.stack_inputs,
            stack,
            recorder: self.recorder,
        })
    }
}

/// Successfully terminated execution whose output may now be prepared.
///
/// The constructor is private. Only successful VM termination yields a completion value.
pub struct HaltedExecution<M: ExecutionMode> {
    mode: M,
    processor: FastProcessor,
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack: StackOutputs,
    recorder: M::Recorder,
}

impl<M: ExecutionMode> HaltedExecution<M> {
    /// Returns the halted VM state before output packaging consumes the processor.
    pub fn state(&self) -> ProcessorState<'_> {
        self.processor.state()
    }

    /// Exports the execution outputs and prepares the selected artifact.
    ///
    /// Precompile witness export and trace construction still enforce their configured limits.
    pub fn finish(self) -> Result<M::Output, ExecutionError> {
        let output = self.processor.into_execution_output(self.stack)?;
        private::ExecutionModeImpl::prepare_output(
            self.mode,
            || self.program_info,
            self.stack_inputs,
            output,
            self.recorder,
        )
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

    impl ExecutionModeImpl for RecordWitness {
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

    impl ExecutionModeImpl for BuildTrace {
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
                RecordWitness.prepare_output(program_info, stack_inputs, output, recorder)?;
            let (vm_witness, precompile) = witness.into_parts();
            let vm = vm_witness.build_trace(&self.budget)?;
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
