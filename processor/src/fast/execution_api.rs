use alloc::{sync::Arc, vec::Vec};
use core::ops::ControlFlow;

use miden_core::{
    Word,
    mast::{MastForest, MastNodeId},
    program::{Kernel, MIN_STACK_DEPTH, Program, StackOutputs},
};
use tracing::instrument;

use super::{
    FastProcessor, NoopTracer,
    external::maybe_use_caller_error_context,
    step::{BreakReason, NeverStopper, ResumeContext, StepStopper},
};
use crate::{
    ExecutionError, ExecutionOutput, Host, Stopper, SyncHost, TraceBuildInputs,
    continuation_stack::ContinuationStack,
    errors::{MapExecErr, MapExecErrNoCtx, OperationError},
    execution::{
        InternalBreakReason, execute_impl, finish_emit_op_execution,
        finish_load_mast_forest_from_dyn_start, finish_load_mast_forest_from_external,
    },
    trace::execution_tracer::ExecutionTracer,
    tracer::Tracer,
};

impl FastProcessor {
    // EXECUTE
    // -------------------------------------------------------------------------------------------

    /// Executes the given program synchronously and returns the execution output.
    pub fn execute_sync(
        self,
        program: &Program,
        host: &mut impl SyncHost,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_tracer_sync(program, host, &mut NoopTracer)
    }

    /// Async variant of [`Self::execute_sync`] for hosts that need async callbacks.
    #[inline(always)]
    pub async fn execute(
        self,
        program: &Program,
        host: &mut impl Host,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_tracer(program, host, &mut NoopTracer).await
    }

    /// Executes the given program synchronously and returns the bundled trace inputs required by
    /// [`crate::trace::build_trace`].
    ///
    /// # Example
    /// ```
    /// use miden_assembly::Assembler;
    /// use miden_processor::{DefaultHost, FastProcessor, StackInputs};
    ///
    /// let program = Assembler::default().assemble_program("begin push.1 drop end").unwrap();
    /// let mut host = DefaultHost::default();
    ///
    /// let trace_inputs = FastProcessor::new(StackInputs::default())
    ///     .execute_trace_inputs_sync(&program, &mut host)
    ///     .unwrap();
    /// let trace = miden_processor::trace::build_trace(trace_inputs).unwrap();
    ///
    /// assert_eq!(*trace.program_hash(), program.hash());
    /// ```
    #[instrument(name = "execute_trace_inputs_sync", skip_all)]
    pub fn execute_trace_inputs_sync(
        self,
        program: &Program,
        host: &mut impl SyncHost,
    ) -> Result<TraceBuildInputs, ExecutionError> {
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
        );
        let execution_output = self.execute_with_tracer_sync(program, host, &mut tracer)?;
        Ok(Self::trace_build_inputs_from_parts(program, execution_output, tracer))
    }

    /// Async variant of [`Self::execute_trace_inputs_sync`] for async hosts.
    #[inline(always)]
    #[instrument(name = "execute_trace_inputs", skip_all)]
    pub async fn execute_trace_inputs(
        self,
        program: &Program,
        host: &mut impl Host,
    ) -> Result<TraceBuildInputs, ExecutionError> {
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
        );
        let execution_output = self.execute_with_tracer(program, host, &mut tracer).await?;
        Ok(Self::trace_build_inputs_from_parts(program, execution_output, tracer))
    }

    /// Executes the given program with the provided tracer using an async host.
    pub async fn execute_with_tracer<T>(
        mut self,
        program: &Program,
        host: &mut impl Host,
        tracer: &mut T,
    ) -> Result<ExecutionOutput, ExecutionError>
    where
        T: Tracer<Processor = Self>,
    {
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();

        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;
        let flow = self
            .execute_impl_async(
                &mut continuation_stack,
                &mut current_forest,
                program.kernel(),
                host,
                tracer,
                &NeverStopper,
            )
            .await;
        Self::execution_result_from_flow(flow, self)
    }

    /// Executes the given program with the provided tracer using a sync host.
    pub fn execute_with_tracer_sync<T>(
        mut self,
        program: &Program,
        host: &mut impl SyncHost,
        tracer: &mut T,
    ) -> Result<ExecutionOutput, ExecutionError>
    where
        T: Tracer<Processor = Self>,
    {
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();

        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;
        let flow = self.execute_impl(
            &mut continuation_stack,
            &mut current_forest,
            program.kernel(),
            host,
            tracer,
            &NeverStopper,
        );
        Self::execution_result_from_flow(flow, self)
    }

    /// Executes a single clock cycle synchronously.
    pub fn step_sync(
        &mut self,
        host: &mut impl SyncHost,
        resume_ctx: ResumeContext,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        let ResumeContext {
            mut current_forest,
            mut continuation_stack,
            kernel,
        } = resume_ctx;

        let flow = self.execute_impl(
            &mut continuation_stack,
            &mut current_forest,
            &kernel,
            host,
            &mut NoopTracer,
            &StepStopper,
        );
        Self::resume_context_from_flow(flow, continuation_stack, current_forest, kernel)
    }

    /// Async variant of [`Self::step_sync`].
    #[inline(always)]
    pub async fn step(
        &mut self,
        host: &mut impl Host,
        resume_ctx: ResumeContext,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        let ResumeContext {
            mut current_forest,
            mut continuation_stack,
            kernel,
        } = resume_ctx;

        let flow = self
            .execute_impl_async(
                &mut continuation_stack,
                &mut current_forest,
                &kernel,
                host,
                &mut NoopTracer,
                &StepStopper,
            )
            .await;
        Self::resume_context_from_flow(flow, continuation_stack, current_forest, kernel)
    }

    /// Pairs execution output with the trace inputs captured by the tracer.
    #[inline(always)]
    fn trace_build_inputs_from_parts(
        program: &Program,
        execution_output: ExecutionOutput,
        tracer: ExecutionTracer,
    ) -> TraceBuildInputs {
        TraceBuildInputs::from_execution(
            program,
            execution_output,
            tracer.into_trace_generation_context(),
        )
    }

    /// Converts a step-wise execution result into the next resume context, if execution stopped.
    #[inline(always)]
    fn resume_context_from_flow(
        flow: ControlFlow<BreakReason, StackOutputs>,
        mut continuation_stack: ContinuationStack,
        current_forest: Arc<MastForest>,
        kernel: Kernel,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        match flow {
            ControlFlow::Continue(_) => Ok(None),
            ControlFlow::Break(break_reason) => match break_reason {
                BreakReason::Err(err) => Err(err),
                BreakReason::Stopped(maybe_continuation) => {
                    if let Some(continuation) = maybe_continuation {
                        continuation_stack.push_continuation(continuation);
                    }

                    Ok(Some(ResumeContext {
                        current_forest,
                        continuation_stack,
                        kernel,
                    }))
                },
            },
        }
    }

    /// Materializes the current stack as public outputs without consuming the processor.
    #[inline(always)]
    fn current_stack_outputs(&self) -> StackOutputs {
        StackOutputs::new(
            &self.stack[self.stack_bot_idx..self.stack_top_idx]
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    /// Executes the given program with the provided tracer and returns the stack outputs.
    ///
    /// This function takes a `&mut self` (compared to `self` for the public sync execution
    /// methods) so that the processor state may be accessed after execution. Reusing the same
    /// processor for a second program is incorrect. This is mainly meant to be used in tests.
    fn execute_impl<S, T>(
        &mut self,
        continuation_stack: &mut ContinuationStack,
        current_forest: &mut Arc<MastForest>,
        kernel: &Kernel,
        host: &mut impl SyncHost,
        tracer: &mut T,
        stopper: &S,
    ) -> ControlFlow<BreakReason, StackOutputs>
    where
        S: Stopper<Processor = Self>,
        T: Tracer<Processor = Self>,
    {
        while let ControlFlow::Break(internal_break_reason) =
            execute_impl(self, continuation_stack, current_forest, kernel, host, tracer, stopper)
        {
            match internal_break_reason {
                InternalBreakReason::User(break_reason) => return ControlFlow::Break(break_reason),
                InternalBreakReason::Emit {
                    basic_block_node_id,
                    op_idx,
                    continuation,
                } => {
                    self.op_emit_sync(host, current_forest, basic_block_node_id, op_idx)?;

                    finish_emit_op_execution(
                        continuation,
                        self,
                        continuation_stack,
                        current_forest,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromDyn { dyn_node_id, callee_hash } => {
                    let (root_id, new_forest) = match self.load_mast_forest_sync(
                        callee_hash,
                        host,
                        current_forest,
                        dyn_node_id,
                    ) {
                        Ok(result) => result,
                        Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
                    };

                    finish_load_mast_forest_from_dyn_start(
                        root_id,
                        new_forest,
                        self,
                        current_forest,
                        continuation_stack,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromExternal {
                    external_node_id,
                    procedure_hash,
                } => {
                    let (root_id, new_forest) = match self.load_mast_forest_sync(
                        procedure_hash,
                        host,
                        current_forest,
                        external_node_id,
                    ) {
                        Ok(result) => result,
                        Err(err) => {
                            let maybe_enriched_err = maybe_use_caller_error_context(
                                err,
                                current_forest,
                                continuation_stack,
                                host,
                            );

                            return ControlFlow::Break(BreakReason::Err(maybe_enriched_err));
                        },
                    };

                    finish_load_mast_forest_from_external(
                        root_id,
                        new_forest,
                        external_node_id,
                        current_forest,
                        continuation_stack,
                        host,
                        tracer,
                    )?;
                },
            }
        }

        match StackOutputs::new(
            &self.stack[self.stack_bot_idx..self.stack_top_idx]
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>(),
        ) {
            Ok(stack_outputs) => ControlFlow::Continue(stack_outputs),
            Err(_) => ControlFlow::Break(BreakReason::Err(ExecutionError::OutputStackOverflow(
                self.stack_top_idx - self.stack_bot_idx - MIN_STACK_DEPTH,
            ))),
        }
    }

    async fn execute_impl_async<S, T>(
        &mut self,
        continuation_stack: &mut ContinuationStack,
        current_forest: &mut Arc<MastForest>,
        kernel: &Kernel,
        host: &mut impl Host,
        tracer: &mut T,
        stopper: &S,
    ) -> ControlFlow<BreakReason, StackOutputs>
    where
        S: Stopper<Processor = Self>,
        T: Tracer<Processor = Self>,
    {
        while let ControlFlow::Break(internal_break_reason) =
            execute_impl(self, continuation_stack, current_forest, kernel, host, tracer, stopper)
        {
            match internal_break_reason {
                InternalBreakReason::User(break_reason) => return ControlFlow::Break(break_reason),
                InternalBreakReason::Emit {
                    basic_block_node_id,
                    op_idx,
                    continuation,
                } => {
                    self.op_emit(host, current_forest, basic_block_node_id, op_idx).await?;

                    finish_emit_op_execution(
                        continuation,
                        self,
                        continuation_stack,
                        current_forest,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromDyn { dyn_node_id, callee_hash } => {
                    let (root_id, new_forest) = match self
                        .load_mast_forest(callee_hash, host, current_forest, dyn_node_id)
                        .await
                    {
                        Ok(result) => result,
                        Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
                    };

                    finish_load_mast_forest_from_dyn_start(
                        root_id,
                        new_forest,
                        self,
                        current_forest,
                        continuation_stack,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromExternal {
                    external_node_id,
                    procedure_hash,
                } => {
                    let (root_id, new_forest) = match self
                        .load_mast_forest(procedure_hash, host, current_forest, external_node_id)
                        .await
                    {
                        Ok(result) => result,
                        Err(err) => {
                            let maybe_enriched_err = maybe_use_caller_error_context(
                                err,
                                current_forest,
                                continuation_stack,
                                host,
                            );

                            return ControlFlow::Break(BreakReason::Err(maybe_enriched_err));
                        },
                    };

                    finish_load_mast_forest_from_external(
                        root_id,
                        new_forest,
                        external_node_id,
                        current_forest,
                        continuation_stack,
                        host,
                        tracer,
                    )?;
                },
            }
        }

        match StackOutputs::new(
            &self.stack[self.stack_bot_idx..self.stack_top_idx]
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>(),
        ) {
            Ok(stack_outputs) => ControlFlow::Continue(stack_outputs),
            Err(_) => ControlFlow::Break(BreakReason::Err(ExecutionError::OutputStackOverflow(
                self.stack_top_idx - self.stack_bot_idx - MIN_STACK_DEPTH,
            ))),
        }
    }

    // HELPERS
    // ------------------------------------------------------------------------------------------

    fn load_mast_forest_sync(
        &mut self,
        node_digest: Word,
        host: &mut impl SyncHost,
        current_forest: &MastForest,
        node_id: MastNodeId,
    ) -> Result<(MastNodeId, Arc<MastForest>), ExecutionError> {
        let mast_forest = host.get_mast_forest(&node_digest).ok_or_else(|| {
            crate::errors::procedure_not_found_with_context(
                node_digest,
                current_forest,
                node_id,
                host,
            )
        })?;

        let root_id = mast_forest.find_procedure_root(node_digest).ok_or_else(|| {
            Err::<(), _>(OperationError::MalformedMastForestInHost { root_digest: node_digest })
                .map_exec_err(current_forest, node_id, host)
                .unwrap_err()
        })?;

        self.advice.extend_map(mast_forest.advice_map()).map_exec_err(
            current_forest,
            node_id,
            host,
        )?;

        Ok((root_id, mast_forest))
    }

    async fn load_mast_forest(
        &mut self,
        node_digest: Word,
        host: &mut impl Host,
        current_forest: &MastForest,
        node_id: MastNodeId,
    ) -> Result<(MastNodeId, Arc<MastForest>), ExecutionError> {
        let mast_forest = if let Some(mast_forest) = host.get_mast_forest(&node_digest).await {
            mast_forest
        } else {
            return Err(crate::errors::procedure_not_found_with_context(
                node_digest,
                current_forest,
                node_id,
                host,
            ));
        };

        let root_id = mast_forest.find_procedure_root(node_digest).ok_or_else(|| {
            Err::<(), _>(OperationError::MalformedMastForestInHost { root_digest: node_digest })
                .map_exec_err(current_forest, node_id, host)
                .unwrap_err()
        })?;

        self.advice.extend_map(mast_forest.advice_map()).map_exec_err(
            current_forest,
            node_id,
            host,
        )?;

        Ok((root_id, mast_forest))
    }

    /// Executes the given program synchronously one step at a time.
    pub fn execute_by_step_sync(
        mut self,
        program: &Program,
        host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut current_resume_ctx = self.get_initial_resume_context(program).unwrap();

        loop {
            match self.step_sync(host, current_resume_ctx)? {
                Some(next_resume_ctx) => {
                    current_resume_ctx = next_resume_ctx;
                },
                None => break Ok(self.current_stack_outputs()),
            }
        }
    }

    /// Async variant of [`Self::execute_by_step_sync`].
    #[inline(always)]
    pub async fn execute_by_step(
        mut self,
        program: &Program,
        host: &mut impl Host,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut current_resume_ctx = self.get_initial_resume_context(program).unwrap();
        let mut processor = self;

        loop {
            match processor.step(host, current_resume_ctx).await? {
                Some(next_resume_ctx) => {
                    current_resume_ctx = next_resume_ctx;
                },
                None => break Ok(processor.current_stack_outputs()),
            }
        }
    }

    /// Similar to [`Self::execute_sync`], but allows mutable access to the processor.
    ///
    /// This is mainly meant to be used in tests.
    #[cfg(any(test, feature = "testing"))]
    pub fn execute_mut_sync(
        &mut self,
        program: &Program,
        host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();

        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;

        let flow = self.execute_impl(
            &mut continuation_stack,
            &mut current_forest,
            program.kernel(),
            host,
            &mut NoopTracer,
            &NeverStopper,
        );
        Self::stack_result_from_flow(flow)
    }

    /// Async variant of [`Self::execute_mut_sync`].
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    pub async fn execute_mut(
        &mut self,
        program: &Program,
        host: &mut impl Host,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();

        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;

        let flow = self
            .execute_impl_async(
                &mut continuation_stack,
                &mut current_forest,
                program.kernel(),
                host,
                &mut NoopTracer,
                &NeverStopper,
            )
            .await;
        Self::stack_result_from_flow(flow)
    }
}
