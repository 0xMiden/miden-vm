use alloc::{sync::Arc, vec::Vec};
use core::ops::ControlFlow;

use miden_core::{
    Word,
    mast::{MastForest, MastNodeId},
    program::{Kernel, MIN_STACK_DEPTH, Program, StackOutputs},
};
use miden_mast_package::debug_info::{
    DebugSourceGraphLookupError, DebugSourceNodeId, PackageDebugInfo,
};
use tracing::instrument;

use super::{
    FastProcessor, NoopTracer,
    external::maybe_use_caller_error_context,
    step::{BreakReason, NeverStopper, ResumeContext, StepStopper},
};
use crate::{
    ExecutionError, ExecutionOutput, Host, LoadedMastForest, Stopper, SyncHost, TraceBuildInputs,
    continuation_stack::ContinuationStack,
    errors::{
        MapExecErr, MapExecErrNoCtx, PackageSourceDebugContext, malformed_mast_forest_with_context,
    },
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

    /// Executes the given program synchronously with package-owned source/debug context.
    ///
    /// This derives the entrypoint source occurrence from [`PackageDebugInfo`], so the source graph
    /// must contain at most one root for the executable entrypoint. When the package manifest names
    /// the exact entrypoint source occurrence, use
    /// [`Self::execute_with_package_debug_info_at_source_node_sync`] instead.
    pub fn execute_with_package_debug_info_sync(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl SyncHost,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_package_debug_info_and_tracer_sync(
            program,
            package_debug_info,
            None,
            host,
            &mut NoopTracer,
        )
    }

    /// Executes the given program synchronously with package-owned source/debug context rooted at
    /// `entrypoint_source_node_id`.
    ///
    /// Use this when the package manifest names the exact source/debug occurrence for the
    /// executable entrypoint. This preserves source disambiguation when multiple source roots map
    /// to the same executable MAST node.
    pub fn execute_with_package_debug_info_at_source_node_sync(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl SyncHost,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_package_debug_info_and_tracer_sync(
            program,
            package_debug_info,
            Some(entrypoint_source_node_id),
            host,
            &mut NoopTracer,
        )
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

    /// Async variant of [`Self::execute_with_package_debug_info_sync`].
    ///
    /// When the package manifest names the exact entrypoint source occurrence, use
    /// [`Self::execute_with_package_debug_info_at_source_node`] instead.
    #[inline(always)]
    pub async fn execute_with_package_debug_info(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl Host,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_package_debug_info_and_tracer(
            program,
            package_debug_info,
            None,
            host,
            &mut NoopTracer,
        )
        .await
    }

    /// Async variant of [`Self::execute_with_package_debug_info_at_source_node_sync`].
    #[inline(always)]
    pub async fn execute_with_package_debug_info_at_source_node(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl Host,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_package_debug_info_and_tracer(
            program,
            package_debug_info,
            Some(entrypoint_source_node_id),
            host,
            &mut NoopTracer,
        )
        .await
    }

    /// Executes the given program synchronously and returns the bundled trace inputs required by
    /// [`crate::trace::build_trace`].
    ///
    /// # Example
    /// ```
    /// use miden_assembly::Assembler;
    /// use miden_processor::{DefaultHost, FastProcessor, StackInputs};
    ///
    /// let program = Assembler::default()
    ///     .assemble_program("prg", "begin push.1 drop end")
    ///     .unwrap()
    ///     .unwrap_program();
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

    /// Executes the given program synchronously with package-owned source/debug context and returns
    /// the bundled trace inputs required by [`crate::trace::build_trace`].
    #[instrument(name = "execute_trace_inputs_with_package_debug_info_sync", skip_all)]
    pub fn execute_trace_inputs_with_package_debug_info_sync(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl SyncHost,
    ) -> Result<TraceBuildInputs, ExecutionError> {
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
        );
        let execution_output = self.execute_with_package_debug_info_and_tracer_sync(
            program,
            package_debug_info,
            None,
            host,
            &mut tracer,
        )?;
        Ok(Self::trace_build_inputs_from_parts(program, execution_output, tracer))
    }

    /// Executes the given program synchronously with package-owned source/debug context rooted at
    /// `entrypoint_source_node_id` and returns the bundled trace inputs required by
    /// [`crate::trace::build_trace`].
    #[instrument(
        name = "execute_trace_inputs_with_package_debug_info_at_source_node_sync",
        skip_all
    )]
    pub fn execute_trace_inputs_with_package_debug_info_at_source_node_sync(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl SyncHost,
    ) -> Result<TraceBuildInputs, ExecutionError> {
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
        );
        let execution_output = self.execute_with_package_debug_info_and_tracer_sync(
            program,
            package_debug_info,
            Some(entrypoint_source_node_id),
            host,
            &mut tracer,
        )?;
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

    /// Async variant of [`Self::execute_trace_inputs_with_package_debug_info_sync`].
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    #[instrument(name = "execute_trace_inputs_with_package_debug_info", skip_all)]
    pub async fn execute_trace_inputs_with_package_debug_info(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl Host,
    ) -> Result<TraceBuildInputs, ExecutionError> {
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
        );
        let execution_output = self
            .execute_with_package_debug_info_and_tracer(
                program,
                package_debug_info,
                None,
                host,
                &mut tracer,
            )
            .await?;
        Ok(Self::trace_build_inputs_from_parts(program, execution_output, tracer))
    }

    /// Async variant of
    /// [`Self::execute_trace_inputs_with_package_debug_info_at_source_node_sync`].
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    #[instrument(name = "execute_trace_inputs_with_package_debug_info_at_source_node", skip_all)]
    pub async fn execute_trace_inputs_with_package_debug_info_at_source_node(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl Host,
    ) -> Result<TraceBuildInputs, ExecutionError> {
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
        );
        let execution_output = self
            .execute_with_package_debug_info_and_tracer(
                program,
                package_debug_info,
                Some(entrypoint_source_node_id),
                host,
                &mut tracer,
            )
            .await?;
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
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();
        let mut package_debug_info = None;

        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;
        let flow = self
            .execute_impl_async(
                &mut continuation_stack,
                &mut current_forest,
                program.kernel(),
                host,
                tracer,
                &NeverStopper,
                &mut package_debug_info,
            )
            .await;
        Self::execution_result_from_flow(flow, self)
    }

    /// Executes the given program with package-owned source/debug context and the provided tracer
    /// using an async host.
    async fn execute_with_package_debug_info_and_tracer<T>(
        mut self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: Option<DebugSourceNodeId>,
        host: &mut impl Host,
        tracer: &mut T,
    ) -> Result<ExecutionOutput, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let mut continuation_stack = Self::source_aware_continuation_stack(
            program,
            package_debug_info,
            entrypoint_source_node_id,
        )?;
        let mut current_forest = program.mast_forest().clone();
        let mut package_debug_info = Some(Arc::new(package_debug_info.clone()));

        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;
        let flow = self
            .execute_impl_async(
                &mut continuation_stack,
                &mut current_forest,
                program.kernel(),
                host,
                tracer,
                &NeverStopper,
                &mut package_debug_info,
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
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();
        let mut package_debug_info = None;

        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;
        let flow = self.execute_impl(
            &mut continuation_stack,
            &mut current_forest,
            program.kernel(),
            host,
            tracer,
            &NeverStopper,
            &mut package_debug_info,
        );
        Self::execution_result_from_flow(flow, self)
    }

    /// Executes the given program with package-owned source/debug context and the provided tracer
    /// using a sync host.
    fn execute_with_package_debug_info_and_tracer_sync<T>(
        mut self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: Option<DebugSourceNodeId>,
        host: &mut impl SyncHost,
        tracer: &mut T,
    ) -> Result<ExecutionOutput, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let mut continuation_stack = Self::source_aware_continuation_stack(
            program,
            package_debug_info,
            entrypoint_source_node_id,
        )?;
        let mut current_forest = program.mast_forest().clone();
        let mut package_debug_info = Some(Arc::new(package_debug_info.clone()));

        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;
        let flow = self.execute_impl(
            &mut continuation_stack,
            &mut current_forest,
            program.kernel(),
            host,
            tracer,
            &NeverStopper,
            &mut package_debug_info,
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
            mut package_debug_info,
        } = resume_ctx;

        let flow = self.execute_impl(
            &mut continuation_stack,
            &mut current_forest,
            &kernel,
            host,
            &mut NoopTracer,
            &StepStopper,
            &mut package_debug_info,
        );
        Self::resume_context_from_flow(
            flow,
            continuation_stack,
            current_forest,
            kernel,
            package_debug_info,
        )
    }

    /// Executes a single clock cycle synchronously with package-owned source/debug context.
    #[cfg(any(test, feature = "testing"))]
    pub fn step_with_package_debug_info_sync(
        &mut self,
        host: &mut impl SyncHost,
        resume_ctx: ResumeContext,
        package_debug_info: &PackageDebugInfo,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        let ResumeContext {
            mut current_forest,
            mut continuation_stack,
            kernel,
            package_debug_info: mut active_package_debug_info,
        } = resume_ctx;
        Self::ensure_source_aware_step_context(
            &mut continuation_stack,
            &mut active_package_debug_info,
            package_debug_info,
        )?;

        let flow = self.execute_impl(
            &mut continuation_stack,
            &mut current_forest,
            &kernel,
            host,
            &mut NoopTracer,
            &StepStopper,
            &mut active_package_debug_info,
        );
        Self::resume_context_from_flow(
            flow,
            continuation_stack,
            current_forest,
            kernel,
            active_package_debug_info,
        )
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
            mut package_debug_info,
        } = resume_ctx;

        let flow = self
            .execute_impl_async(
                &mut continuation_stack,
                &mut current_forest,
                &kernel,
                host,
                &mut NoopTracer,
                &StepStopper,
                &mut package_debug_info,
            )
            .await;
        Self::resume_context_from_flow(
            flow,
            continuation_stack,
            current_forest,
            kernel,
            package_debug_info,
        )
    }

    /// Async variant of [`Self::step_with_package_debug_info_sync`].
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    pub async fn step_with_package_debug_info(
        &mut self,
        host: &mut impl Host,
        resume_ctx: ResumeContext,
        package_debug_info: &PackageDebugInfo,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        let ResumeContext {
            mut current_forest,
            mut continuation_stack,
            kernel,
            package_debug_info: mut active_package_debug_info,
        } = resume_ctx;
        Self::ensure_source_aware_step_context(
            &mut continuation_stack,
            &mut active_package_debug_info,
            package_debug_info,
        )?;

        let flow = self
            .execute_impl_async(
                &mut continuation_stack,
                &mut current_forest,
                &kernel,
                host,
                &mut NoopTracer,
                &StepStopper,
                &mut active_package_debug_info,
            )
            .await;
        Self::resume_context_from_flow(
            flow,
            continuation_stack,
            current_forest,
            kernel,
            active_package_debug_info,
        )
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

    fn source_aware_continuation_stack(
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: Option<DebugSourceNodeId>,
    ) -> Result<ContinuationStack<Arc<MastForest>>, ExecutionError> {
        if let Some(source_node_id) = entrypoint_source_node_id {
            let Some(source_node) = package_debug_info.source_node(source_node_id) else {
                return Err(ExecutionError::Internal(
                    "package debug source graph is missing the entrypoint source node",
                ));
            };
            if source_node.exec_node != program.entrypoint() {
                return Err(ExecutionError::Internal(
                    "package debug entrypoint source node does not match the program entrypoint",
                ));
            }

            return Ok(ContinuationStack::new_with_source_node_id(program, source_node_id));
        }

        let Some(source_node_id) = package_debug_info
            .unique_source_root_for_exec_node(program.entrypoint())
            .map_err(|_| {
                ExecutionError::Internal(
                    "package debug source graph has ambiguous or malformed entrypoint roots",
                )
            })?
        else {
            return Ok(ContinuationStack::new_with_optional_source_node_id(program, None));
        };

        Ok(ContinuationStack::new_with_source_node_id(program, source_node_id))
    }

    #[cfg(any(test, feature = "testing"))]
    fn source_aware_resume_context(
        &mut self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: Option<DebugSourceNodeId>,
    ) -> Result<ResumeContext, ExecutionError> {
        self.advice
            .extend_map(program.mast_forest().advice_map())
            .map_exec_err_no_ctx()?;

        Ok(ResumeContext {
            current_forest: program.mast_forest().clone(),
            continuation_stack: Self::source_aware_continuation_stack(
                program,
                package_debug_info,
                entrypoint_source_node_id,
            )?,
            kernel: program.kernel().clone(),
            package_debug_info: Some(Arc::new(package_debug_info.clone())),
        })
    }

    #[cfg(any(test, feature = "testing"))]
    fn ensure_source_aware_step_context(
        continuation_stack: &mut ContinuationStack<Arc<MastForest>>,
        package_debug_info: &mut Option<Arc<PackageDebugInfo>>,
        supplied_package_debug_info: &PackageDebugInfo,
    ) -> Result<(), ExecutionError> {
        if package_debug_info.is_none() {
            *package_debug_info = Some(Arc::new(supplied_package_debug_info.clone()));
        }

        if !continuation_stack.tracks_source_nodes() {
            let source_node_id = Self::source_root_for_next_continuation(
                continuation_stack,
                package_debug_info.as_deref().expect("package debug info was just initialized"),
            )?;
            continuation_stack.start_tracking_source_nodes(source_node_id);
        }

        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    fn source_root_for_next_continuation(
        continuation_stack: &ContinuationStack<Arc<MastForest>>,
        package_debug_info: &PackageDebugInfo,
    ) -> Result<Option<DebugSourceNodeId>, ExecutionError> {
        let Some((continuation, _)) = continuation_stack.peek_continuation_with_source_node_id()
        else {
            return Ok(None);
        };

        let Some(exec_node) = continuation.exec_node() else {
            return Ok(None);
        };

        package_debug_info.unique_source_root_for_exec_node(exec_node).map_err(|_| {
            ExecutionError::Internal(
                "package debug source graph has ambiguous or malformed continuation roots",
            )
        })
    }

    /// Converts a step-wise execution result into the next resume context, if execution stopped.
    #[inline(always)]
    fn resume_context_from_flow(
        flow: ControlFlow<BreakReason<Arc<MastForest>>, StackOutputs>,
        mut continuation_stack: ContinuationStack<Arc<MastForest>>,
        current_forest: Arc<MastForest>,
        kernel: Kernel,
        package_debug_info: Option<Arc<PackageDebugInfo>>,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        match flow {
            ControlFlow::Continue(_) => Ok(None),
            ControlFlow::Break(break_reason) => match break_reason {
                BreakReason::Err(err) => Err(err),
                BreakReason::Stopped(maybe_continuation) => {
                    if let Some((continuation, source_node_id)) = maybe_continuation {
                        continuation_stack.push_with_source_node_id(continuation, source_node_id);
                    }

                    Ok(Some(ResumeContext {
                        current_forest,
                        continuation_stack,
                        kernel,
                        package_debug_info,
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
        continuation_stack: &mut ContinuationStack<Arc<MastForest>>,
        current_forest: &mut Arc<MastForest>,
        kernel: &Kernel,
        host: &mut impl SyncHost,
        tracer: &mut T,
        stopper: &S,
        package_debug_info: &mut Option<Arc<PackageDebugInfo>>,
    ) -> ControlFlow<BreakReason<Arc<MastForest>>, StackOutputs>
    where
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        while let ControlFlow::Break(internal_break_reason) = execute_impl(
            self,
            continuation_stack,
            current_forest,
            kernel,
            host,
            tracer,
            stopper,
            package_debug_info,
        ) {
            let current_package_debug_info = package_debug_info.as_deref();
            let source_aware_execution =
                current_package_debug_info.is_some() || continuation_stack.tracks_source_nodes();
            match internal_break_reason {
                InternalBreakReason::User(break_reason) => return ControlFlow::Break(break_reason),
                InternalBreakReason::Emit { op_idx, continuation, source_node_id } => {
                    self.op_emit_sync(host, op_idx, current_package_debug_info, source_node_id)?;

                    finish_emit_op_execution(
                        continuation,
                        source_node_id,
                        self,
                        continuation_stack,
                        current_forest,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromDyn { callee_hash, source_node_id } => {
                    let (root_id, new_forest, new_package_debug_info, new_source_node_id) =
                        match self.load_mast_forest_sync(
                            callee_hash,
                            host,
                            current_package_debug_info,
                            source_node_id,
                            source_aware_execution,
                        ) {
                            Ok(result) => result,
                            Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
                        };

                    finish_load_mast_forest_from_dyn_start(
                        root_id,
                        new_forest,
                        new_package_debug_info,
                        new_source_node_id,
                        self,
                        current_forest,
                        package_debug_info,
                        continuation_stack,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromExternal {
                    external_node_id,
                    procedure_hash,
                    source_node_id,
                } => {
                    let (root_id, new_forest, new_package_debug_info, new_source_node_id) =
                        match self.load_mast_forest_sync(
                            procedure_hash,
                            host,
                            current_package_debug_info,
                            source_node_id,
                            source_aware_execution,
                        ) {
                            Ok(result) => result,
                            Err(err) => {
                                let maybe_enriched_err = maybe_use_caller_error_context(
                                    err,
                                    continuation_stack,
                                    current_package_debug_info,
                                    host,
                                );
                                return ControlFlow::Break(BreakReason::Err(maybe_enriched_err));
                            },
                        };

                    finish_load_mast_forest_from_external(
                        root_id,
                        new_forest,
                        new_package_debug_info,
                        new_source_node_id,
                        external_node_id,
                        current_forest,
                        package_debug_info,
                        continuation_stack,
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
        continuation_stack: &mut ContinuationStack<Arc<MastForest>>,
        current_forest: &mut Arc<MastForest>,
        kernel: &Kernel,
        host: &mut impl Host,
        tracer: &mut T,
        stopper: &S,
        package_debug_info: &mut Option<Arc<PackageDebugInfo>>,
    ) -> ControlFlow<BreakReason<Arc<MastForest>>, StackOutputs>
    where
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        while let ControlFlow::Break(internal_break_reason) = execute_impl(
            self,
            continuation_stack,
            current_forest,
            kernel,
            host,
            tracer,
            stopper,
            package_debug_info,
        ) {
            let current_package_debug_info = package_debug_info.as_deref();
            let source_aware_execution =
                current_package_debug_info.is_some() || continuation_stack.tracks_source_nodes();
            match internal_break_reason {
                InternalBreakReason::User(break_reason) => return ControlFlow::Break(break_reason),
                InternalBreakReason::Emit { op_idx, continuation, source_node_id } => {
                    self.op_emit(host, op_idx, current_package_debug_info, source_node_id).await?;

                    finish_emit_op_execution(
                        continuation,
                        source_node_id,
                        self,
                        continuation_stack,
                        current_forest,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromDyn { callee_hash, source_node_id } => {
                    let (root_id, new_forest, new_package_debug_info, new_source_node_id) =
                        match self
                            .load_mast_forest(
                                callee_hash,
                                host,
                                current_package_debug_info,
                                source_node_id,
                                source_aware_execution,
                            )
                            .await
                        {
                            Ok(result) => result,
                            Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
                        };

                    finish_load_mast_forest_from_dyn_start(
                        root_id,
                        new_forest,
                        new_package_debug_info,
                        new_source_node_id,
                        self,
                        current_forest,
                        package_debug_info,
                        continuation_stack,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromExternal {
                    external_node_id,
                    procedure_hash,
                    source_node_id,
                } => {
                    let (root_id, new_forest, new_package_debug_info, new_source_node_id) =
                        match self
                            .load_mast_forest(
                                procedure_hash,
                                host,
                                current_package_debug_info,
                                source_node_id,
                                source_aware_execution,
                            )
                            .await
                        {
                            Ok(result) => result,
                            Err(err) => {
                                let maybe_enriched_err = maybe_use_caller_error_context(
                                    err,
                                    continuation_stack,
                                    current_package_debug_info,
                                    host,
                                );
                                return ControlFlow::Break(BreakReason::Err(maybe_enriched_err));
                            },
                        };

                    finish_load_mast_forest_from_external(
                        root_id,
                        new_forest,
                        new_package_debug_info,
                        new_source_node_id,
                        external_node_id,
                        current_forest,
                        package_debug_info,
                        continuation_stack,
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
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
        source_aware_execution: bool,
    ) -> Result<
        (
            MastNodeId,
            Arc<MastForest>,
            Option<Arc<PackageDebugInfo>>,
            Option<DebugSourceNodeId>,
        ),
        ExecutionError,
    > {
        let loaded_mast_forest = host.get_mast_forest(&node_digest).ok_or_else(|| {
            match (package_debug_info, source_node_id) {
                (Some(debug_info), Some(source_node_id)) => {
                    crate::errors::procedure_not_found_with_package_source_context(
                        node_digest,
                        PackageSourceDebugContext::new(debug_info, source_node_id),
                        host,
                    )
                },
                _ => crate::errors::procedure_not_found_with_context(node_digest),
            }
        })?;
        let mast_forest = loaded_mast_forest.mast_forest().clone();

        let root_id = mast_forest.find_procedure_root(node_digest).ok_or_else(|| {
            let context = match (package_debug_info, source_node_id) {
                (Some(debug_info), Some(source_node_id)) => {
                    Some(PackageSourceDebugContext::new(debug_info, source_node_id))
                },
                _ => None,
            };
            malformed_mast_forest_with_context(node_digest, context, host)
        })?;

        self.advice.extend_map(mast_forest.advice_map()).map_exec_err()?;
        let (loaded_package_debug_info, loaded_source_node_id) =
            Self::loaded_package_source_context(
                &loaded_mast_forest,
                root_id,
                source_aware_execution,
            )?;

        Ok((root_id, mast_forest, loaded_package_debug_info, loaded_source_node_id))
    }

    async fn load_mast_forest(
        &mut self,
        node_digest: Word,
        host: &mut impl Host,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
        source_aware_execution: bool,
    ) -> Result<
        (
            MastNodeId,
            Arc<MastForest>,
            Option<Arc<PackageDebugInfo>>,
            Option<DebugSourceNodeId>,
        ),
        ExecutionError,
    > {
        let loaded_mast_forest = if let Some(mast_forest) = host.get_mast_forest(&node_digest).await
        {
            mast_forest
        } else {
            return Err(match (package_debug_info, source_node_id) {
                (Some(debug_info), Some(source_node_id)) => {
                    crate::errors::procedure_not_found_with_package_source_context(
                        node_digest,
                        PackageSourceDebugContext::new(debug_info, source_node_id),
                        host,
                    )
                },
                _ => crate::errors::procedure_not_found_with_context(node_digest),
            });
        };
        let mast_forest = loaded_mast_forest.mast_forest().clone();

        let root_id = mast_forest.find_procedure_root(node_digest).ok_or_else(|| {
            let context = match (package_debug_info, source_node_id) {
                (Some(debug_info), Some(source_node_id)) => {
                    Some(PackageSourceDebugContext::new(debug_info, source_node_id))
                },
                _ => None,
            };
            malformed_mast_forest_with_context(node_digest, context, host)
        })?;

        self.advice.extend_map(mast_forest.advice_map()).map_exec_err()?;
        let (loaded_package_debug_info, loaded_source_node_id) =
            Self::loaded_package_source_context(
                &loaded_mast_forest,
                root_id,
                source_aware_execution,
            )?;

        Ok((root_id, mast_forest, loaded_package_debug_info, loaded_source_node_id))
    }

    fn loaded_package_source_context(
        loaded_mast_forest: &LoadedMastForest,
        root_id: MastNodeId,
        source_aware_execution: bool,
    ) -> Result<(Option<Arc<PackageDebugInfo>>, Option<DebugSourceNodeId>), ExecutionError> {
        if !source_aware_execution {
            return Ok((None, None));
        }

        let Some(package_debug_info) = loaded_mast_forest
            .package_debug_info()
            .map_err(|_| ExecutionError::Internal("loaded package debug info is malformed"))?
        else {
            return Ok((None, None));
        };

        let source_node_id = match package_debug_info.unique_source_root_for_exec_node(root_id) {
            Ok(source_node_id) => source_node_id,
            Err(DebugSourceGraphLookupError::AmbiguousRoot { .. }) => None,
            Err(_) => {
                return Err(ExecutionError::Internal(
                    "loaded package debug source graph has malformed entrypoint roots",
                ));
            },
        };

        Ok((Some(package_debug_info), source_node_id))
    }

    /// Executes the given program synchronously one step at a time.
    pub fn execute_by_step_sync(
        mut self,
        program: &Program,
        host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut current_resume_ctx = self.get_initial_resume_context(program)?;

        loop {
            match self.step_sync(host, current_resume_ctx)? {
                Some(next_resume_ctx) => {
                    current_resume_ctx = next_resume_ctx;
                },
                None => break Ok(self.current_stack_outputs()),
            }
        }
    }

    /// Executes the given program synchronously one step at a time with package-owned source/debug
    /// context.
    #[cfg(any(test, feature = "testing"))]
    pub fn execute_by_step_with_package_debug_info_sync(
        mut self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut current_resume_ctx =
            self.source_aware_resume_context(program, package_debug_info, None)?;

        loop {
            match self.step_with_package_debug_info_sync(
                host,
                current_resume_ctx,
                package_debug_info,
            )? {
                Some(next_resume_ctx) => {
                    current_resume_ctx = next_resume_ctx;
                },
                None => break Ok(self.current_stack_outputs()),
            }
        }
    }

    /// Executes the given program synchronously one step at a time with package-owned source/debug
    /// context rooted at `entrypoint_source_node_id`.
    #[cfg(any(test, feature = "testing"))]
    pub fn execute_by_step_with_package_debug_info_at_source_node_sync(
        mut self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut current_resume_ctx = self.source_aware_resume_context(
            program,
            package_debug_info,
            Some(entrypoint_source_node_id),
        )?;

        loop {
            match self.step_with_package_debug_info_sync(
                host,
                current_resume_ctx,
                package_debug_info,
            )? {
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
        let mut current_resume_ctx = self.get_initial_resume_context(program)?;
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

    /// Async variant of [`Self::execute_by_step_with_package_debug_info_sync`].
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    pub async fn execute_by_step_with_package_debug_info(
        mut self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl Host,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut current_resume_ctx =
            self.source_aware_resume_context(program, package_debug_info, None)?;
        let mut processor = self;

        loop {
            match processor
                .step_with_package_debug_info(host, current_resume_ctx, package_debug_info)
                .await?
            {
                Some(next_resume_ctx) => {
                    current_resume_ctx = next_resume_ctx;
                },
                None => break Ok(processor.current_stack_outputs()),
            }
        }
    }

    /// Async variant of
    /// [`Self::execute_by_step_with_package_debug_info_at_source_node_sync`].
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    pub async fn execute_by_step_with_package_debug_info_at_source_node(
        mut self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl Host,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut current_resume_ctx = self.source_aware_resume_context(
            program,
            package_debug_info,
            Some(entrypoint_source_node_id),
        )?;
        let mut processor = self;

        loop {
            match processor
                .step_with_package_debug_info(host, current_resume_ctx, package_debug_info)
                .await?
            {
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
        let mut package_debug_info = None;

        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;

        let flow = self.execute_impl(
            &mut continuation_stack,
            &mut current_forest,
            program.kernel(),
            host,
            &mut NoopTracer,
            &NeverStopper,
            &mut package_debug_info,
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
        let mut package_debug_info = None;

        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;

        let flow = self
            .execute_impl_async(
                &mut continuation_stack,
                &mut current_forest,
                program.kernel(),
                host,
                &mut NoopTracer,
                &NeverStopper,
                &mut package_debug_info,
            )
            .await;
        Self::stack_result_from_flow(flow)
    }
}
