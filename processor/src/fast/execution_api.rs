use alloc::{sync::Arc, vec::Vec};
use core::ops::ControlFlow;

use miden_core::{
    Word, ZERO,
    mast::{MastForest, MastNodeId},
    program::{MIN_STACK_DEPTH, Program, StackInputs, StackOutputs},
};
use miden_mast_package::debug_info::{
    DebugSourceGraphLookupError, DebugSourceNodeId, PackageDebugInfo,
};

use super::{
    FastProcessor, NoopTracer,
    external::load_error_with_context,
    step::{BreakReason, NeverStopper, ResumeContext, ResumeOutcome, StepStopper},
};
use crate::{
    ExecutionError, ExecutionOutput, Host, LoadedMastForest, ProcessorError, SourceContextError,
    Stopper, SyncHost,
    advice::AdviceError,
    continuation_stack::{Continuation, ContinuationStack, SourceInlineCallContext},
    errors::{OperationError, PackageSourceDebugContext},
    execution::{
        InternalBreakReason, ResolvedMastForest, execute_impl, finish_emit_op_execution,
        finish_load_mast_forest_from_dyn_start, finish_load_mast_forest_from_external,
    },
    trace::execution_tracer::ExecutionTracer,
    tracer::Tracer,
};

impl FastProcessor {
    pub(crate) fn new_tracer(&self) -> ExecutionTracer {
        ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
        )
    }

    pub(crate) fn start_context(
        &mut self,
        program: &Program,
        source_context: Option<PackageSourceDebugContext<'_>>,
    ) -> Result<ResumeContext, ExecutionError> {
        let continuation_stack = source_context
            .map(|context| {
                Self::source_aware_continuation_stack(
                    program,
                    context.debug_info(),
                    context.source_node_id(),
                )
            })
            .transpose()?;
        self.advice.extend_map(program.mast_forest().advice_map())?;
        Ok(ResumeContext {
            current_forest: program.mast_forest().clone(),
            continuation_stack: continuation_stack
                .unwrap_or_else(|| ContinuationStack::new(program)),
            kernel: program.kernel().clone(),
            package_debug_info: source_context
                .map(|context| Arc::new(context.debug_info().clone())),
            inline_call_contexts: Vec::new(),
        })
    }

    #[tracing::instrument(
        target = "miden::vm::execute",
        level = "trace",
        name = "execute_program",
        skip_all
    )]
    pub(crate) fn run_with_tracer_sync<T>(
        mut self,
        program: &Program,
        source_context: Option<PackageSourceDebugContext<'_>>,
        host: &mut impl SyncHost,
        tracer: &mut T,
    ) -> Result<ExecutionOutput, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let mut context = self.start_context(program, source_context)?;
        let flow = self.execute_impl(&mut context, host, tracer, &NeverStopper);
        Self::execution_result_from_flow(flow, self)
    }

    #[tracing::instrument(
        target = "miden::vm::execute",
        level = "trace",
        name = "execute_program",
        skip_all
    )]
    pub(crate) async fn run_with_tracer<T>(
        mut self,
        program: &Program,
        source_context: Option<PackageSourceDebugContext<'_>>,
        host: &mut impl Host,
        tracer: &mut T,
    ) -> Result<ExecutionOutput, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let mut context = self.start_context(program, source_context)?;
        let flow = self.execute_impl_async(&mut context, host, tracer, &NeverStopper).await;
        Self::execution_result_from_flow(flow, self)
    }

    pub(crate) fn step_with_tracer_sync<T>(
        &mut self,
        host: &mut impl SyncHost,
        context: ResumeContext,
        tracer: &mut T,
    ) -> Result<ResumeOutcome, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        self.drive_sync(host, context, tracer, &StepStopper)
    }

    pub(crate) async fn step_with_tracer<T>(
        &mut self,
        host: &mut impl Host,
        context: ResumeContext,
        tracer: &mut T,
    ) -> Result<ResumeOutcome, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        self.drive(host, context, tracer, &StepStopper).await
    }

    pub(crate) fn drive_to_halt_sync<T>(
        &mut self,
        host: &mut impl SyncHost,
        context: ResumeContext,
        tracer: &mut T,
    ) -> Result<ResumeOutcome, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        self.drive_sync(host, context, tracer, &NeverStopper)
    }

    pub(crate) async fn drive_to_halt<T>(
        &mut self,
        host: &mut impl Host,
        context: ResumeContext,
        tracer: &mut T,
    ) -> Result<ResumeOutcome, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        self.drive(host, context, tracer, &NeverStopper).await
    }

    fn drive_sync<S, T>(
        &mut self,
        host: &mut impl SyncHost,
        mut context: ResumeContext,
        tracer: &mut T,
        stopper: &S,
    ) -> Result<ResumeOutcome, ExecutionError>
    where
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let flow = self.execute_impl(&mut context, host, tracer, stopper);
        Self::resume_outcome_from_flow(flow, context)
    }

    async fn drive<S, T>(
        &mut self,
        host: &mut impl Host,
        mut context: ResumeContext,
        tracer: &mut T,
        stopper: &S,
    ) -> Result<ResumeOutcome, ExecutionError>
    where
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let flow = self.execute_impl_async(&mut context, host, tracer, stopper).await;
        Self::resume_outcome_from_flow(flow, context)
    }

    /// Executes a single clock cycle synchronously.
    pub fn step_sync(
        &mut self,
        host: &mut impl SyncHost,
        resume_ctx: ResumeContext,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        self.step_with_tracer_sync(host, resume_ctx, &mut NoopTracer)
            .map(ResumeOutcome::into_resume_context)
    }

    /// Executes a single clock cycle synchronously with package-owned source/debug context.
    pub fn step_with_package_debug_info_sync(
        &mut self,
        host: &mut impl SyncHost,
        mut resume_ctx: ResumeContext,
        package_debug_info: &PackageDebugInfo,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        Self::ensure_source_aware_step_context(
            &mut resume_ctx.continuation_stack,
            &mut resume_ctx.package_debug_info,
            package_debug_info,
        )?;
        self.step_sync(host, resume_ctx)
    }

    /// Async variant of [`Self::step_sync`].
    #[inline(always)]
    pub async fn step(
        &mut self,
        host: &mut impl Host,
        resume_ctx: ResumeContext,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        self.step_with_tracer(host, resume_ctx, &mut NoopTracer)
            .await
            .map(ResumeOutcome::into_resume_context)
    }

    /// Async variant of [`Self::step_with_package_debug_info_sync`].
    #[inline(always)]
    pub async fn step_with_package_debug_info(
        &mut self,
        host: &mut impl Host,
        mut resume_ctx: ResumeContext,
        package_debug_info: &PackageDebugInfo,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        Self::ensure_source_aware_step_context(
            &mut resume_ctx.continuation_stack,
            &mut resume_ctx.package_debug_info,
            package_debug_info,
        )?;
        self.step(host, resume_ctx).await
    }

    /// Returns the current top 16 stack elements in public input order.
    #[inline(always)]
    pub(crate) fn initial_stack_inputs(&self) -> StackInputs {
        core::array::from_fn(|idx| self.stack_get(idx)).into()
    }

    pub(super) fn source_aware_continuation_stack(
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: Option<DebugSourceNodeId>,
    ) -> Result<ContinuationStack<Arc<MastForest>>, SourceContextError> {
        let entrypoint = program.entrypoint();
        if let Some(source_node_id) = entrypoint_source_node_id {
            let source_node = package_debug_info.source_node(source_node_id).ok_or(
                DebugSourceGraphLookupError::MissingSourceNode { source_node: source_node_id },
            )?;
            if source_node.exec_node != entrypoint {
                return Err(SourceContextError::EntrypointMismatch {
                    source_node: source_node_id,
                    expected: entrypoint,
                    actual: source_node.exec_node,
                });
            }

            return Ok(ContinuationStack::new_with_source_node_id(program, source_node_id));
        }

        let source_node_id = package_debug_info.unique_source_root_for_exec_node(entrypoint)?;
        Ok(ContinuationStack::new_with_optional_source_node_id(program, source_node_id))
    }

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

    fn source_root_for_next_continuation(
        continuation_stack: &ContinuationStack<Arc<MastForest>>,
        package_debug_info: &PackageDebugInfo,
    ) -> Result<Option<DebugSourceNodeId>, SourceContextError> {
        let Some((continuation, _)) = continuation_stack.peek_continuation_with_source_node_id()
        else {
            return Ok(None);
        };

        let Some(exec_node) = continuation.exec_node() else {
            return Ok(None);
        };

        Ok(package_debug_info.unique_source_root_for_exec_node(exec_node)?)
    }

    /// Carries the terminal outputs or normalizes the continuation for the next step.
    #[inline(always)]
    fn resume_outcome_from_flow(
        flow: ControlFlow<BreakReason<Arc<MastForest>>, StackOutputs>,
        mut context: ResumeContext,
    ) -> Result<ResumeOutcome, ExecutionError> {
        match flow {
            ControlFlow::Continue(stack) => {
                Ok(ResumeOutcome::Halted { stack, kernel: context.kernel })
            },
            ControlFlow::Break(BreakReason::Err(err)) => Err(err),
            ControlFlow::Break(BreakReason::Stopped(maybe_continuation)) => {
                let continuation_stack = &mut context.continuation_stack;
                if let Some((continuation, source_node_id)) = maybe_continuation {
                    continuation_stack
                        .push_resumed_with_source_node_id(continuation, source_node_id);
                }

                while matches!(
                    continuation_stack.peek_continuation(),
                    Some(Continuation::EnterForest { .. })
                ) {
                    let Some((
                        Continuation::EnterForest {
                            forest,
                            package_debug_info,
                            inline_context_depth,
                        },
                        _,
                    )) = continuation_stack.pop_continuation_with_source_node_id()
                    else {
                        unreachable!("peeked continuation must still be EnterForest")
                    };
                    context.current_forest = forest;
                    context.package_debug_info = package_debug_info;
                    context.inline_call_contexts.truncate(inline_context_depth);
                }

                Ok(ResumeOutcome::Suspended(context))
            },
        }
    }

    /// Validates the terminal stack and copies its contents in public output order.
    #[inline(always)]
    fn final_stack_outputs(&self) -> ControlFlow<BreakReason<Arc<MastForest>>, StackOutputs> {
        let stack = self.stack();
        if stack.len() > MIN_STACK_DEPTH {
            return ControlFlow::Break(BreakReason::Err(
                ProcessorError::OutputStackOverflow(stack.len() - MIN_STACK_DEPTH).into(),
            ));
        }

        let mut outputs = [ZERO; MIN_STACK_DEPTH];
        for (output, &value) in outputs.iter_mut().zip(stack.iter().rev()) {
            *output = value;
        }
        ControlFlow::Continue(outputs.into())
    }

    /// Drives the context until termination, an execution error, or a stop requested by `stopper`.
    fn execute_impl<S, T>(
        &mut self,
        context: &mut ResumeContext,
        host: &mut impl SyncHost,
        tracer: &mut T,
        stopper: &S,
    ) -> ControlFlow<BreakReason<Arc<MastForest>>, StackOutputs>
    where
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let ResumeContext {
            current_forest,
            continuation_stack,
            kernel,
            package_debug_info,
            inline_call_contexts,
        } = context;
        while let ControlFlow::Break(internal_break_reason) = execute_impl(
            self,
            continuation_stack,
            current_forest,
            kernel,
            host,
            tracer,
            stopper,
            package_debug_info,
            inline_call_contexts,
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
                    let resolved =
                        match self.load_mast_forest_sync(callee_hash, host, source_aware_execution)
                        {
                            Ok(result) => result,
                            Err(err) => {
                                return ControlFlow::Break(BreakReason::Err(err.with_context(
                                    current_package_debug_info.map(|debug_info| {
                                        PackageSourceDebugContext::new_optional(
                                            debug_info,
                                            source_node_id,
                                        )
                                    }),
                                    host,
                                    None,
                                )));
                            },
                        };

                    finish_load_mast_forest_from_dyn_start(
                        resolved,
                        self,
                        current_forest,
                        package_debug_info,
                        inline_call_contexts.as_slice(),
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
                    let inline_call_context = package_debug_info.clone().and_then(|debug_info| {
                        SourceInlineCallContext::for_source_boundary(debug_info, source_node_id)
                    });
                    let resolved = match self.load_mast_forest_sync(
                        procedure_hash,
                        host,
                        source_aware_execution,
                    ) {
                        Ok(result) => result,
                        Err(err) => {
                            let err = load_error_with_context(
                                err,
                                source_node_id,
                                continuation_stack,
                                current_package_debug_info,
                                host,
                            );
                            return ControlFlow::Break(BreakReason::Err(err));
                        },
                    };

                    finish_load_mast_forest_from_external(
                        resolved,
                        inline_call_context,
                        (external_node_id, source_node_id),
                        current_forest,
                        package_debug_info,
                        inline_call_contexts,
                        continuation_stack,
                        tracer,
                        host,
                    )?;
                },
            }
        }

        self.final_stack_outputs()
    }

    async fn execute_impl_async<S, T>(
        &mut self,
        context: &mut ResumeContext,
        host: &mut impl Host,
        tracer: &mut T,
        stopper: &S,
    ) -> ControlFlow<BreakReason<Arc<MastForest>>, StackOutputs>
    where
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let ResumeContext {
            current_forest,
            continuation_stack,
            kernel,
            package_debug_info,
            inline_call_contexts,
        } = context;
        while let ControlFlow::Break(internal_break_reason) = execute_impl(
            self,
            continuation_stack,
            current_forest,
            kernel,
            host,
            tracer,
            stopper,
            package_debug_info,
            inline_call_contexts,
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
                    let resolved = match self
                        .load_mast_forest(callee_hash, host, source_aware_execution)
                        .await
                    {
                        Ok(result) => result,
                        Err(err) => {
                            return ControlFlow::Break(BreakReason::Err(err.with_context(
                                current_package_debug_info.map(|debug_info| {
                                    PackageSourceDebugContext::new_optional(
                                        debug_info,
                                        source_node_id,
                                    )
                                }),
                                host,
                                None,
                            )));
                        },
                    };

                    finish_load_mast_forest_from_dyn_start(
                        resolved,
                        self,
                        current_forest,
                        package_debug_info,
                        inline_call_contexts.as_slice(),
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
                    let inline_call_context = package_debug_info.clone().and_then(|debug_info| {
                        SourceInlineCallContext::for_source_boundary(debug_info, source_node_id)
                    });
                    let resolved = match self
                        .load_mast_forest(procedure_hash, host, source_aware_execution)
                        .await
                    {
                        Ok(result) => result,
                        Err(err) => {
                            let err = load_error_with_context(
                                err,
                                source_node_id,
                                continuation_stack,
                                current_package_debug_info,
                                host,
                            );
                            return ControlFlow::Break(BreakReason::Err(err));
                        },
                    };

                    finish_load_mast_forest_from_external(
                        resolved,
                        inline_call_context,
                        (external_node_id, source_node_id),
                        current_forest,
                        package_debug_info,
                        inline_call_contexts,
                        continuation_stack,
                        tracer,
                        host,
                    )?;
                },
            }
        }

        self.final_stack_outputs()
    }

    // HELPERS
    // ------------------------------------------------------------------------------------------

    fn load_mast_forest_sync(
        &mut self,
        node_digest: Word,
        host: &mut impl SyncHost,
        source_aware_execution: bool,
    ) -> Result<ResolvedMastForest<Arc<MastForest>>, ProcessorError> {
        let cached = self.loaded_mast_forests.get(&node_digest).cloned();
        let was_cached = cached.is_some();
        let loaded_mast_forest = match cached {
            Some(mast_forest) => mast_forest,
            None => host
                .get_mast_forest(&node_digest)
                .map_err(|source| ProcessorError::MastForestLoad {
                    root_digest: node_digest,
                    source,
                })?
                .ok_or(ProcessorError::ProcedureNotFound { root_digest: node_digest })?,
        };
        self.finish_loading_mast_forest(
            loaded_mast_forest,
            node_digest,
            was_cached,
            source_aware_execution,
        )
    }

    async fn load_mast_forest(
        &mut self,
        node_digest: Word,
        host: &mut impl Host,
        source_aware_execution: bool,
    ) -> Result<ResolvedMastForest<Arc<MastForest>>, ProcessorError> {
        let cached = self.loaded_mast_forests.get(&node_digest).cloned();
        let was_cached = cached.is_some();
        let loaded_mast_forest = match cached {
            Some(mast_forest) => mast_forest,
            None => host
                .get_mast_forest(&node_digest)
                .await
                .map_err(|source| ProcessorError::MastForestLoad {
                    root_digest: node_digest,
                    source,
                })?
                .ok_or(ProcessorError::ProcedureNotFound { root_digest: node_digest })?,
        };
        self.finish_loading_mast_forest(
            loaded_mast_forest,
            node_digest,
            was_cached,
            source_aware_execution,
        )
    }

    fn finish_loading_mast_forest(
        &mut self,
        loaded_mast_forest: LoadedMastForest,
        node_digest: Word,
        was_cached: bool,
        source_aware_execution: bool,
    ) -> Result<ResolvedMastForest<Arc<MastForest>>, ProcessorError> {
        let mast_forest = loaded_mast_forest.mast_forest().clone();
        let root_id = mast_forest
            .find_procedure_root(node_digest)
            .ok_or(OperationError::MalformedMastForestInHost { root_digest: node_digest })?;
        if !was_cached {
            self.cache_loaded_mast_forest(&loaded_mast_forest);
        }
        self.merge_mast_forest_advice(&mast_forest)?;
        let (loaded_package_debug_info, loaded_source_node_id) =
            Self::loaded_package_source_context(
                &loaded_mast_forest,
                root_id,
                source_aware_execution,
            )?;
        Ok(ResolvedMastForest {
            root_id,
            forest: mast_forest,
            package_debug_info: loaded_package_debug_info,
            source_node_id: loaded_source_node_id,
        })
    }

    fn cache_loaded_mast_forest(&mut self, loaded_mast_forest: &LoadedMastForest) {
        for procedure_digest in loaded_mast_forest.mast_forest().local_procedure_digests() {
            self.loaded_mast_forests
                .entry(procedure_digest)
                .or_insert_with(|| loaded_mast_forest.clone());
        }
    }

    fn merge_mast_forest_advice(&mut self, mast_forest: &MastForest) -> Result<(), AdviceError> {
        let commitment = mast_forest.commitment();
        if self.merged_mast_forests.contains(&commitment) {
            return Ok(());
        }

        self.advice.extend_map(mast_forest.advice_map())?;
        self.merged_mast_forests.insert(commitment);
        Ok(())
    }

    fn loaded_package_source_context(
        loaded_mast_forest: &LoadedMastForest,
        root_id: MastNodeId,
        source_aware_execution: bool,
    ) -> Result<(Option<Arc<PackageDebugInfo>>, Option<DebugSourceNodeId>), ProcessorError> {
        if !source_aware_execution {
            return Ok((None, None));
        }

        let Some(package_debug_info) = loaded_mast_forest.package_debug_info()? else {
            return Ok((None, None));
        };

        let source_node_id = match package_debug_info.unique_source_root_for_exec_node(root_id) {
            Ok(source_node_id) => source_node_id,
            Err(DebugSourceGraphLookupError::AmbiguousRoot { .. }) => None,
            Err(error) => return Err(SourceContextError::from(error).into()),
        };

        Ok((Some(package_debug_info), source_node_id))
    }
}
