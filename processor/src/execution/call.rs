use core::ops::ControlFlow;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE};

use crate::{
    BaseHost, BreakReason, ContextId, MapExecErr, Stopper,
    continuation_stack::Continuation,
    execution::{
        ExecutionState, InternalBreakReason, finalize_clock_cycle,
        finalize_clock_cycle_with_continuation, get_next_ctx_id,
    },
    mast::{CallNode, ExecutableMastForest, MastNodeId},
    operation::OperationError,
    option_map_break_reason,
    processor::{MemoryInterface, Processor, StackInterface, SystemInterface},
    tracer::Tracer,
};

// CALL NODE PROCESSORS
// ================================================================================================

/// Executes a Call node from the start.
#[inline]
pub(super) fn start_call_node<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    call_node: &CallNode,
    current_node_id: MastNodeId,
    current_forest: &F,
) -> ControlFlow<InternalBreakReason<F>>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    state.tracer.start_clock_cycle(
        state.processor,
        Continuation::StartNode(current_node_id),
        state.continuation_stack,
        current_forest,
    );

    state.processor.stack_mut().start_context();
    state.processor.system_mut().save_call_state();

    let callee_hash = option_map_break_reason(
        current_forest.get_digest_by_id(call_node.callee()),
        "callee node not found in current forest",
    )
    .map_break(InternalBreakReason::from)?;
    let mut resolved_hash = callee_hash;
    if call_node.is_syscall() {
        let Some(procedure_root) = state.kernel.resolve(callee_hash) else {
            let err = OperationError::SyscallTargetNotInKernel { proc_root: callee_hash };
            return ControlFlow::Break(
                BreakReason::Err(state.operation_error_with_current_context(err)).into(),
            );
        };
        resolved_hash = procedure_root;
        state.tracer.record_kernel_proc_access(callee_hash, procedure_root);

        // set the system registers to the syscall context
        state.processor.system_mut().set_ctx(ContextId::root());
    } else {
        let new_ctx: ContextId = get_next_ctx_id(state.processor);

        // Set the system registers to the callee context.
        state.processor.system_mut().set_ctx(new_ctx);
        state.processor.system_mut().set_caller_hash(callee_hash);

        // Initialize the frame pointer in memory for the new context.
        if let Err(err) = state
            .processor
            .memory_mut()
            .write_element(new_ctx, FMP_ADDR, FMP_INIT_VALUE)
            .map_exec_err()
        {
            return ControlFlow::Break(BreakReason::Err(err).into());
        }
        state.tracer.record_memory_write_element(
            FMP_INIT_VALUE,
            FMP_ADDR,
            new_ctx,
            state.processor.system().clock(),
        );
    }

    // Update the continuation stack: first push the finish call continuation, then the callee node
    // (to be executed next).
    let (callee_id, callee_source_node_id) = if resolved_hash == callee_hash {
        (Some(call_node.callee()), state.child_source_node_id(0))
    } else {
        let callee_id = current_forest.find_procedure_root(resolved_hash);
        let source_node_id = callee_id.and_then(|id| {
            state
                .source_debug_info
                .as_ref()?
                .unique_source_root_for_exec_node(id)
                .unwrap_or_default()
        });
        (callee_id, Ok(source_node_id))
    };
    let callee_source_node_id = match callee_source_node_id {
        Ok(source_node_id) => source_node_id,
        Err(err) => return ControlFlow::Break(BreakReason::Err(err).into()),
    };
    if resolved_hash != callee_hash {
        // The resolved body is not the source child carrying the callsite's inline rows.
        let inline_call_context = state.current_inline_call_context();
        state.inline_call_contexts.push(inline_call_context);
    }
    state.continuation_stack.push_with_source_node_id(
        Continuation::FinishCall(current_node_id),
        state.current_source_node_id(),
    );
    let Some(callee_id) = callee_id else {
        return ControlFlow::Break(InternalBreakReason::LoadMastForestForInvocation {
            callee_hash: resolved_hash,
            source_node_id: state.current_source_node_id(),
        });
    };
    state
        .continuation_stack
        .push_with_source_node_id(Continuation::StartNode(callee_id), callee_source_node_id);

    // Finalize the clock cycle corresponding to the CALL or SYSCALL operation.
    finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    )
    .map_break(InternalBreakReason::from)
}

/// Executes the finish phase of a Call node.
#[inline(always)]
pub(super) fn finish_call_node<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    node_id: MastNodeId,
    current_forest: &F,
) -> ControlFlow<BreakReason<F>>
where
    P: Processor,
    H: BaseHost,
    S: Stopper<Processor = P, Forest = F>,
    T: Tracer<Processor = P, Forest = F>,
    F: ExecutableMastForest + Clone,
{
    let call_node = option_map_break_reason(
        current_forest.get_node_by_id(node_id),
        "call node not found in current forest",
    )?
    .unwrap_call();
    if call_node.is_syscall() {
        let key = option_map_break_reason(
            current_forest.get_digest_by_id(call_node.callee()),
            "callee node not found in current forest",
        )?;
        if state.kernel.resolve(key).is_some_and(|root| root != key) {
            state.inline_call_contexts.pop();
        }
    }
    state.tracer.start_clock_cycle(
        state.processor,
        Continuation::FinishCall(node_id),
        state.continuation_stack,
        current_forest,
    );

    // When returning from a call or a syscall, restore the context of the system registers and the
    // operand stack to what it was prior to the call.
    if let Err(e) = state.processor.stack_mut().restore_context() {
        return ControlFlow::Break(BreakReason::Err(state.operation_error_with_current_context(e)));
    }
    if let Err(e) = state.processor.system_mut().restore_call_state() {
        return ControlFlow::Break(BreakReason::Err(state.operation_error_with_current_context(e)));
    }
    // Finalize the clock cycle corresponding to the END operation.
    finalize_clock_cycle_with_continuation(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        || None,
        current_forest,
    )
}
