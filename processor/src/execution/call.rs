use core::ops::ControlFlow;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE};

use crate::{
    BaseHost, BreakReason, ContextId, MapExecErr, Stopper,
    continuation_stack::Continuation,
    execution::{
        ExecutionState, finalize_clock_cycle, finalize_clock_cycle_with_continuation,
        get_next_ctx_id,
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
) -> ControlFlow<BreakReason<F>>
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
    )?;
    if call_node.is_syscall() {
        // check if the callee is in the kernel
        if !state.kernel.contains_proc(callee_hash) {
            let err = OperationError::SyscallTargetNotInKernel { proc_root: callee_hash };
            return ControlFlow::Break(BreakReason::Err(
                state.operation_error_with_current_context(err),
            ));
        }
        state.tracer.record_kernel_proc_access(callee_hash);

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
            return ControlFlow::Break(BreakReason::Err(err));
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
    let callee_source_node_id = match state.child_source_node_id(0) {
        Ok(source_node_id) => source_node_id,
        Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
    };
    state.continuation_stack.push_with_source_node_id(
        Continuation::FinishCall(current_node_id),
        state.current_source_node_id(),
    );
    state.continuation_stack.push_with_source_node_id(
        Continuation::StartNode(call_node.callee()),
        callee_source_node_id,
    );

    // Finalize the clock cycle corresponding to the CALL or SYSCALL operation.
    finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    )
}

/// Executes a Call node from the start without source debug metadata.
#[inline(always)]
pub(super) fn start_call_node_pure<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    call_node: &CallNode,
    current_node_id: MastNodeId,
    current_forest: &F,
) -> ControlFlow<BreakReason<F>>
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
    )?;
    if call_node.is_syscall() {
        // check if the callee is in the kernel
        if !state.kernel.contains_proc(callee_hash) {
            let err = OperationError::SyscallTargetNotInKernel { proc_root: callee_hash };
            return ControlFlow::Break(BreakReason::Err(
                state.operation_error_with_current_context(err),
            ));
        }
        state.tracer.record_kernel_proc_access(callee_hash);

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
            return ControlFlow::Break(BreakReason::Err(err));
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
    state.continuation_stack.push_finish_call(current_node_id);
    state.continuation_stack.push_start_node(call_node.callee());

    // Finalize the clock cycle corresponding to the CALL or SYSCALL operation.
    finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    )
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
