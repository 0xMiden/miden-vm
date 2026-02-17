use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE};

use crate::{
    BreakReason, ContextId, Host, MapExecErr, Stopper,
    continuation_stack::Continuation,
    execution::{
        ExecutionState, finalize_clock_cycle, finalize_clock_cycle_with_continuation,
        get_next_ctx_id,
    },
    mast::{CallNode, MastForest, MastNodeExt, MastNodeId},
    operation::OperationError,
    processor::{MemoryInterface, Processor, SystemInterface},
    tracer::Tracer,
};

// CALL NODE PROCESSORS
// ================================================================================================

/// Executes a Call node from the start.
#[inline(always)]
pub(super) fn start_call_node<P, H, S, T>(
    state: &mut ExecutionState<'_, P, H, S, T>,
    call_node: &CallNode,
    current_node_id: MastNodeId,
    current_forest: &Arc<MastForest>,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    H: Host,
    S: Stopper<Processor = P>,
    T: Tracer<Processor = P>,
{
    state.tracer.start_clock_cycle(
        state.processor,
        Continuation::StartNode(current_node_id),
        state.continuation_stack,
        current_forest,
    );

    // Execute decorators that should be executed before entering the node
    state
        .processor
        .execute_before_enter_decorators(current_node_id, current_forest, state.host)?;

    state.tracer.start_context();
    state.processor.save_context_and_truncate_stack();

    let callee_hash = current_forest[call_node.callee()].digest();
    if call_node.is_syscall() {
        // check if the callee is in the kernel
        if !state.kernel.contains_proc(callee_hash) {
            let err = OperationError::SyscallTargetNotInKernel { proc_root: callee_hash };
            return ControlFlow::Break(BreakReason::Err(err.with_context(
                current_forest,
                current_node_id,
                state.host,
            )));
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
            .map_exec_err(current_forest, current_node_id, state.host)
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
    finalize_clock_cycle(state.processor, state.tracer, state.stopper, current_forest)
}

/// Executes the finish phase of a Call node.
#[inline(always)]
pub(super) fn finish_call_node<P, H, S, T>(
    state: &mut ExecutionState<'_, P, H, S, T>,
    node_id: MastNodeId,
    current_forest: &Arc<MastForest>,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    H: Host,
    S: Stopper<Processor = P>,
    T: Tracer<Processor = P>,
{
    state.tracer.start_clock_cycle(
        state.processor,
        Continuation::FinishCall(node_id),
        state.continuation_stack,
        current_forest,
    );

    // When returning from a call or a syscall, restore the context of the system registers and the
    // operand stack to what it was prior to the call.
    if let Err(e) = state.processor.restore_context() {
        return ControlFlow::Break(BreakReason::Err(e.with_context(
            current_forest,
            node_id,
            state.host,
        )));
    }
    state.tracer.restore_context();

    // Finalize the clock cycle corresponding to the END operation.
    finalize_clock_cycle_with_continuation(
        state.processor,
        state.tracer,
        state.stopper,
        || Some(Continuation::AfterExitDecorators(node_id)),
        current_forest,
    )?;

    state
        .processor
        .execute_after_exit_decorators(node_id, current_forest, state.host)
}
