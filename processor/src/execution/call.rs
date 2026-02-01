use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{
    FMP_ADDR, FMP_INIT_VALUE, Kernel,
    mast::{CallNode, MastForest, MastNodeExt, MastNodeId},
};

use crate::{
    ContextId, Host, MapExecErr, OperationError, Stopper,
    continuation_stack::{Continuation, ContinuationStack},
    execution::{finalize_clock_cycle, finalize_clock_cycle_with_continuation},
    fast::step::BreakReason,
    processor::{MemoryInterface, Processor, SystemInterface},
    tracer::Tracer,
};

/// Executes a Call node from the start.
#[inline(always)]
pub(super) fn start_call_node<P, S>(
    processor: &mut P,
    call_node: &CallNode,
    current_node_id: MastNodeId,
    kernel: &Kernel,
    current_forest: &Arc<MastForest>,
    continuation_stack: &mut ContinuationStack,
    host: &mut impl Host,
    tracer: &mut impl Tracer,
    stopper: &S,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
{
    tracer.start_clock_cycle(
        processor,
        Continuation::StartNode(current_node_id),
        continuation_stack,
        current_forest,
    );

    // Execute decorators that should be executed before entering the node
    processor.execute_before_enter_decorators(current_node_id, current_forest, host)?;

    processor.save_context_and_truncate_stack(tracer);

    let callee_hash = current_forest[call_node.callee()].digest();
    if call_node.is_syscall() {
        // check if the callee is in the kernel
        if !kernel.contains_proc(callee_hash) {
            let err = OperationError::SyscallTargetNotInKernel { proc_root: callee_hash };
            return ControlFlow::Break(BreakReason::Err(err.with_context(
                current_forest,
                current_node_id,
                host,
            )));
        }
        tracer.record_kernel_proc_access(callee_hash);

        // set the system registers to the syscall context
        processor.system_mut().set_ctx(ContextId::root());
    } else {
        let new_ctx: ContextId = processor.next_ctx_id();

        // Set the system registers to the callee context.
        processor.system_mut().set_ctx(new_ctx);
        processor.system_mut().set_caller_hash(callee_hash);

        // Initialize the frame pointer in memory for the new context.
        if let Err(err) = processor
            .memory_mut()
            .write_element(new_ctx, FMP_ADDR, FMP_INIT_VALUE)
            .map_exec_err(current_forest, current_node_id, host)
        {
            return ControlFlow::Break(BreakReason::Err(err));
        }
        tracer.record_memory_write_element(
            FMP_INIT_VALUE,
            FMP_ADDR,
            new_ctx,
            processor.system().clock(),
        );
    }

    // Update the continuation stack: first push the finish call continuation, then the callee node
    // (to be executed next).
    continuation_stack.push_finish_call(current_node_id);
    continuation_stack.push_start_node(call_node.callee());

    // Finalize the clock cycle corresponding to the CALL or SYSCALL operation.
    finalize_clock_cycle(processor, tracer, stopper)
}

/// Executes the finish phase of a Call node.
#[inline(always)]
pub(super) fn finish_call_node<P, S>(
    processor: &mut P,
    node_id: MastNodeId,
    current_forest: &Arc<MastForest>,
    continuation_stack: &mut ContinuationStack,
    host: &mut impl Host,
    tracer: &mut impl Tracer,
    stopper: &S,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
{
    tracer.start_clock_cycle(
        processor,
        Continuation::FinishCall(node_id),
        continuation_stack,
        current_forest,
    );

    // When returning from a call or a syscall, restore the context of the system registers and the
    // operand stack to what it was prior to the call.
    if let Err(e) = processor.restore_context(tracer) {
        return ControlFlow::Break(BreakReason::Err(e.with_context(current_forest, node_id, host)));
    }

    // Finalize the clock cycle corresponding to the END operation.
    finalize_clock_cycle_with_continuation(processor, tracer, stopper, || {
        Some(Continuation::AfterExitDecorators(node_id))
    })?;

    processor.execute_after_exit_decorators(node_id, current_forest, host)
}
