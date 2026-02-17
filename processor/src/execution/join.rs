use alloc::sync::Arc;
use core::ops::ControlFlow;

use crate::{
    BreakReason, Host, Stopper,
    continuation_stack::Continuation,
    execution::{ExecutionState, finalize_clock_cycle, finalize_clock_cycle_with_continuation},
    mast::{JoinNode, MastForest, MastNodeId},
    processor::Processor,
    tracer::Tracer,
};

// JOIN NODE PROCESSING
// ================================================================================================

/// Executes a Join node from the start.
#[inline(always)]
pub(super) fn start_join_node<P, H, S, T>(
    state: &mut ExecutionState<'_, P, H, S, T>,
    join_node: &JoinNode,
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
        Continuation::StartNode(node_id),
        state.continuation_stack,
        current_forest,
    );

    // Execute decorators that should be executed before entering the node
    state
        .processor
        .execute_before_enter_decorators(node_id, current_forest, state.host)?;

    state.continuation_stack.push_finish_join(node_id);
    state.continuation_stack.push_start_node(join_node.second());
    state.continuation_stack.push_start_node(join_node.first());

    // Finalize the clock cycle corresponding to the JOIN operation.
    finalize_clock_cycle(state.processor, state.tracer, state.stopper, current_forest)
}

/// Executes the finish phase of a Join node.
#[inline(always)]
pub(super) fn finish_join_node<P, H, S, T>(
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
        Continuation::FinishJoin(node_id),
        state.continuation_stack,
        current_forest,
    );

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
