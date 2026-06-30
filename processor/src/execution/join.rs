use core::ops::ControlFlow;

use crate::{
    BaseHost, BreakReason, Stopper,
    continuation_stack::Continuation,
    execution::{ExecutionState, finalize_clock_cycle, finalize_clock_cycle_with_continuation},
    mast::{ExecutableMastForest, JoinNode, MastNodeId},
    processor::Processor,
    tracer::Tracer,
};

// JOIN NODE PROCESSING
// ================================================================================================

/// Executes a Join node from the start.
#[inline]
pub(super) fn start_join_node<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    join_node: &JoinNode,
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
        Continuation::StartNode(node_id),
        state.continuation_stack,
        current_forest,
    );

    let first_source_node_id = match state.child_source_node_id(0) {
        Ok(source_node_id) => source_node_id,
        Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
    };
    let second_source_node_id = match state.child_source_node_id(1) {
        Ok(source_node_id) => source_node_id,
        Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
    };

    state.continuation_stack.push_with_source_node_id(
        Continuation::FinishJoin(node_id),
        state.current_source_node_id(),
    );
    state.continuation_stack.push_with_source_node_id(
        Continuation::StartNode(join_node.second()),
        second_source_node_id,
    );
    state
        .continuation_stack
        .push_with_source_node_id(Continuation::StartNode(join_node.first()), first_source_node_id);

    // Finalize the clock cycle corresponding to the JOIN operation.
    finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    )
}

/// Executes a Join node from the start without source debug metadata.
#[inline(always)]
pub(super) fn start_join_node_pure<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    join_node: &JoinNode,
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
        Continuation::StartNode(node_id),
        state.continuation_stack,
        current_forest,
    );

    state.continuation_stack.push_finish_join(node_id);
    state.continuation_stack.push_start_node(join_node.second());
    state.continuation_stack.push_start_node(join_node.first());

    // Finalize the clock cycle corresponding to the JOIN operation.
    finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    )
}

/// Executes the finish phase of a Join node.
#[inline(always)]
pub(super) fn finish_join_node<P, H, S, T, F>(
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
        Continuation::FinishJoin(node_id),
        state.continuation_stack,
        current_forest,
    );

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
