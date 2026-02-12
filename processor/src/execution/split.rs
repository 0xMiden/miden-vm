use alloc::sync::Arc;
use core::ops::ControlFlow;

use crate::{
    BreakReason, Host, ONE, Stopper, ZERO,
    continuation_stack::Continuation,
    execution::{
        ExecutionState, finalize_clock_cycle, finalize_clock_cycle_with_continuation,
        result_to_control_flow,
    },
    mast::{MastForest, MastNodeId, SplitNode},
    operation::OperationError,
    processor::{Processor, StackInterface},
    tracer::Tracer,
};

// SPLIT PROCESSING
// ================================================================================================

/// Executes a Split node from the start.
#[inline(always)]
pub(super) fn start_split_node<P, H, S, T>(
    state: &mut ExecutionState<'_, P, H, S, T>,
    split_node: &SplitNode,
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
    result_to_control_flow(state.processor.execute_before_enter_decorators(
        node_id,
        current_forest,
        state.host,
    ))?;

    let condition = state.processor.stack().get(0);

    // drop the condition from the stack
    state.processor.stack_mut().decrement_size();
    state.tracer.decrement_stack_size();

    // execute the appropriate branch
    state.continuation_stack.push_finish_split(node_id);
    if condition == ONE {
        state.continuation_stack.push_start_node(split_node.on_true());
    } else if condition == ZERO {
        state.continuation_stack.push_start_node(split_node.on_false());
    } else {
        let err = OperationError::NotBinaryValueIf { value: condition };
        return ControlFlow::Break(BreakReason::Err(err.with_context(
            current_forest,
            node_id,
            state.host,
        )));
    };

    // Finalize the clock cycle corresponding to the SPLIT operation.
    finalize_clock_cycle(state.processor, state.tracer, state.stopper, current_forest)
}

/// Executes the finish phase of a Split node.
#[inline(always)]
pub(super) fn finish_split_node<P, H, S, T>(
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
        Continuation::FinishSplit(node_id),
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

    result_to_control_flow(state.processor.execute_after_exit_decorators(
        node_id,
        current_forest,
        state.host,
    ))
}
