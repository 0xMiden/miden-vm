use core::ops::ControlFlow;

use crate::{
    BaseHost, BreakReason, MapExecErr, ONE, Stopper, ZERO,
    continuation_stack::Continuation,
    execution::{ExecutionState, finalize_clock_cycle, finalize_clock_cycle_with_continuation},
    mast::{ExecutableMastForest, MastNodeId, SplitNode},
    operation::OperationError,
    processor::{Processor, StackInterface},
    tracer::Tracer,
};

// SPLIT PROCESSING
// ================================================================================================

/// Executes a Split node from the start.
#[inline(always)]
pub(super) fn start_split_node<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    split_node: &SplitNode,
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

    let condition = state.processor.stack().get(0);

    // drop the condition from the stack
    if let Err(err) = state.processor.stack_mut().decrement_size().map_exec_err() {
        return ControlFlow::Break(BreakReason::Err(err));
    }

    // execute the appropriate branch
    if condition == ONE {
        let source_node = match state.child_source_node(0) {
            Ok(source_node) => source_node,
            Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
        };
        state
            .continuation_stack
            .push_finish_split_with_source(node_id, state.current_source_node());
        state
            .continuation_stack
            .push_start_node_with_source(split_node.on_true(), source_node);
    } else if condition == ZERO {
        let source_node = match state.child_source_node(1) {
            Ok(source_node) => source_node,
            Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
        };
        state
            .continuation_stack
            .push_finish_split_with_source(node_id, state.current_source_node());
        state
            .continuation_stack
            .push_start_node_with_source(split_node.on_false(), source_node);
    } else {
        let err = OperationError::NotBinaryValueIf { value: condition };
        return ControlFlow::Break(BreakReason::Err(err.with_context()));
    };

    // Finalize the clock cycle corresponding to the SPLIT operation.
    finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    )
}

/// Executes the finish phase of a Split node.
#[inline(always)]
pub(super) fn finish_split_node<P, H, S, T, F>(
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
        Continuation::FinishSplit(node_id),
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
