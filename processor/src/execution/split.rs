use core::ops::ControlFlow;

use crate::{
    BaseHost, BreakReason, MapExecErr, ONE, Stopper, ZERO,
    continuation_stack::Continuation,
    execution::{ExecutionState, finalize_clock_cycle, finalize_clock_cycle_with_continuation},
    mast::{ExecutableMastForest, MastNodeId, SplitNode},
    operation::{BinaryValueErrorContext, OperationError},
    processor::{Processor, StackInterface},
    tracer::Tracer,
};

// SPLIT PROCESSING
// ================================================================================================

/// Executes a Split node from the start.
#[inline]
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
        let source_node_id = match state.child_source_node_id(0) {
            Ok(source_node_id) => source_node_id,
            Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
        };
        state.continuation_stack.push_with_source_node_id(
            Continuation::FinishSplit(node_id),
            state.current_source_node_id(),
        );
        state.continuation_stack.push_with_source_node_id(
            Continuation::StartNode(split_node.on_true()),
            source_node_id,
        );
    } else if condition == ZERO {
        let source_node_id = match state.child_source_node_id(1) {
            Ok(source_node_id) => source_node_id,
            Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
        };
        state.continuation_stack.push_with_source_node_id(
            Continuation::FinishSplit(node_id),
            state.current_source_node_id(),
        );
        state.continuation_stack.push_with_source_node_id(
            Continuation::StartNode(split_node.on_false()),
            source_node_id,
        );
    } else {
        let err = OperationError::NotBinaryValue {
            context: BinaryValueErrorContext::If,
            value: condition,
        };
        return ControlFlow::Break(BreakReason::Err(
            state.operation_error_with_current_context(err),
        ));
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

/// Executes a Split node from the start without source debug metadata.
#[inline(always)]
pub(super) fn start_split_node_pure<P, H, S, T, F>(
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
        state.continuation_stack.push_finish_split(node_id);
        state.continuation_stack.push_start_node(split_node.on_true());
    } else if condition == ZERO {
        state.continuation_stack.push_finish_split(node_id);
        state.continuation_stack.push_start_node(split_node.on_false());
    } else {
        let err = OperationError::NotBinaryValue {
            context: BinaryValueErrorContext::If,
            value: condition,
        };
        return ControlFlow::Break(BreakReason::Err(
            state.operation_error_with_current_context(err),
        ));
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
