use core::ops::ControlFlow;

use crate::{
    BaseHost, BreakReason, MapExecErr, ONE, Stopper, ZERO,
    continuation_stack::Continuation,
    execution::{ExecutionState, finalize_clock_cycle, finalize_clock_cycle_with_continuation},
    mast::{ExecutableMastForest, LoopNode, MastNodeId},
    operation::OperationError,
    option_map_break_reason,
    processor::{Processor, StackInterface},
    tracer::Tracer,
};

// LOOP NODE PROCESSING
// ================================================================================================

/// Executes a Loop node from the start.
///
/// LoopNode has do-while semantics: the body is entered unconditionally and the condition is only
/// inspected at the end of each iteration (REPEAT/END). Source-level guarding (`while.true`) is
/// implemented by the assembler wrapping the LOOP in a SPLIT that selects the loop on a true
/// condition and skips it on false.
#[inline(always)]
pub(super) fn start_loop_node<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    loop_node: &LoopNode,
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

    // Unconditionally enter the loop body for the first iteration.
    //
    // WARNING: if we eventually push another continuation in between the `FinishLoop` and the
    // `StartNode` continuations, then the logic in `ExecutionTracer::start_clock_cycle()` that
    // computes the value for the `is_loop_body` flag will be incorrect and needs to be adjusted.
    let body_source_node_id = match state.child_source_node_id(0) {
        Ok(source_node_id) => source_node_id,
        Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
    };
    state
        .continuation_stack
        .push_finish_loop_with_source_node_id(current_node_id, state.current_source_node_id());
    state
        .continuation_stack
        .push_start_node_with_source_node_id(loop_node.body(), body_source_node_id);

    // Finalize the clock cycle corresponding to the LOOP operation.
    finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    )
}

/// Executes a Loop node from the start without source debug metadata.
#[inline(always)]
pub(super) fn start_loop_node_pure<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
    loop_node: &LoopNode,
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

    // Unconditionally enter the loop body for the first iteration.
    //
    // WARNING: if we eventually push another continuation in between the `FinishLoop` and the
    // `StartNode` continuations, then the logic in `ExecutionTracer::start_clock_cycle()` that
    // computes the value for the `is_loop_body` flag will be incorrect and needs to be adjusted.
    state.continuation_stack.push_finish_loop(current_node_id);
    state.continuation_stack.push_start_node(loop_node.body());

    // Finalize the clock cycle corresponding to the LOOP operation.
    finalize_clock_cycle(
        state.processor,
        state.tracer,
        state.stopper,
        state.continuation_stack,
        current_forest,
    )
}

/// Executes the finish phase of a Loop node, called once the loop body has finished executing.
///
/// Reads the boolean condition the body left on top of the stack. If `ONE`, fires REPEAT and
/// re-enters the body; if `ZERO`, fires END and exits the loop. Any other value is an error.
#[inline(always)]
pub(super) fn finish_loop_node<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
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
    let condition = state.processor.stack().get(0);
    let loop_node = option_map_break_reason(
        current_forest.get_node_by_id(current_node_id),
        "loop node not found in current forest",
    )?
    .unwrap_loop();

    if condition == ONE {
        // Start the clock cycle corresponding to the REPEAT operation, before re-entering the loop
        // body.
        state.tracer.start_clock_cycle(
            state.processor,
            Continuation::FinishLoop(current_node_id),
            state.continuation_stack,
            current_forest,
        );

        // Drop the condition from the stack.
        if let Err(err) = state.processor.stack_mut().decrement_size().map_exec_err() {
            return ControlFlow::Break(BreakReason::Err(err));
        }

        let body_source_node_id = match state.child_source_node_id(0) {
            Ok(source_node_id) => source_node_id,
            Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
        };
        state
            .continuation_stack
            .push_finish_loop_with_source_node_id(current_node_id, state.current_source_node_id());
        state
            .continuation_stack
            .push_start_node_with_source_node_id(loop_node.body(), body_source_node_id);

        // Finalize the clock cycle corresponding to the REPEAT operation.
        finalize_clock_cycle(
            state.processor,
            state.tracer,
            state.stopper,
            state.continuation_stack,
            current_forest,
        )
    } else if condition == ZERO {
        // Exit the loop - start the clock cycle corresponding to the END operation.
        state.tracer.start_clock_cycle(
            state.processor,
            Continuation::FinishLoop(current_node_id),
            state.continuation_stack,
            current_forest,
        );

        // The END operation drops the condition from the stack; the loop body always leaves the
        // condition there.
        if let Err(err) = state.processor.stack_mut().decrement_size().map_exec_err() {
            return ControlFlow::Break(BreakReason::Err(err));
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
    } else {
        let err = OperationError::NotBinaryValueLoop { value: condition };
        ControlFlow::Break(BreakReason::Err(state.operation_error_with_current_context(err)))
    }
}

/// Executes the finish phase of a Loop node without source debug metadata.
#[inline(always)]
pub(super) fn finish_loop_node_pure<P, H, S, T, F>(
    state: &mut ExecutionState<'_, P, H, S, T, F>,
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
    let condition = state.processor.stack().get(0);
    let loop_node = option_map_break_reason(
        current_forest.get_node_by_id(current_node_id),
        "loop node not found in current forest",
    )?
    .unwrap_loop();

    if condition == ONE {
        // Start the clock cycle corresponding to the REPEAT operation, before re-entering the loop
        // body.
        state.tracer.start_clock_cycle(
            state.processor,
            Continuation::FinishLoop(current_node_id),
            state.continuation_stack,
            current_forest,
        );

        // Drop the condition from the stack.
        if let Err(err) = state.processor.stack_mut().decrement_size().map_exec_err() {
            return ControlFlow::Break(BreakReason::Err(err));
        }

        state.continuation_stack.push_finish_loop(current_node_id);
        state.continuation_stack.push_start_node(loop_node.body());

        // Finalize the clock cycle corresponding to the REPEAT operation.
        finalize_clock_cycle(
            state.processor,
            state.tracer,
            state.stopper,
            state.continuation_stack,
            current_forest,
        )
    } else if condition == ZERO {
        // Exit the loop - start the clock cycle corresponding to the END operation.
        state.tracer.start_clock_cycle(
            state.processor,
            Continuation::FinishLoop(current_node_id),
            state.continuation_stack,
            current_forest,
        );

        // The END operation drops the condition from the stack; the loop body always leaves the
        // condition there.
        if let Err(err) = state.processor.stack_mut().decrement_size().map_exec_err() {
            return ControlFlow::Break(BreakReason::Err(err));
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
    } else {
        let err = OperationError::NotBinaryValueLoop { value: condition };
        ControlFlow::Break(BreakReason::Err(state.operation_error_with_current_context(err)))
    }
}
