use alloc::sync::Arc;
use core::ops::ControlFlow;

use crate::{
    BreakReason, Host, ONE, Stopper, ZERO,
    continuation_stack::Continuation,
    execution::{
        ExecutionState, finalize_clock_cycle, finalize_clock_cycle_with_continuation,
        result_to_control_flow,
    },
    mast::{LoopNode, MastForest, MastNodeId},
    operation::OperationError,
    processor::{Processor, StackInterface},
    tracer::Tracer,
};

// LOOP NODE PROCESSING
// ================================================================================================

/// Executes a Loop node from the start.
#[inline(always)]
pub(super) fn start_loop_node<P, H, S, T>(
    state: &mut ExecutionState<'_, P, H, S, T>,
    loop_node: &LoopNode,
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
    result_to_control_flow(state.processor.execute_before_enter_decorators(
        current_node_id,
        current_forest,
        state.host,
    ))?;

    let condition = state.processor.stack().get(0);

    // drop the condition from the stack
    state.processor.stack_mut().decrement_size();
    state.tracer.decrement_stack_size();

    // execute the loop body as long as the condition is true
    if condition == ONE {
        // Push the loop to check condition again after body
        // executes
        state.continuation_stack.push_finish_loop_entered(current_node_id);
        state.continuation_stack.push_start_node(loop_node.body());

        // Finalize the clock cycle corresponding to the LOOP operation.
        finalize_clock_cycle(state.processor, state.tracer, state.stopper, current_forest)
    } else if condition == ZERO {
        // Start and exit the loop immediately - corresponding to adding a LOOP and END row
        // immediately since there is no body to execute.

        // Finalize the clock cycle corresponding to the LOOP operation.
        finalize_clock_cycle_with_continuation(
            state.processor,
            state.tracer,
            state.stopper,
            || {
                Some(Continuation::FinishLoop {
                    node_id: current_node_id,
                    was_entered: false,
                })
            },
            current_forest,
        )?;

        finish_loop_node(state, false, current_node_id, current_forest)
    } else {
        let err = OperationError::NotBinaryValueLoop { value: condition };
        ControlFlow::Break(BreakReason::Err(err.with_context(
            current_forest,
            current_node_id,
            state.host,
        )))
    }
}

/// Executes the finish phase of a Loop node.
///
/// This function is called either after the loop body has executed (in which case
/// `loop_was_entered` is true), or when the loop condition was found to be ZERO at the start of
/// the loop (in which case `loop_was_entered` is false).
#[inline(always)]
pub(super) fn finish_loop_node<P, H, S, T>(
    state: &mut ExecutionState<'_, P, H, S, T>,
    loop_was_entered: bool,
    current_node_id: MastNodeId,
    current_forest: &Arc<MastForest>,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    H: Host,
    S: Stopper<Processor = P>,
    T: Tracer<Processor = P>,
{
    // This happens after loop body execution or when the loop condition was ZERO at the start.
    // Check condition again to see if we should continue looping. If the loop was never entered, we
    // know the condition is ZERO.
    let condition = if loop_was_entered {
        state.processor.stack().get(0)
    } else {
        ZERO
    };
    let loop_node = current_forest[current_node_id].unwrap_loop();

    if condition == ONE {
        // Start the clock cycle corresponding to the REPEAT operation, before re-entering the loop
        // body.
        state.tracer.start_clock_cycle(
            state.processor,
            Continuation::FinishLoop {
                node_id: current_node_id,
                was_entered: true,
            },
            state.continuation_stack,
            current_forest,
        );

        // Drop the condition from the stack (we know the loop was entered since condition is
        // ONE).
        state.processor.stack_mut().decrement_size();
        state.tracer.decrement_stack_size();

        state.continuation_stack.push_finish_loop_entered(current_node_id);
        state.continuation_stack.push_start_node(loop_node.body());

        // Finalize the clock cycle corresponding to the REPEAT operation.
        finalize_clock_cycle(state.processor, state.tracer, state.stopper, current_forest)
    } else if condition == ZERO {
        // Exit the loop - start the clock cycle corresponding to the END operation.
        state.tracer.start_clock_cycle(
            state.processor,
            Continuation::FinishLoop {
                node_id: current_node_id,
                was_entered: loop_was_entered,
            },
            state.continuation_stack,
            current_forest,
        );

        // The END operation only drops the condition from the stack if the loop was entered. This
        // is because if the loop was never entered, then the condition will have already been
        // dropped by the LOOP operation. Compare this with when the loop body *is* entered, then
        // the loop body is responsible for pushing the condition back onto the stack, and therefore
        // the END instruction must drop it.
        if loop_was_entered {
            state.processor.stack_mut().decrement_size();
            state.tracer.decrement_stack_size();
        }

        // Finalize the clock cycle corresponding to the END operation.
        finalize_clock_cycle_with_continuation(
            state.processor,
            state.tracer,
            state.stopper,
            || Some(Continuation::AfterExitDecorators(current_node_id)),
            current_forest,
        )?;

        result_to_control_flow(state.processor.execute_after_exit_decorators(
            current_node_id,
            current_forest,
            state.host,
        ))
    } else {
        let err = OperationError::NotBinaryValueLoop { value: condition };
        ControlFlow::Break(BreakReason::Err(err.with_context(
            current_forest,
            current_node_id,
            state.host,
        )))
    }
}
