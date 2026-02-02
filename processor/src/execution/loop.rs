use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{
    ONE, ZERO,
    mast::{LoopNode, MastForest, MastNodeId},
};

use crate::{
    Host, Stopper,
    continuation_stack::{Continuation, ContinuationStack},
    execution::{finalize_clock_cycle, finalize_clock_cycle_with_continuation},
    fast::step::BreakReason,
    operation::OperationError,
    processor::{Processor, StackInterface},
    tracer::Tracer,
};

/// Executes a Loop node from the start.
#[inline(always)]
pub(super) fn start_loop_node<P, S>(
    processor: &mut P,
    loop_node: &LoopNode,
    current_node_id: MastNodeId,
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

    let condition = processor.stack().get(0);

    // drop the condition from the stack
    processor.stack_mut().decrement_size(tracer);

    // execute the loop body as long as the condition is true
    if condition == ONE {
        // Push the loop to check condition again after body
        // executes
        continuation_stack.push_finish_loop_entered(current_node_id);
        continuation_stack.push_start_node(loop_node.body());

        // Finalize the clock cycle corresponding to the LOOP operation.
        finalize_clock_cycle(processor, tracer, stopper)
    } else if condition == ZERO {
        // Start and exit the loop immediately - corresponding to adding a LOOP and END row
        // immediately since there is no body to execute.

        // Finalize the clock cycle corresponding to the LOOP operation.
        finalize_clock_cycle_with_continuation(processor, tracer, stopper, || {
            Some(Continuation::FinishLoop {
                node_id: current_node_id,
                was_entered: false,
            })
        })?;

        finish_loop_node(
            processor,
            false,
            current_node_id,
            current_forest,
            continuation_stack,
            host,
            tracer,
            stopper,
        )
    } else {
        let err = OperationError::NotBinaryValueLoop { value: condition };
        ControlFlow::Break(BreakReason::Err(err.with_context(
            current_forest,
            current_node_id,
            host,
        )))
    }
}

/// Executes the finish phase of a Loop node.
///
/// This function is called either after the loop body has executed (in which case
/// `loop_was_entered` is true), or when the loop condition was found to be ZERO at the start of
/// the loop (in which case `loop_was_entered` is false).
#[inline(always)]
pub(super) fn finish_loop_node<P, S>(
    processor: &mut P,
    loop_was_entered: bool,
    current_node_id: MastNodeId,
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
    // This happens after loop body execution or when the loop condition was ZERO at the start.
    // Check condition again to see if we should continue looping. If the loop was never entered, we
    // know the condition is ZERO.
    let condition = if loop_was_entered {
        processor.stack().get(0)
    } else {
        ZERO
    };
    let loop_node = current_forest[current_node_id].unwrap_loop();

    if condition == ONE {
        // Start the clock cycle corresponding to the REPEAT operation, before re-entering the loop
        // body.
        tracer.start_clock_cycle(
            processor,
            Continuation::FinishLoop {
                node_id: current_node_id,
                was_entered: true,
            },
            continuation_stack,
            current_forest,
        );

        // Drop the condition from the stack (we know the loop was entered since condition is
        // ONE).
        processor.stack_mut().decrement_size(tracer);

        continuation_stack.push_finish_loop_entered(current_node_id);
        continuation_stack.push_start_node(loop_node.body());

        // Finalize the clock cycle corresponding to the REPEAT operation.
        finalize_clock_cycle(processor, tracer, stopper)
    } else if condition == ZERO {
        // Exit the loop - start the clock cycle corresponding to the END operation.
        tracer.start_clock_cycle(
            processor,
            Continuation::FinishLoop {
                node_id: current_node_id,
                was_entered: loop_was_entered,
            },
            continuation_stack,
            current_forest,
        );

        // The END operation only drops the condition from the stack if the loop was entered. This
        // is because if the loop was never entered, then the condition will have already been
        // dropped by the LOOP operation. Compare this with when the loop body *is* entered, then
        // the loop body is responsible for pushing the condition back onto the stack, and therefore
        // the END instruction must drop it.
        if loop_was_entered {
            processor.stack_mut().decrement_size(tracer);
        }

        // Finalize the clock cycle corresponding to the END operation.
        finalize_clock_cycle_with_continuation(processor, tracer, stopper, || {
            Some(Continuation::AfterExitDecorators(current_node_id))
        })?;

        processor.execute_after_exit_decorators(current_node_id, current_forest, host)
    } else {
        let err = OperationError::NotBinaryValueLoop { value: condition };
        ControlFlow::Break(BreakReason::Err(err.with_context(
            current_forest,
            current_node_id,
            host,
        )))
    }
}
