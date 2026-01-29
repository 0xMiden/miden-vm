use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{
    ONE, ZERO,
    mast::{LoopNode, MastForest, MastNodeId},
};

use crate::{
    Host,
    continuation_stack::{Continuation, ContinuationStack},
    errors::OperationError,
    fast::{BreakReason, FastProcessor, Tracer, step::Stopper},
};

impl FastProcessor {
    /// Executes a Loop node from the start.
    #[inline(always)]
    pub(super) fn start_loop_node(
        &mut self,
        loop_node: &LoopNode,
        current_node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl Host,
        tracer: &mut impl Tracer,
        stopper: &impl Stopper,
    ) -> ControlFlow<BreakReason> {
        tracer.start_clock_cycle(
            self,
            Continuation::StartNode(current_node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(current_node_id, current_forest, host)?;

        let condition = self.stack_get(0);

        // drop the condition from the stack
        self.decrement_stack_size(tracer);

        // execute the loop body as long as the condition is true
        if condition == ONE {
            // Push the loop to check condition again after body
            // executes
            continuation_stack.push_finish_loop_entered(current_node_id);
            continuation_stack.push_start_node(loop_node.body());

            // Corresponds to the row inserted for the LOOP operation added
            // to the trace.
            self.increment_clk(tracer, stopper)
        } else if condition == ZERO {
            // Start and exit the loop immediately - corresponding to adding a LOOP and END row
            // immediately since there is no body to execute.

            // Increment the clock, corresponding to the LOOP operation
            self.increment_clk_with_continuation(tracer, stopper, || {
                Some(Continuation::FinishLoop {
                    node_id: current_node_id,
                    was_entered: false,
                })
            })?;

            self.finish_loop_node(
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
    pub(super) fn finish_loop_node(
        &mut self,
        loop_was_entered: bool,
        current_node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl Host,
        tracer: &mut impl Tracer,
        stopper: &impl Stopper,
    ) -> ControlFlow<BreakReason> {
        // This happens after loop body execution
        // Check condition again to see if we should continue looping.
        // If the loop was never entered, we know the condition is ZERO.
        let condition = if loop_was_entered { self.stack_get(0) } else { ZERO };
        let loop_node = current_forest[current_node_id].unwrap_loop();

        if condition == ONE {
            // Add REPEAT row and continue looping
            tracer.start_clock_cycle(
                self,
                Continuation::FinishLoop {
                    node_id: current_node_id,
                    was_entered: true,
                },
                continuation_stack,
                current_forest,
            );

            // Drop the condition from the stack (we know the loop was entered since condition is
            // ONE).
            self.decrement_stack_size(tracer);

            continuation_stack.push_finish_loop_entered(current_node_id);
            continuation_stack.push_start_node(loop_node.body());

            // Corresponds to the REPEAT operation added to the trace.
            self.increment_clk(tracer, stopper)
        } else if condition == ZERO {
            // Exit the loop - add END row
            tracer.start_clock_cycle(
                self,
                Continuation::FinishLoop {
                    node_id: current_node_id,
                    was_entered: loop_was_entered,
                },
                continuation_stack,
                current_forest,
            );

            // The END row only drops the condition from the stack if the loop was entered. This is
            // because the LOOP instruction already dropped the condition. Compare this with when
            // the loop body *is* entered, then the loop body is responsible for pushing the
            // condition back onto the stack, and therefore the END instruction must drop it.
            if loop_was_entered {
                self.decrement_stack_size(tracer);
            }

            // Corresponds to the END operation added to the trace.
            self.increment_clk_with_continuation(tracer, stopper, || {
                Some(Continuation::AfterExitDecorators(current_node_id))
            })?;

            self.execute_after_exit_decorators(current_node_id, current_forest, host)
        } else {
            let err = OperationError::NotBinaryValueLoop { value: condition };
            ControlFlow::Break(BreakReason::Err(err.with_context(
                current_forest,
                current_node_id,
                host,
            )))
        }
    }
}
