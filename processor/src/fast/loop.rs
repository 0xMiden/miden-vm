use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{
    ONE, ZERO,
    mast::{LoopNode, MastForest, MastNodeId},
};

use crate::{
    AsyncHost, ExecutionError,
    continuation_stack::{Continuation, ContinuationStack},
    err_ctx,
    fast::{BreakReason, FastProcessor, Tracer, step::Stopper, trace_state::NodeExecutionState},
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
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
        stopper: &impl Stopper,
    ) -> ControlFlow<BreakReason> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::Start(current_node_id),
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
            continuation_stack.push_finish_loop(current_node_id);
            continuation_stack.push_start_node(loop_node.body());

            // Corresponds to the row inserted for the LOOP operation added
            // to the trace.
            self.increment_clk(tracer, stopper)
        } else if condition == ZERO {
            // Start and exit the loop immediately - corresponding to adding a LOOP and END row
            // immediately since there is no body to execute.

            // Increment the clock, corresponding to the LOOP operation
            self.increment_clk_with_continuation(tracer, stopper, || {
                Some(Continuation::FinishLoopUnentered(current_node_id))
            })?;

            self.finish_loop_node_unentered(
                current_node_id,
                current_forest,
                continuation_stack,
                host,
                tracer,
                stopper,
            )
        } else {
            let err_ctx = err_ctx!(current_forest, current_node_id, host, self.in_debug_mode());
            ControlFlow::Break(BreakReason::Err(ExecutionError::not_binary_value_loop(
                condition, &err_ctx,
            )))
        }
    }

    /// Executes the finish phase of a Loop node.
    #[inline(always)]
    pub(super) fn finish_loop_node(
        &mut self,
        current_node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
        stopper: &impl Stopper,
    ) -> ControlFlow<BreakReason> {
        // This happens after loop body execution
        // Check condition again to see if we should continue looping
        let condition = self.stack_get(0);
        let loop_node = current_forest[current_node_id].unwrap_loop();

        if condition == ONE {
            // Add REPEAT row and continue looping
            tracer.start_clock_cycle(
                self,
                NodeExecutionState::LoopRepeat(current_node_id),
                continuation_stack,
                current_forest,
            );

            // Drop the condition from the stack (on the REPEAT instruction)
            self.decrement_stack_size(tracer);

            continuation_stack.push_finish_loop(current_node_id);
            continuation_stack.push_start_node(loop_node.body());

            // Corresponds to the REPEAT operation added to the trace.
            self.increment_clk(tracer, stopper)
        } else if condition == ZERO {
            // Exit the loop - add END row
            tracer.start_clock_cycle(
                self,
                NodeExecutionState::End(current_node_id),
                continuation_stack,
                current_forest,
            );
            self.decrement_stack_size(tracer);

            // Corresponds to the END operation added to the trace.
            self.increment_clk_with_continuation(tracer, stopper, || {
                Some(Continuation::AfterExitDecorators(current_node_id))
            })?;

            self.execute_after_exit_decorators(current_node_id, current_forest, host)
        } else {
            let err_ctx = err_ctx!(current_forest, current_node_id, host, self.in_debug_mode());
            ControlFlow::Break(BreakReason::Err(ExecutionError::not_binary_value_loop(
                condition, &err_ctx,
            )))
        }
    }

    /// Executes the finish phase of a Loop node that was never entered.
    ///
    /// This corresponds to simply executing the after_exit decorators and incrementing the clock,
    /// corresponding to the END operation added to the trace.
    #[inline(always)]
    pub(super) fn finish_loop_node_unentered(
        &mut self,
        current_node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
        stopper: &impl Stopper,
    ) -> ControlFlow<BreakReason> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::End(current_node_id),
            continuation_stack,
            current_forest,
        );

        // Increment the clock, corresponding to the END operation added to the trace.
        self.increment_clk_with_continuation(tracer, stopper, || {
            Some(Continuation::AfterExitDecorators(current_node_id))
        })?;

        // Execute decorators that should be executed after exiting the node
        self.execute_after_exit_decorators(current_node_id, current_forest, host)
    }
}
