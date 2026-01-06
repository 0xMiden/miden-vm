use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{
    ONE, ZERO,
    mast::{MastForest, MastNodeId, SplitNode},
};

use crate::{
    AsyncHost, ExecutionError,
    continuation_stack::{Continuation, ContinuationStack},
    err_ctx,
    fast::{BreakReason, FastProcessor, Tracer, step::Stopper, trace_state::NodeExecutionState},
};

impl FastProcessor {
    /// Executes a Split node from the start.
    #[inline(always)]
    pub(super) fn start_split_node(
        &mut self,
        split_node: &SplitNode,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
        stopper: &impl Stopper,
    ) -> ControlFlow<BreakReason> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::Start(node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, current_forest, host)?;

        let condition = self.stack_get(0);

        // drop the condition from the stack
        self.decrement_stack_size(tracer);

        // execute the appropriate branch
        continuation_stack.push_finish_split(node_id);
        if condition == ONE {
            continuation_stack.push_start_node(split_node.on_true());
        } else if condition == ZERO {
            continuation_stack.push_start_node(split_node.on_false());
        } else {
            let err_ctx = err_ctx!(current_forest, node_id, host, self.in_debug_mode());
            return ControlFlow::Break(BreakReason::Err(ExecutionError::not_binary_value_if(
                condition, &err_ctx,
            )));
        };

        // Corresponds to the row inserted for the SPLIT operation added
        // to the trace.
        self.increment_clk(tracer, stopper)
    }

    /// Executes the finish phase of a Split node.
    #[inline(always)]
    pub(super) fn finish_split_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
        stopper: &impl Stopper,
    ) -> ControlFlow<BreakReason> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::End(node_id),
            continuation_stack,
            current_forest,
        );

        // Corresponds to the row inserted for the END operation added
        // to the trace.
        self.increment_clk_with_continuation(tracer, stopper, || {
            Some(Continuation::AfterExitDecorators(node_id))
        })?;

        self.execute_after_exit_decorators(node_id, current_forest, host)?;

        ControlFlow::Continue(())
    }
}
