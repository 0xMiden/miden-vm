use alloc::sync::Arc;

use miden_core::mast::{JoinNode, MastForest, MastNodeId};

use crate::{
    AsyncHost, ExecutionError,
    continuation_stack::ContinuationStack,
    fast::{FastProcessor, Tracer, trace_state::NodeExecutionState},
};

impl FastProcessor {
    /// Executes a Join node from the start.
    #[inline(always)]
    pub(super) fn start_join_node(
        &mut self,
        join_node: &JoinNode,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::Start(node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, current_forest, host)?;

        continuation_stack.push_finish_join(node_id);
        continuation_stack.push_start_node(join_node.second());
        continuation_stack.push_start_node(join_node.first());

        // Corresponds to the row inserted for the JOIN operation added
        // to the trace.
        self.increment_clk(tracer);

        Ok(())
    }

    /// Executes the finish phase of a Join node.
    #[inline(always)]
    pub(super) fn finish_join_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::End(node_id),
            continuation_stack,
            current_forest,
        );

        // Corresponds to the row inserted for the END operation added
        // to the trace.
        self.increment_clk(tracer);

        self.execute_after_exit_decorators(node_id, current_forest, host)
    }
}
