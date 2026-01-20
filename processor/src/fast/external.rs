use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::mast::{ExternalNode, MastForest, MastNodeExt, MastNodeId};

use crate::{
    AsyncHost, ExecutionError,
    continuation_stack::ContinuationStack,
    errors::OperationError,
    fast::{BreakReason, FastProcessor, Tracer},
};

impl FastProcessor {
    /// Executes an External node.
    #[inline(always)]
    pub(super) async fn execute_external_node(
        &mut self,
        external_node_id: MastNodeId,
        current_forest: &mut Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
    ) -> ControlFlow<BreakReason> {
        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(external_node_id, current_forest, host)?;

        let external_node = current_forest[external_node_id].unwrap_external();
        let (resolved_node_id, new_mast_forest) = match self
            .resolve_external_node(external_node, external_node_id, current_forest, host)
            .await
        {
            Ok(result) => result,
            Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
        };

        tracer.record_mast_forest_resolution(resolved_node_id, &new_mast_forest);

        // Push a continuation to execute after_exit decorators when we return from the external
        // forest
        continuation_stack.push_finish_external(external_node_id);

        // Push current forest to the continuation stack so that we can return to it
        continuation_stack.push_enter_forest(current_forest.clone());

        // Push the root node of the external MAST forest onto the continuation stack.
        continuation_stack.push_start_node(resolved_node_id);

        // Update the current forest to the new MAST forest.
        *current_forest = new_mast_forest;

        ControlFlow::Continue(())
    }

    /// Analogous to [`Process::resolve_external_node`](crate::Process::resolve_external_node), but
    /// for asynchronous execution.
    ///
    /// Note: External node diagnostics are not fully implemented in FastProcessor (see #2476).
    /// We pass the external node's parent forest and node_id for basic error context.
    async fn resolve_external_node(
        &mut self,
        external_node: &ExternalNode,
        external_node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl AsyncHost,
    ) -> Result<(MastNodeId, Arc<MastForest>), ExecutionError> {
        let (root_id, mast_forest) = self
            .load_mast_forest(
                external_node.digest(),
                host,
                |root_digest| OperationError::NoMastForestWithProcedure { root_digest },
                current_forest,
                external_node_id,
            )
            .await?;

        // if the node that we got by looking up an external reference is also an External
        // node, we are about to enter into an infinite loop - so, return an error
        if mast_forest[root_id].is_external() {
            return Err(OperationError::CircularExternalNode(external_node.digest()).with_context(
                current_forest,
                external_node_id,
                host,
            ));
        }

        Ok((root_id, mast_forest))
    }
}
