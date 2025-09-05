use alloc::sync::Arc;

use miden_core::mast::{ExternalNode, MastForest, MastNodeId};

use crate::{
    AsyncHost, ExecutionError,
    continuation_stack::ContinuationStack,
    fast::{FastProcessor, Tracer},
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
    ) -> Result<(), ExecutionError> {
        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(external_node_id, current_forest, host)?;

        let external_node = current_forest[external_node_id].unwrap_external();
        let (resolved_node_id, new_mast_forest) =
            self.resolve_external_node(external_node, host).await?;

        tracer.record_external_node_resolution(resolved_node_id, &new_mast_forest);

        // Push current forest to the continuation stack so that we can return to it
        continuation_stack.push_enter_forest(current_forest.clone());

        // Push the root node of the external MAST forest onto the continuation stack.
        continuation_stack.push_start_node(resolved_node_id);

        self.execute_after_exit_decorators(external_node_id, current_forest, host)?;

        // Update the current forest to the new MAST forest.
        *current_forest = new_mast_forest;

        Ok(())
    }

    /// Analogous to [`Process::resolve_external_node`](crate::Process::resolve_external_node), but
    /// for asynchronous execution.
    async fn resolve_external_node(
        &mut self,
        external_node: &ExternalNode,
        host: &mut impl AsyncHost,
    ) -> Result<(MastNodeId, Arc<MastForest>), ExecutionError> {
        let (root_id, mast_forest) = self
            .load_mast_forest(
                external_node.digest(),
                host,
                ExecutionError::no_mast_forest_with_procedure,
                &(),
            )
            .await?;

        // if the node that we got by looking up an external reference is also an External
        // node, we are about to enter into an infinite loop - so, return an error
        if mast_forest[root_id].is_external() {
            return Err(ExecutionError::CircularExternalNode(external_node.digest()));
        }

        Ok((root_id, mast_forest))
    }
}
