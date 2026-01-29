use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::mast::{ExternalNode, MastForest, MastNodeExt, MastNodeId};

use crate::{
    ExecutionError, Host,
    continuation_stack::{Continuation, ContinuationStack},
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
        host: &mut impl Host,
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
            Err(err) => {
                let maybe_enriched_err =
                    maybe_use_caller_error_context(err, current_forest, continuation_stack, host);

                return ControlFlow::Break(BreakReason::Err(maybe_enriched_err));
            },
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

    /// Resolves an External node by loading the MAST forest from the host that contains the
    /// referenced procedure, if any.
    async fn resolve_external_node(
        &mut self,
        external_node: &ExternalNode,
        external_node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl Host,
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

// HELPERS
// ---------------------------------------------------------------------------------------------

/// If the given error is an error generated when trying to resolve an External node, and there is a
/// caller context available in the continuation stack, use the caller node ID to build the error
/// context.
///
/// In practice, `ExternalNode`s are executed via a `CallNode` or `DynNode`. Thus, if we fail to
/// resolve an `ExternalNode`, we can look at the top of the continuation stack to find the caller
/// node ID (that we expect to be a `CallNode` or `DynNode`), and build the diagnostic from that
/// node.
///
/// For example, in MASM, the user would see an error like:
/// ```masm
/// x no MAST forest contains the procedure with root digest <digest>
///     ,-[::\$exec:5:13]
///   4 |         begin
///   5 |             call.bar::dummy_proc
///     :             ^^^^^^^^^^^^^^^^^^^^
///   6 |         end
///     `----
/// ```
///
/// The carets and line numbers point to the `call` instruction that triggered the error because of
/// the remapping we do in this function.
fn maybe_use_caller_error_context(
    original_err: ExecutionError,
    current_forest: &MastForest,
    continuation_stack: &ContinuationStack,
    host: &mut impl Host,
) -> ExecutionError {
    // We only care about operation errors...
    let ExecutionError::OperationError { label: _, source_file: _, err: inner_err } = &original_err
    else {
        return original_err;
    };

    // ... that are related to external node resolution.
    let is_external_resolution_err = matches!(
        inner_err,
        OperationError::NoMastForestWithProcedure { .. }
            | OperationError::MalformedMastForestInHost { .. }
    );
    if !is_external_resolution_err {
        return original_err;
    }

    // Look for caller context in the continuation stack
    let Some(top_continuation) = continuation_stack.peek_continuation() else {
        return original_err;
    };

    // Extract parent node ID from all continuations that can lead to an external node execution.
    //
    // Note that the assembler current doesn't attach `AssemblyOp` decorators to Join nodes.
    let parent_node_id = match top_continuation {
        Continuation::FinishCall(parent_node_id)
        | Continuation::FinishJoin(parent_node_id)
        | Continuation::FinishSplit(parent_node_id)
        | Continuation::FinishLoop { node_id: parent_node_id, .. } => parent_node_id,
        _ => return original_err,
    };

    // We were able to get the parent node ID, so use that to build the error context
    inner_err.clone().with_context(current_forest, *parent_node_id, host)
}
