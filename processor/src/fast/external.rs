use miden_core::mast::MastForest;

use crate::{
    ExecutionError, Host,
    continuation_stack::{Continuation, ContinuationStack},
    errors::{OperationError, procedure_not_found_with_context},
};

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
/// x procedure with root digest <digest> could not be found
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
pub(super) fn maybe_use_caller_error_context(
    original_err: ExecutionError,
    current_forest: &MastForest,
    continuation_stack: &ContinuationStack,
    host: &mut impl Host,
) -> ExecutionError {
    // We only care about procedure-not-found errors or malformed MAST forest errors.
    let root_digest = match &original_err {
        ExecutionError::ProcedureNotFound { root_digest, .. } => *root_digest,
        ExecutionError::OperationError {
            err: OperationError::MalformedMastForestInHost { root_digest },
            ..
        } => *root_digest,
        _ => return original_err,
    };

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

    // We were able to get the parent node ID, so rebuild the error with the caller's context.
    // For ProcedureNotFound, we reconstruct with the parent's source location.
    // For MalformedMastForestInHost, we wrap in OperationError with the parent's context.
    match &original_err {
        ExecutionError::ProcedureNotFound { .. } => {
            procedure_not_found_with_context(root_digest, current_forest, *parent_node_id, host)
        },
        ExecutionError::OperationError { err, .. } => {
            err.clone().with_context(current_forest, *parent_node_id, host)
        },
        _ => original_err,
    }
}
