use miden_mast_package::debug_info::PackageDebugInfo;

use crate::{
    BaseHost, ExecutionError,
    continuation_stack::{Continuation, ContinuationStack},
    errors::{
        OperationError, PackageSourceDebugContext, procedure_not_found_with_context,
        procedure_not_found_with_package_source_context,
    },
};

// HELPERS
// ---------------------------------------------------------------------------------------------

/// If the given error is generated when trying to resolve an External node, and there is a caller
/// continuation available, rebuild the error in the legacy no-context form.
///
/// In practice, `ExternalNode`s are executed via a `CallNode` or `DynNode`. Thus, if we fail to
/// resolve an `ExternalNode`, we can look at the top of the continuation stack to confirm that the
/// break came from a caller node that can lead to external node execution.
pub(super) fn maybe_use_caller_error_context<F>(
    original_err: ExecutionError,
    continuation_stack: &ContinuationStack<F>,
    package_debug_info: Option<&PackageDebugInfo>,
    host: &impl BaseHost,
) -> ExecutionError {
    if matches!(original_err, ExecutionError::ProcedureNotFound { source_file: Some(_), .. }) {
        return original_err;
    }

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
    let Some((top_continuation, source_node)) = continuation_stack.peek_continuation_with_source()
    else {
        return original_err;
    };

    // Accept all continuations that can lead to external node execution.
    match top_continuation {
        Continuation::FinishCall(_)
        | Continuation::FinishJoin(_)
        | Continuation::FinishSplit(_)
        | Continuation::FinishLoop(_) => {},
        _ => return original_err,
    }

    // We found a caller continuation, so rebuild the error through the legacy no-context path.
    match &original_err {
        ExecutionError::ProcedureNotFound { .. } => match (package_debug_info, source_node) {
            (Some(debug_info), Some(source_node)) => {
                procedure_not_found_with_package_source_context(
                    root_digest,
                    PackageSourceDebugContext::new(debug_info, source_node),
                    host,
                )
            },
            _ => procedure_not_found_with_context(root_digest),
        },
        ExecutionError::OperationError { err, .. } => err.clone().with_context(),
        _ => original_err,
    }
}
