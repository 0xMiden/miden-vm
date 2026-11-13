use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

use crate::{
    BaseHost, ExecutionError, ProcessorError,
    continuation_stack::{Continuation, ContinuationStack},
    errors::{OperationError, PackageSourceDebugContext},
};

/// Chooses the failing external occurrence or its caller before resolving diagnostics once.
///
/// An external reference may have no source location of its own. For resolution failures, the
/// pending caller continuation provides a useful fallback within the same package.
pub(super) fn load_error_with_context<F>(
    err: ProcessorError,
    source_node_id: Option<DebugSourceNodeId>,
    continuation_stack: &ContinuationStack<F>,
    package_debug_info: Option<&PackageDebugInfo>,
    host: &impl BaseHost,
) -> ExecutionError {
    let context = package_debug_info
        .map(|debug_info| PackageSourceDebugContext::new(debug_info, source_node_id));
    let is_resolution_error = matches!(
        err,
        ProcessorError::ProcedureNotFound { .. }
            | ProcessorError::MastForestLoad { .. }
            | ProcessorError::Operation(OperationError::MalformedMastForestInHost { .. })
    );
    let has_location = context.and_then(|context| context.assembly_location(None)).is_some();
    let context = if is_resolution_error && !has_location {
        let caller = continuation_stack.peek_continuation_with_source_node_id().and_then(
            |(continuation, source_node_id)| match continuation {
                Continuation::FinishCall(_)
                | Continuation::FinishJoin(_)
                | Continuation::FinishSplit(_)
                | Continuation::FinishLoop(_) => source_node_id,
                _ => None,
            },
        );
        match (package_debug_info, caller) {
            (Some(debug_info), Some(source_node_id)) => {
                Some(PackageSourceDebugContext::new(debug_info, Some(source_node_id)))
            },
            _ => context,
        }
    } else {
        context
    };
    err.with_context(context, host, None)
}
