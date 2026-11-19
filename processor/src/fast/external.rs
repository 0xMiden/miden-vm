use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

use crate::{
    BaseHost, ExecutionError, ProcessorError,
    continuation_stack::{Continuation, ContinuationStack},
    errors::{OperationError, PackageSourceDebugContext},
};

/// Selects resolved source diagnostics before constructing the execution error.
///
/// An external reference may have no location or refer to a source file unavailable to the host.
/// For resolution failures, the pending caller continuation provides a fallback in the same
/// package. Prefer a source file over a span alone, and prefer the external reference when both
/// provide the same kind of source information.
pub(super) fn load_error_with_context<F>(
    err: ProcessorError,
    source_node_id: Option<DebugSourceNodeId>,
    continuation_stack: &ContinuationStack<F>,
    package_debug_info: Option<&PackageDebugInfo>,
    host: &impl BaseHost,
) -> ExecutionError {
    let context = package_debug_info
        .map(|debug_info| PackageSourceDebugContext::new(debug_info, source_node_id));
    let mut source = context.map(|context| context.resolve_source(host, None)).unwrap_or_default();
    let is_resolution_error = matches!(
        err,
        ProcessorError::ProcedureNotFound { .. }
            | ProcessorError::MastForestLoad { .. }
            | ProcessorError::Operation(OperationError::MalformedMastForestInHost { .. })
    );
    if is_resolution_error && source.1.is_none() {
        let caller = continuation_stack.peek_continuation_with_source_node_id().and_then(
            |(continuation, source_node_id)| match continuation {
                Continuation::FinishCall(_)
                | Continuation::FinishJoin(_)
                | Continuation::FinishSplit(_)
                | Continuation::FinishLoop(_) => source_node_id,
                _ => None,
            },
        );
        if let (Some(debug_info), Some(source_node_id)) = (package_debug_info, caller) {
            let caller_source = PackageSourceDebugContext::new(debug_info, Some(source_node_id))
                .resolve_source(host, None);
            if caller_source.1.is_some() || (source.0.is_unknown() && !caller_source.0.is_unknown())
            {
                source = caller_source;
            }
        }
    }
    err.with_resolved_context(package_debug_info, source)
}
