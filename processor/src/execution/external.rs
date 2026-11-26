use alloc::{sync::Arc, vec::Vec};
use core::ops::ControlFlow;

use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

use crate::{
    BaseHost, BreakReason, ProcessorError,
    continuation_stack::{Continuation, ContinuationStack, SourceInlineCallContext},
    errors::PackageSourceDebugContext,
    execution::{InternalBreakReason, ResolvedMastForest},
    mast::{ExecutableMastForest, MastNodeExt, MastNodeId},
    operation::OperationError,
    option_map_break_reason,
    tracer::Tracer,
};

// EXTERNAL NODE PROCESSING
// ================================================================================================

/// Executes an External node.
#[inline(always)]
pub(super) fn execute_external_node<T, F>(
    external_node_id: MastNodeId,
    source_node_id: Option<DebugSourceNodeId>,
    current_forest: &mut F,
    tracer: &mut T,
) -> ControlFlow<InternalBreakReason<F>>
where
    T: Tracer<Forest = F>,
    F: ExecutableMastForest + Clone,
{
    // External nodes don't drive a clock cycle and so don't reach `Tracer::start_clock_cycle`.
    // Inform the tracer that we are entering this node so accumulating tracers (e.g. the sparse
    // forest builder) can mark it as visited.
    tracer.record_external_node_entered(external_node_id, current_forest);

    // This is a sans-IO point: we cannot proceed with loading the MAST forest, since some
    // processors need this to be done asynchronously. Thus, we break here and make the implementing
    // processor handle the loading in the outer execution loop. When done, the processor *must*
    // call `finish_load_mast_forest_from_external()` below for execution to proceed properly.
    let external_node = option_map_break_reason(
        current_forest.get_node_by_id(external_node_id),
        "external node not found in current forest",
    )
    .map_break(InternalBreakReason::from)?
    .unwrap_external();
    ControlFlow::Break(InternalBreakReason::LoadMastForestFromExternal {
        external_node_id,
        procedure_hash: external_node.digest(),
        source_node_id,
    })
}

/// Function to be called after [`InternalBreakReason::LoadMastForestFromExternal`] is handled. See
/// the documentation of that enum variant for more details.
pub(crate) fn finish_load_mast_forest_from_external<F, T>(
    resolved: ResolvedMastForest<F>,
    inline_call_context: Option<SourceInlineCallContext>,
    external_origin: (MastNodeId, Option<DebugSourceNodeId>),
    current_forest: &mut F,
    current_package_debug_info: &mut Option<Arc<PackageDebugInfo>>,
    inline_call_contexts: &mut Vec<Option<SourceInlineCallContext>>,
    continuation_stack: &mut ContinuationStack<F>,
    tracer: &mut T,
    host: &impl BaseHost,
) -> ControlFlow<BreakReason<F>>
where
    F: ExecutableMastForest + Clone,
    T: Tracer<Forest = F>,
{
    let ResolvedMastForest {
        root_id: resolved_node_id_new_forest,
        forest: new_mast_forest,
        package_debug_info: new_package_debug_info,
        source_node_id: new_source_node_id,
    } = resolved;
    let (external_node_id_old_forest, old_source_node_id) = external_origin;
    let old_forest = current_forest as &F;
    let external_node_old_forest = option_map_break_reason(
        old_forest.get_node_by_id(external_node_id_old_forest),
        "external node not found in current forest",
    )?
    .unwrap_external();
    let resolved_node_new_forest = option_map_break_reason(
        new_mast_forest.get_node_by_id(resolved_node_id_new_forest),
        "resolved node not found in new mast forest",
    )?;
    // if the node that we got by looking up an external reference is also an External
    // node, we are about to enter into an infinite loop - so, return an error
    if resolved_node_new_forest.is_external() {
        return ControlFlow::Break(BreakReason::Err(
            ProcessorError::Operation(OperationError::CircularExternalNode(
                external_node_old_forest.digest(),
            ))
            .with_context(
                current_package_debug_info.as_deref().map(|debug_info| {
                    PackageSourceDebugContext::new_optional(debug_info, old_source_node_id)
                }),
                host,
                None,
            ),
        ));
    }

    tracer.record_mast_forest_resolution(resolved_node_id_new_forest, &new_mast_forest);

    let old_package_debug_info = current_package_debug_info.clone();
    let inline_context_depth = inline_call_contexts.len();
    if let Some(inline_call_context) = inline_call_context {
        inline_call_contexts.push(Some(inline_call_context));
    }

    // Push current forest to the continuation stack so that we can return to it
    continuation_stack.push_enter_forest_with_package_debug_info(
        old_forest.clone(),
        old_package_debug_info,
        inline_context_depth,
        old_source_node_id,
    );

    // Push the root node of the external MAST forest onto the continuation stack.
    continuation_stack.push_with_source_node_id(
        Continuation::StartNode(resolved_node_id_new_forest),
        new_source_node_id,
    );

    // Update the current forest to the new MAST forest.
    *current_forest = new_mast_forest;
    *current_package_debug_info = new_package_debug_info;

    // Note that executing an External node does not end the clock cycle, so we do not finalize the
    // clock cycle here.
    ControlFlow::Continue(())
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::{assert_matches, ops::ControlFlow};

    use miden_core::{
        Felt,
        mast::{BasicBlockNodeBuilder, ExternalNodeBuilder, MastForest},
        operations::Operation,
        program::Program,
    };
    use miden_mast_package::debug_info::DebugSourceNodeId;

    use super::*;
    use crate::{Continuation, fast::NoopTracer};

    #[test]
    fn loaded_external_forest_starts_without_source_sidecar() {
        let mut current_forest = MastForest::new();
        let mut loaded_forest = MastForest::new();
        let target_id = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::from_u32(7))])
            .add_to_forest(&mut loaded_forest)
            .unwrap();
        loaded_forest.make_root(target_id);
        let external_id = ExternalNodeBuilder::new(loaded_forest[target_id].digest())
            .add_to_forest(&mut current_forest)
            .unwrap();
        current_forest.make_root(external_id);

        let caller_source_node_id = DebugSourceNodeId::from(0);
        let mut current_forest = Arc::new(current_forest);
        let program = Program::new(current_forest.clone(), external_id);
        let new_mast_forest = Arc::new(loaded_forest);
        let mut continuation_stack =
            ContinuationStack::new_with_source_node_id(&program, caller_source_node_id);
        let mut tracer = NoopTracer;
        let mut package_debug_info = None;
        let mut inline_call_contexts = Vec::new();

        let result = finish_load_mast_forest_from_external(
            ResolvedMastForest {
                root_id: target_id,
                forest: new_mast_forest,
                package_debug_info: None,
                source_node_id: None,
            },
            None,
            (external_id, None),
            &mut current_forest,
            &mut package_debug_info,
            &mut inline_call_contexts,
            &mut continuation_stack,
            &mut tracer,
            &crate::host::default::NoopHost,
        );

        assert_matches!(result, ControlFlow::Continue(()));
        assert!(inline_call_contexts.is_empty());
        assert_matches!(
            continuation_stack.pop_continuation_with_source_node_id(),
            Some((Continuation::StartNode(node_id), None)) if node_id == target_id
        );
        assert_matches!(
            continuation_stack.pop_continuation_with_source_node_id(),
            Some((Continuation::EnterForest { .. }, None))
        );
        assert_matches!(
            continuation_stack.pop_continuation_with_source_node_id(),
            Some((Continuation::StartNode(node_id), Some(source_node_id)))
                if node_id == external_id && source_node_id == caller_source_node_id
        );
    }
}
