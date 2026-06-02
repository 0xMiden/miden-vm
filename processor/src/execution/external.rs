use core::ops::ControlFlow;

use miden_mast_package::debug_info::{DebugSourceMastNodeId, PackageDebugInfo};

use crate::{
    BaseHost, BreakReason,
    continuation_stack::ContinuationStack,
    execution::InternalBreakReason,
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
    source_node: Option<DebugSourceMastNodeId>,
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
        source_node,
    })
}

/// Function to be called after [`InternalBreakReason::LoadMastForestFromExternal`] is handled. See
/// the documentation of that enum variant for more details.
pub fn finish_load_mast_forest_from_external<F, T>(
    resolved_node_id_new_forest: MastNodeId,
    new_mast_forest: F,
    external_node_id_old_forest: MastNodeId,
    current_forest: &mut F,
    continuation_stack: &mut ContinuationStack<F>,
    source_debug_info: Option<&PackageDebugInfo>,
    host: &mut impl BaseHost,
    tracer: &mut T,
) -> ControlFlow<BreakReason<F>>
where
    F: ExecutableMastForest + Clone,
    T: Tracer<Forest = F>,
{
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
            OperationError::CircularExternalNode(external_node_old_forest.digest()).with_context(
                old_forest,
                external_node_id_old_forest,
                host,
            ),
        ));
    }

    tracer.record_mast_forest_resolution(resolved_node_id_new_forest, &new_mast_forest);

    let source_node =
        match (source_debug_info, old_forest.get_node_by_id(resolved_node_id_new_forest)) {
            (Some(source_debug_info), Some(resolved_node_old_forest))
                if !resolved_node_old_forest.is_external()
                    && resolved_node_old_forest.digest() == external_node_old_forest.digest() =>
            {
                source_debug_info
                    .unique_source_root_for_exec_node(resolved_node_id_new_forest)
                    .unwrap_or(None)
            },
            _ => None,
        };

    // Push current forest to the continuation stack so that we can return to it
    continuation_stack.push_enter_forest(old_forest.clone());

    // Push the root node of the external MAST forest onto the continuation stack.
    continuation_stack.push_start_node_with_source(resolved_node_id_new_forest, source_node);

    // Update the current forest to the new MAST forest.
    *current_forest = new_mast_forest;

    // Note that executing an External node does not end the clock cycle, so we do not finalize the
    // clock cycle here.
    ControlFlow::Continue(())
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::ops::ControlFlow;

    use miden_core::{
        Felt, assert_matches,
        mast::{
            BasicBlockNodeBuilder, ExternalNodeBuilder, MastForest, MastForestContributor,
            MastNodeExt,
        },
        operations::Operation,
    };
    use miden_mast_package::debug_info::{
        DebugSourceGraphSection, DebugSourceMastNode, DebugSourceMastNodeId, PackageDebugInfo,
    };

    use super::*;
    use crate::{Continuation, DefaultHost, fast::NoopTracer};

    #[test]
    fn current_package_external_resolution_ignores_ambiguous_source_root() {
        let mut forest = MastForest::new();
        let target_id = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::from_u32(7))])
            .add_to_forest(&mut forest)
            .unwrap();
        let target_digest = forest[target_id].digest();
        let external_id =
            ExternalNodeBuilder::new(target_digest).add_to_forest(&mut forest).unwrap();
        forest.make_root(target_id);
        forest.make_root(external_id);

        let source_a = DebugSourceMastNodeId::from(0);
        let source_b = DebugSourceMastNodeId::from(1);
        let package_debug_info = PackageDebugInfo {
            source_graph: Some(DebugSourceGraphSection {
                nodes: vec![
                    DebugSourceMastNode::new(target_id, vec![], 0, 1),
                    DebugSourceMastNode::new(target_id, vec![], 0, 1),
                ],
                roots: vec![source_a, source_b],
                ..DebugSourceGraphSection::new()
            }),
            ..PackageDebugInfo::default()
        };

        let mut current_forest = Arc::new(forest);
        let new_mast_forest = current_forest.clone();
        let mut continuation_stack = ContinuationStack::default();
        let mut host = DefaultHost::default();
        let mut tracer = NoopTracer;

        let result = finish_load_mast_forest_from_external(
            target_id,
            new_mast_forest,
            external_id,
            &mut current_forest,
            &mut continuation_stack,
            Some(&package_debug_info),
            &mut host,
            &mut tracer,
        );

        assert_matches!(result, ControlFlow::Continue(()));
        assert_matches!(
            continuation_stack.pop_continuation_with_source(),
            Some((Continuation::StartNode(node_id), None)) if node_id == target_id
        );
    }
}
