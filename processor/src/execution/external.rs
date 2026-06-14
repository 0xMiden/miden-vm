use core::ops::ControlFlow;

use miden_mast_package::debug_info::DebugSourceNodeId;

use crate::{
    BreakReason,
    continuation_stack::{Continuation, ContinuationStack},
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
pub fn finish_load_mast_forest_from_external<F, T>(
    resolved_node_id_new_forest: MastNodeId,
    new_mast_forest: F,
    external_node_id_old_forest: MastNodeId,
    current_forest: &mut F,
    continuation_stack: &mut ContinuationStack<F>,
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
            OperationError::CircularExternalNode(external_node_old_forest.digest()).with_context(),
        ));
    }

    tracer.record_mast_forest_resolution(resolved_node_id_new_forest, &new_mast_forest);

    // Push current forest to the continuation stack so that we can return to it
    continuation_stack.push_enter_forest(old_forest.clone());

    // Push the root node of the external MAST forest onto the continuation stack.
    //
    // Caller package debug info describes the forest that contained the `External` node, not the
    // loaded forest. The loaded root therefore starts without a source sidecar here.
    continuation_stack
        .push_with_source_node_id(Continuation::StartNode(resolved_node_id_new_forest), None);

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
        mast::{BasicBlockNodeBuilder, ExternalNodeBuilder, MastForest, MastForestContributor},
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

        let result = finish_load_mast_forest_from_external(
            target_id,
            new_mast_forest,
            external_id,
            &mut current_forest,
            &mut continuation_stack,
            &mut tracer,
        );

        assert_matches!(result, ControlFlow::Continue(()));
        assert_matches!(
            continuation_stack.pop_continuation_with_source_node_id(),
            Some((Continuation::StartNode(node_id), None)) if node_id == target_id
        );
        assert_matches!(
            continuation_stack.pop_continuation_with_source_node_id(),
            Some((Continuation::EnterForest(_), None))
        );
        assert_matches!(
            continuation_stack.pop_continuation_with_source_node_id(),
            Some((Continuation::StartNode(node_id), Some(source_node_id)))
                if node_id == external_id && source_node_id == caller_source_node_id
        );
    }
}
