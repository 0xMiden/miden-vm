use core::ops::ControlFlow;

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

    // Push current forest to the continuation stack so that we can return to it
    continuation_stack.push_enter_forest(old_forest.clone());

    // Push the root node of the external MAST forest onto the continuation stack.
    continuation_stack.push_start_node(resolved_node_id_new_forest);

    // Update the current forest to the new MAST forest.
    *current_forest = new_mast_forest;

    // Note that executing an External node does not end the clock cycle, so we do not finalize the
    // clock cycle here.
    ControlFlow::Continue(())
}
