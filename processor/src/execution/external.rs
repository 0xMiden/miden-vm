use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::mast::{MastForest, MastNodeExt, MastNodeId};

use crate::{
    Host, continuation_stack::ContinuationStack, execution::InternalBreakReason,
    fast::step::BreakReason, operation::OperationError, processor::Processor, tracer::Tracer,
};

/// Executes an External node.
#[inline(always)]
pub(super) fn execute_external_node(
    processor: &mut impl Processor,
    external_node_id: MastNodeId,
    current_forest: &mut Arc<MastForest>,
    host: &mut impl Host,
) -> ControlFlow<InternalBreakReason> {
    // Execute decorators that should be executed before entering the node
    processor
        .execute_before_enter_decorators(external_node_id, current_forest, host)
        .map_break(InternalBreakReason::from)?;

    // This is a sans-IO point: we cannot proceed with loading the MAST forest, since some
    // processors need this to be done asynchronously. Thus, we break here and make the implementing
    // processor handle the loading in the outer execution loop. When done, the processor *must*
    // call `finish_load_mast_forest_from_external()` below for execution to proceed properly.
    let external_node = current_forest[external_node_id].unwrap_external();
    ControlFlow::Break(InternalBreakReason::LoadMastForestFromExternal {
        external_node_id,
        procedure_hash: external_node.digest(),
    })
}

/// Function to be called after [`InternalBreakReason::LoadMastForestFromExternal`] is handled. See
/// the documentation of that enum variant for more details.
pub fn finish_load_mast_forest_from_external(
    resolved_node_id: MastNodeId,
    new_mast_forest: Arc<MastForest>,
    external_node_id: MastNodeId,
    current_forest: &mut Arc<MastForest>,
    continuation_stack: &mut ContinuationStack,
    host: &mut impl Host,
    tracer: &mut impl Tracer,
) -> ControlFlow<BreakReason> {
    let external_node = current_forest[external_node_id].unwrap_external();
    // if the node that we got by looking up an external reference is also an External
    // node, we are about to enter into an infinite loop - so, return an error
    if new_mast_forest[resolved_node_id].is_external() {
        return ControlFlow::Break(BreakReason::Err(
            OperationError::CircularExternalNode(external_node.digest()).with_context(
                current_forest,
                external_node_id,
                host,
            ),
        ));
    }

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

    // Note that executing an External node does not end the clock cycle, so we do not finalize the
    // clock cycle here.
    ControlFlow::Continue(())
}
