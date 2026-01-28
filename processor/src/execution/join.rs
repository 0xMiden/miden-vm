use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::mast::{JoinNode, MastForest, MastNodeId};

use crate::{
    Host, Stopper,
    continuation_stack::{Continuation, ContinuationStack},
    execution::{finalize_clock_cycle, finalize_clock_cycle_with_continuation},
    fast::step::BreakReason,
    processor::Processor,
    tracer::Tracer,
};

/// Executes a Join node from the start.
#[inline(always)]
pub(super) fn start_join_node<P, S>(
    processor: &mut P,
    join_node: &JoinNode,
    node_id: MastNodeId,
    current_forest: &Arc<MastForest>,
    continuation_stack: &mut ContinuationStack,
    host: &mut impl Host,
    tracer: &mut impl Tracer,
    stopper: &S,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
{
    tracer.start_clock_cycle(
        processor,
        Continuation::StartNode(node_id),
        continuation_stack,
        current_forest,
    );

    // Execute decorators that should be executed before entering the node
    processor.execute_before_enter_decorators(node_id, current_forest, host)?;

    continuation_stack.push_finish_join(node_id);
    continuation_stack.push_start_node(join_node.second());
    continuation_stack.push_start_node(join_node.first());

    // Finalize the clock cycle corresponding to the JOIN operation.
    finalize_clock_cycle(processor, tracer, stopper)
}

/// Executes the finish phase of a Join node.
#[inline(always)]
pub(super) fn finish_join_node<P, S>(
    processor: &mut P,
    node_id: MastNodeId,
    current_forest: &Arc<MastForest>,
    continuation_stack: &mut ContinuationStack,
    host: &mut impl Host,
    tracer: &mut impl Tracer,
    stopper: &S,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
{
    tracer.start_clock_cycle(
        processor,
        Continuation::FinishJoin(node_id),
        continuation_stack,
        current_forest,
    );

    // Finalize the clock cycle corresponding to the END operation.
    finalize_clock_cycle_with_continuation(processor, tracer, stopper, || {
        Some(Continuation::AfterExitDecorators(node_id))
    })?;

    processor.execute_after_exit_decorators(node_id, current_forest, host)
}
