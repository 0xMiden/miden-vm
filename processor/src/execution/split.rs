use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{
    ONE, ZERO,
    mast::{MastForest, MastNodeId, SplitNode},
};

use crate::{
    Host, Stopper,
    continuation_stack::{Continuation, ContinuationStack},
    execution::{finalize_clock_cycle, finalize_clock_cycle_with_continuation},
    fast::step::BreakReason,
    operation::OperationError,
    processor::{Processor, StackInterface},
    tracer::Tracer,
};

/// Executes a Split node from the start.
#[inline(always)]
pub(super) fn start_split_node<P, S>(
    processor: &mut P,
    split_node: &SplitNode,
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

    let condition = processor.stack().get(0);

    // drop the condition from the stack
    processor.stack_mut().decrement_size(tracer);

    // execute the appropriate branch
    continuation_stack.push_finish_split(node_id);
    if condition == ONE {
        continuation_stack.push_start_node(split_node.on_true());
    } else if condition == ZERO {
        continuation_stack.push_start_node(split_node.on_false());
    } else {
        let err = OperationError::NotBinaryValueIf { value: condition };
        return ControlFlow::Break(BreakReason::Err(err.with_context(
            current_forest,
            node_id,
            host,
        )));
    };

    // Finalize the clock cycle corresponding to the SPLIT operation.
    finalize_clock_cycle(processor, tracer, stopper)
}

/// Executes the finish phase of a Split node.
#[inline(always)]
pub(super) fn finish_split_node<P, S>(
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
        Continuation::FinishSplit(node_id),
        continuation_stack,
        current_forest,
    );

    // Finalize the clock cycle corresponding to the END operation.
    finalize_clock_cycle_with_continuation(processor, tracer, stopper, || {
        Some(Continuation::AfterExitDecorators(node_id))
    })?;

    processor.execute_after_exit_decorators(node_id, current_forest, host)
}
