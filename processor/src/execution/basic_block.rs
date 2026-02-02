use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{
    mast::{BasicBlockNode, MastForest, MastNodeId},
    operations::Operation,
};

use crate::{
    Host, Stopper,
    continuation_stack::{Continuation, ContinuationStack},
    execution::{InternalBreakReason, execute_sync_op, finalize_clock_cycle_with_continuation},
    fast::step::BreakReason,
    processor::Processor,
    tracer::Tracer,
};

/// Execute the given basic block node.
#[inline(always)]
pub(super) fn execute_basic_block_node_from_start<P, S>(
    processor: &mut P,
    basic_block_node: &BasicBlockNode,
    node_id: MastNodeId,
    host: &mut impl Host,
    continuation_stack: &mut ContinuationStack,
    current_forest: &Arc<MastForest>,
    tracer: &mut impl Tracer,
    stopper: &S,
) -> ControlFlow<InternalBreakReason>
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
    processor
        .execute_before_enter_decorators(node_id, current_forest, host)
        .map_break(InternalBreakReason::from)?;

    // Finalize the clock cycle corresponding to the SPAN operation.
    finalize_clock_cycle_with_continuation(processor, tracer, stopper, || {
        Some(Continuation::ResumeBasicBlock {
            node_id,
            batch_index: 0,
            op_idx_in_batch: 0,
        })
    })
    .map_break(InternalBreakReason::from)?;

    // Execute the first batch separately, since `execute_basic_block_node_from_batch` executes
    // starting from the RESPAN preceding the batch (and there is no such RESPAN before the first
    // batch).
    if !basic_block_node.op_batches().is_empty() {
        execute_op_batch(
            processor,
            basic_block_node,
            0,
            0,
            0,
            host,
            continuation_stack,
            current_forest,
            tracer,
            stopper,
        )?;
    }

    // Execute the rest of the batches.
    execute_basic_block_node_from_batch(
        processor,
        basic_block_node,
        node_id,
        1,
        host,
        continuation_stack,
        current_forest,
        tracer,
        stopper,
    )
}

/// Executes the give basic block node starting from the specified operation index within the
/// specified batch.
#[inline(always)]
pub(super) fn execute_basic_block_node_from_op_idx<P, S>(
    processor: &mut P,
    basic_block_node: &BasicBlockNode,
    node_id: MastNodeId,
    start_batch_index: usize,
    start_op_idx_in_batch: usize,
    host: &mut impl Host,
    continuation_stack: &mut ContinuationStack,
    current_forest: &Arc<MastForest>,
    tracer: &mut impl Tracer,
    stopper: &S,
) -> ControlFlow<InternalBreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
{
    let batch_offset_in_block = basic_block_node
        .op_batches()
        .iter()
        .take(start_batch_index)
        .map(|batch| batch.ops().len())
        .sum();

    // Finish executing the specified batch from the given op index
    execute_op_batch(
        processor,
        basic_block_node,
        start_batch_index,
        start_op_idx_in_batch,
        batch_offset_in_block,
        host,
        continuation_stack,
        current_forest,
        tracer,
        stopper,
    )?;

    // Execute the rest of the batches
    execute_basic_block_node_from_batch(
        processor,
        basic_block_node,
        node_id,
        start_batch_index + 1,
        host,
        continuation_stack,
        current_forest,
        tracer,
        stopper,
    )
}

/// Executes the give basic block node starting from the RESPAN preceding the specified batch.
#[inline(always)]
pub(super) fn execute_basic_block_node_from_batch<P, S>(
    processor: &mut P,
    basic_block_node: &BasicBlockNode,
    node_id: MastNodeId,
    start_batch_index: usize,
    host: &mut impl Host,
    continuation_stack: &mut ContinuationStack,
    current_forest: &Arc<MastForest>,
    tracer: &mut impl Tracer,
    stopper: &S,
) -> ControlFlow<InternalBreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
{
    let mut batch_offset_in_block = basic_block_node
        .op_batches()
        .iter()
        .take(start_batch_index)
        .map(|batch| batch.ops().len())
        .sum();

    for (batch_index, op_batch) in
        basic_block_node.op_batches().iter().enumerate().skip(start_batch_index)
    {
        {
            // Start clock cycle corresponding to the RESPAN operation before the batch.
            tracer.start_clock_cycle(
                processor,
                Continuation::Respan { node_id, batch_index },
                continuation_stack,
                current_forest,
            );

            // Finalize the clock cycle corresponding to the RESPAN operation.
            //
            // Note: in the continuation closure, the continuation encodes resuming from the start
            // of the batch *after* the RESPAN operation. This is because the continuation encodes
            // what happens *after* the clock is incremented. For example, if we were to put a
            // `Continuation::Respan` here instead, and execution was stopped after this RESPAN,
            // then the next call to `Processor::execute_impl()` would re-execute the RESPAN.
            finalize_clock_cycle_with_continuation(processor, tracer, stopper, || {
                Some(Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch: 0 })
            })
            .map_break(InternalBreakReason::from)?;
        }

        // Execute the batch.
        execute_op_batch(
            processor,
            basic_block_node,
            batch_index,
            0,
            batch_offset_in_block,
            host,
            continuation_stack,
            current_forest,
            tracer,
            stopper,
        )?;
        batch_offset_in_block += op_batch.ops().len();
    }

    finish_basic_block(
        processor,
        basic_block_node,
        node_id,
        current_forest,
        host,
        continuation_stack,
        tracer,
        stopper,
    )
    .map_break(InternalBreakReason::from)
}

/// Execute the finish phase of a basic block node.
#[inline(always)]
pub(super) fn finish_basic_block<P, S>(
    processor: &mut P,
    basic_block_node: &BasicBlockNode,
    node_id: MastNodeId,
    current_forest: &Arc<MastForest>,
    host: &mut impl Host,
    continuation_stack: &mut ContinuationStack,
    tracer: &mut impl Tracer,
    stopper: &S,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
{
    tracer.start_clock_cycle(
        processor,
        Continuation::FinishBasicBlock(node_id),
        continuation_stack,
        current_forest,
    );

    // Finalize the clock cycle corresponding to the END operation.
    finalize_clock_cycle_with_continuation(processor, tracer, stopper, || {
        Some(Continuation::AfterExitDecoratorsBasicBlock(node_id))
    })?;

    processor.execute_end_of_block_decorators(basic_block_node, node_id, current_forest, host)?;
    processor.execute_after_exit_decorators(node_id, current_forest, host)
}

// HELPERS
// ================================================================================================

/// Executes a single operation batch within a basic block node, starting from the operation
/// index `start_op_idx`.
#[inline(always)]
fn execute_op_batch<P, S>(
    processor: &mut P,
    basic_block: &BasicBlockNode,
    batch_index: usize,
    start_op_idx: usize,
    batch_offset_in_block: usize,
    host: &mut impl Host,
    continuation_stack: &mut ContinuationStack,
    current_forest: &Arc<MastForest>,
    tracer: &mut impl Tracer,
    stopper: &S,
) -> ControlFlow<InternalBreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
{
    let batch = &basic_block.op_batches()[batch_index];

    // Get the node ID once since it doesn't change within the loop
    let node_id = basic_block
        .linked_id()
        .expect("basic block node should be linked when executing operations");

    // Execute operations in the batch one by one
    for (op_idx_in_batch, op) in batch.ops().iter().enumerate().skip(start_op_idx) {
        let op_idx_in_block = batch_offset_in_block + op_idx_in_batch;

        tracer.start_clock_cycle(
            processor,
            Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch },
            continuation_stack,
            current_forest,
        );

        processor
            .execute_decorators_for_op(node_id, op_idx_in_block, current_forest, host)
            .map_break(InternalBreakReason::from)?;

        // Execute the operation.
        {
            match op {
                Operation::Emit => {
                    // This is a sans-IO point: we cannot proceed with handling the Emit operation,
                    // since some processors need this to be done asynchronously. Thus, we break
                    // here and make the implementing processor handle the loading in the outer
                    // execution loop. When done, the processor *must* call
                    // `finish_emit_op_execution()` below for execution to proceed properly.
                    return ControlFlow::Break(InternalBreakReason::Emit {
                        basic_block_node_id: node_id,
                        continuation: get_continuation_after_executing_operation(
                            basic_block,
                            node_id,
                            batch_index,
                            op_idx_in_batch,
                        ),
                    });
                },
                _ => {
                    // If the operation is not an Emit, we execute it normally.
                    if let Err(err) = execute_sync_op(
                        processor,
                        op,
                        current_forest,
                        node_id,
                        host,
                        tracer,
                        op_idx_in_block,
                    ) {
                        return ControlFlow::Break(BreakReason::Err(err).into());
                    }
                },
            }
        }

        // Finalize the clock cycle corresponding to the operation.
        finalize_clock_cycle_with_continuation(processor, tracer, stopper, || {
            Some(get_continuation_after_executing_operation(
                basic_block,
                node_id,
                batch_index,
                op_idx_in_batch,
            ))
        })
        .map_break(InternalBreakReason::from)?;
    }

    ControlFlow::Continue(())
}

/// Given the current operation being executed within a basic block, returns the appropriate
/// continuation to add to the continuation stack if execution is stopped right after execution the
/// operation (node_id, batch_index, op_idx_in_batch).
///
/// That is, `op_idx_in_batch` is the index of the operation that was just executed within the batch
/// `batch_index` of the basic block `basic_block_node`.
fn get_continuation_after_executing_operation(
    basic_block_node: &BasicBlockNode,
    node_id: MastNodeId,
    batch_index: usize,
    op_idx_in_batch: usize,
) -> Continuation {
    let last_op_idx_in_batch = basic_block_node.op_batches()[batch_index].ops().len() - 1;
    let last_batch_idx_in_block = basic_block_node.num_op_batches() - 1;

    if op_idx_in_batch < last_op_idx_in_batch {
        // The operation that just executed was not the last one in the batch, so continue within
        // the same batch at the following operation
        Continuation::ResumeBasicBlock {
            node_id,
            batch_index,
            op_idx_in_batch: op_idx_in_batch + 1,
        }
    } else if batch_index < last_batch_idx_in_block {
        // The operation that just executed was the last one in the batch, but there are more
        // batches to execute in this basic block, so continue at the RESPAN before the next batch
        Continuation::Respan { node_id, batch_index: batch_index + 1 }
    } else {
        // The operation that just executed was the last one in the last batch, so finish the basic
        // block
        Continuation::FinishBasicBlock(node_id)
    }
}

// EXPORTS
// ================================================================================================

/// Function to be called after [`InternalBreakReason::Emit`] is handled. See the documentation of
/// that enum variant for more details.
pub fn finish_emit_op_execution<P, S>(
    post_emit_continuation: Continuation,
    processor: &mut P,
    continuation_stack: &mut ContinuationStack,
    tracer: &mut impl Tracer,
    stopper: &S,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
{
    // When we enter here, the `continuation_stack` top contains the continuation to execute *after*
    // the basic block that contained the `Emit` operation (i.e. after all operations are executed,
    // and the finish phase of the basic block is complete). Hence, we need to add the
    // `post_emit_continuation` on top of the continuation stack so that execution resumes at the
    // operation right after the `Emit`.
    //
    // However, if the `stopper` stops execution in `finalize_clock_cycle_with_continuation()`, the
    // stopper will already include the `post_emit_continuation` in the break reason (which the
    // processor will then push onto the continuation stack). Hence, in this case, we do not need to
    // push the `post_emit_continuation` ourselves. In other words, *only if* the
    // `finalize_clock_cycle_with_continuation()` completes successfully do we need to push the
    // `post_emit_continuation` ourselves.

    finalize_clock_cycle_with_continuation(processor, tracer, stopper, {
        let post_emit_continuation = post_emit_continuation.clone();
        || Some(post_emit_continuation)
    })?;

    continuation_stack.push_continuation(post_emit_continuation);

    ControlFlow::Continue(())
}
