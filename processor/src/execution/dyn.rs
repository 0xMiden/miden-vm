use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE};

use crate::{
    BreakReason, ContextId, Host, MapExecErr, Stopper,
    continuation_stack::{Continuation, ContinuationStack},
    execution::{
        InternalBreakReason, finalize_clock_cycle, finalize_clock_cycle_with_continuation,
        get_next_ctx_id,
    },
    mast::{MastForest, MastNodeId},
    processor::{MemoryInterface, Processor, StackInterface, SystemInterface},
    tracer::Tracer,
};

// DYN NODE PROCESSING
// ================================================================================================

/// Executes a Dyn node from the start.
#[inline(always)]
pub(super) fn start_dyn_node<P, S, T>(
    processor: &mut P,
    current_node_id: MastNodeId,
    current_forest: &mut Arc<MastForest>,
    continuation_stack: &mut ContinuationStack,
    host: &mut impl Host,
    tracer: &mut T,
    stopper: &S,
) -> ControlFlow<InternalBreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
    T: Tracer<Processor = P>,
{
    tracer.start_clock_cycle(
        processor,
        Continuation::StartNode(current_node_id),
        continuation_stack,
        current_forest,
    );

    // Execute decorators that should be executed before entering the node
    processor
        .execute_before_enter_decorators(current_node_id, current_forest, host)
        .map_break(InternalBreakReason::from)?;

    let dyn_node = current_forest[current_node_id].unwrap_dyn();

    // Retrieve callee hash from memory, using stack top as the memory address.
    let callee_hash = {
        let ctx = processor.system().ctx();
        let clk = processor.system().clock();
        let mem_addr = processor.stack().get(0);

        let word = match processor.memory_mut().read_word(ctx, mem_addr, clk).map_exec_err(
            current_forest,
            current_node_id,
            host,
        ) {
            Ok(w) => w,
            Err(err) => {
                return ControlFlow::Break(BreakReason::Err(err).into());
            },
        };
        tracer.record_memory_read_word(
            word,
            mem_addr,
            processor.system().ctx(),
            processor.system().clock(),
        );

        word
    };

    // Drop the memory address from the stack. This needs to be done before saving the context.
    processor.stack_mut().decrement_size();
    tracer.decrement_stack_size();

    // For dyncall,
    // - save the context and reset it,
    // - initialize the frame pointer in memory for the new context.
    if dyn_node.is_dyncall() {
        let new_ctx: ContextId = get_next_ctx_id(processor);

        // Save the current state, and update the system registers.
        processor.save_context_and_truncate_stack(tracer);

        processor.system_mut().set_ctx(new_ctx);
        processor.system_mut().set_caller_hash(callee_hash);

        // Initialize the frame pointer in memory for the new context.
        if let Err(err) = processor
            .memory_mut()
            .write_element(new_ctx, FMP_ADDR, FMP_INIT_VALUE)
            .map_exec_err(current_forest, current_node_id, host)
        {
            return ControlFlow::Break(BreakReason::Err(err).into());
        }
        tracer.record_memory_write_element(
            FMP_INIT_VALUE,
            FMP_ADDR,
            new_ctx,
            processor.system().clock(),
        );
    };

    // Update continuation stack
    // -----------------------------
    continuation_stack.push_finish_dyn(current_node_id);

    // if the callee is not in the program's MAST forest, then we need to break to allow the
    // implementing processor to fetch it (possibly asynchronously in an external library in the
    // host).
    match current_forest.find_procedure_root(callee_hash) {
        Some(callee_id) => {
            continuation_stack.push_start_node(callee_id);
        },
        None => {
            // This is a sans-IO point: we cannot proceed with loading the MAST forest, since some
            // processors need this to be done asynchronously. Thus, we break here and make the
            // implementing processor handle the loading in the outer execution loop. When done, the
            // processor *must* call `finish_load_mast_forest_from_dyn_start()` below for execution
            // to proceed properly.
            return ControlFlow::Break(InternalBreakReason::LoadMastForestFromDyn {
                dyn_node_id: current_node_id,
                callee_hash,
            });
        },
    }

    // Finalize the clock cycle corresponding to the DYN or DYNCALL operation.
    finalize_clock_cycle(processor, tracer, stopper, current_forest)
        .map_break(InternalBreakReason::from)
}

/// Function to be called after [`InternalBreakReason::LoadMastForestFromDyn`] is handled. See the
/// documentation of that enum variant for more details.
pub fn finish_load_mast_forest_from_dyn_start<P, S, T>(
    root_id: MastNodeId,
    new_forest: Arc<MastForest>,
    processor: &mut P,
    current_forest: &mut Arc<MastForest>,
    continuation_stack: &mut ContinuationStack,
    tracer: &mut T,
    stopper: &S,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
    T: Tracer<Processor = P>,
{
    tracer.record_mast_forest_resolution(root_id, &new_forest);

    // Save the old forest: the continuation from start_clock_cycle references nodes in it.
    let old_forest = Arc::clone(current_forest);

    // Push current forest to the continuation stack so that we can return to it
    continuation_stack.push_enter_forest(Arc::clone(current_forest));

    // Push the root node of the external MAST forest onto the continuation stack.
    continuation_stack.push_start_node(root_id);

    // Set the new MAST forest as current
    *current_forest = new_forest;

    // Finalize the clock cycle corresponding to the DYN or DYNCALL operation. We pass the old
    // forest because the continuation was set during start_clock_cycle, which referenced the old
    // forest.
    finalize_clock_cycle(processor, tracer, stopper, &old_forest)
}

/// Executes the finish phase of a Dyn node.
#[inline(always)]
pub(super) fn finish_dyn_node<P, S, T>(
    processor: &mut P,
    node_id: MastNodeId,
    current_forest: &Arc<MastForest>,
    continuation_stack: &mut ContinuationStack,
    host: &mut impl Host,
    tracer: &mut T,
    stopper: &S,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
    T: Tracer<Processor = P>,
{
    tracer.start_clock_cycle(
        processor,
        Continuation::FinishDyn(node_id),
        continuation_stack,
        current_forest,
    );

    let dyn_node = current_forest[node_id].unwrap_dyn();
    // For dyncall, restore the context.
    if dyn_node.is_dyncall()
        && let Err(e) = processor.restore_context(tracer)
    {
        return ControlFlow::Break(BreakReason::Err(e.with_context(current_forest, node_id, host)));
    }

    // Finalize the clock cycle corresponding to the END operation.
    finalize_clock_cycle_with_continuation(
        processor,
        tracer,
        stopper,
        || Some(Continuation::AfterExitDecorators(node_id)),
        current_forest,
    )?;

    processor.execute_after_exit_decorators(node_id, current_forest, host)
}
