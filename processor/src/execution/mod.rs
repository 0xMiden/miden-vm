use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{
    Word,
    mast::{MastForest, MastNode, MastNodeId},
    program::Kernel,
};

use crate::{
    ContextId, Host, Stopper,
    continuation_stack::{Continuation, ContinuationStack},
    fast::step::BreakReason,
    processor::{Processor, SystemInterface},
    tracer::{OperationHelperRegisters, Tracer},
};

mod basic_block;
mod call;
mod r#dyn;
mod external;
mod join;
mod r#loop;
mod split;

mod operations;

// RE-EXPORTS
// ================================================================================================

pub(crate) use basic_block::finish_emit_op_execution;
pub(crate) use r#dyn::finish_load_mast_forest_from_dyn_start;
pub(crate) use external::finish_load_mast_forest_from_external;
pub(crate) use operations::execute_sync_op;

// MAIN EXECUTION FUNCTION
// ================================================================================================

/// Executes the main execution loop given an abstract processor until a break condition is met.
///
/// By "main execution loop", we mean the loop that fetches the top continuation from the provided
/// continuation stack, executes it (possibly pushing new continuations onto the stack), and checks
/// the stopper after each clock cycle to see whether execution should stop. Execution is complete
/// when `ControlFlow::Continue` is returned, at which point the implementing processor can inspect
/// the final state of the processor and/or tracer.
///
/// # Tracing
///
/// Different processor implementations will need to record different pieces of information as the
/// the program is executed. For example, the [`crate::fast::FastProcessor::execute_for_trace`]
/// execution mode needs to build a [`crate::fast::execution_tracer::TraceGenerationContext`] which
/// records information necessary to build the trace at each clock cycle, while the
/// [`crate::parallel::core_trace_fragment::CoreTraceFragmentFiller`] needs to build the trace
/// essentially by recording the processor state at each clock cycle. For this purpose, the
/// [`Self::execute_impl`] method takes in [`Tracer`] argument that abstracts away the "information
/// recording" logic (or "tracing") for each processor implementation. Note that the same processor
/// implementation is also free to use different tracers for different execution modes.
///
/// # Stopping
///
/// Execution can be stopped at any clock cycle based on user-defined conditions. For this purpose,
/// the [`Self::execute_impl`] method takes in a [`Stopper`] argument that is queried after each
/// clock cycle to determine whether execution should stop. This is useful for implementing stepping
/// modes (e.g., step-by-step execution), or executing a predetermined number of clock cycles (e.g.,
/// in trace generation, where separate trace fragments are generated concurrently).
///
/// # Sans-IO
///
/// In addition to the stopper, execution can also be interrupted by operations that may require
/// asynchronous execution outside of the main loop. We refer to this general pattern as "sans-IO".
/// Each such operation has their own [`InternalBreakReason`] enum variant, and a corresponding
/// "finish" function (e.g., [`finish_emit_op_execution`] for the `Emit` break reason) that must be
/// called to complete the execution of the operation after the main loop has been interrupted, and
/// before calling [`Self::execute_impl`] again.
///
/// In pseudo-code, the general pattern when implementing program execution in a processor is as
/// follows:
///
/// ```ignore
/// let mut continuation_stack = ...;
/// let mut current_forest = ...;
/// let kernel = ...;
/// let mut host = ...;
/// let mut tracer = ...;
/// let stopper = ...;
///
/// while let ControlFlow::Break(internal_break_reason) = self.execute_impl() {
///     match internal_break_reason {
///         InternalBreakReason::User(reason) => {
///             // Handle user-initiated break (e.g., propagate break reason)
///         },
///         InternalBreakReason::Emit { basic_block_node_id, continuation } => {
///             // Handle Emit operation (e.g., call `Host::on_event`)
///             self.op_emit(...);
///    
///             // As per `InternalBreakReason::Emit` documentation, we call `finish_emit_op_execution`
///             // to complete the execution of the Emit operation.
///             finish_emit_op_execution(...);
///         },
///         InternalBreakReason::LoadMastForestFromDyn { dyn_node_id, callee_hash } => {
///             // load MAST forest containing the callee procedure
///             let (procedure_id, new_forest) = self.load_mast_forest(...);
///    
///             // As per `InternalBreakReason::LoadMastForestFromDyn` documentation, we call
///             // `finish_load_mast_forest_from_dyn_start` to complete the execution of the operation.
///             finish_load_mast_forest_from_dyn_start(...);
///         },
///         InternalBreakReason::LoadMastForestFromExternal { external_node_id, procedure_hash } => {
///             // load MAST forest containing the callee procedure
///             let (procedure_id, new_forest) = self.load_mast_forest(...);
///    
///             // As per `InternalBreakReason::LoadMastForestFromExternal` documentation, we call
///             // `finish_load_mast_forest_from_external_start` to complete the execution of the operation.
///             finish_load_mast_forest_from_external_start(...);
///         },
///     }
/// }
/// ```
pub(crate) fn execute_impl<P, S, T>(
    processor: &mut P,
    continuation_stack: &mut ContinuationStack,
    current_forest: &mut Arc<MastForest>,
    kernel: &Kernel,
    host: &mut impl Host,
    tracer: &mut T,
    stopper: &S,
) -> ControlFlow<InternalBreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
    T: Tracer<Processor = P>,
{
    while let Some(continuation) = continuation_stack.pop_continuation() {
        match continuation {
            Continuation::StartNode(node_id) => {
                let node = current_forest.get_node_by_id(node_id).unwrap();

                match node {
                    MastNode::Block(basic_block_node) => {
                        basic_block::execute_basic_block_node_from_start(
                            processor,
                            basic_block_node,
                            node_id,
                            host,
                            continuation_stack,
                            current_forest,
                            tracer,
                            stopper,
                        )?
                    },
                    MastNode::Join(join_node) => join::start_join_node(
                        processor,
                        join_node,
                        node_id,
                        current_forest,
                        continuation_stack,
                        host,
                        tracer,
                        stopper,
                    )
                    .map_break(InternalBreakReason::from)?,
                    MastNode::Split(split_node) => split::start_split_node(
                        processor,
                        split_node,
                        node_id,
                        current_forest,
                        continuation_stack,
                        host,
                        tracer,
                        stopper,
                    )
                    .map_break(InternalBreakReason::from)?,
                    MastNode::Loop(loop_node) => r#loop::start_loop_node(
                        processor,
                        loop_node,
                        node_id,
                        current_forest,
                        continuation_stack,
                        host,
                        tracer,
                        stopper,
                    )
                    .map_break(InternalBreakReason::from)?,
                    MastNode::Call(call_node) => call::start_call_node(
                        processor,
                        call_node,
                        node_id,
                        kernel,
                        current_forest,
                        continuation_stack,
                        host,
                        tracer,
                        stopper,
                    )
                    .map_break(InternalBreakReason::from)?,
                    MastNode::Dyn(_) => r#dyn::start_dyn_node(
                        processor,
                        node_id,
                        current_forest,
                        continuation_stack,
                        host,
                        tracer,
                        stopper,
                    )?,
                    MastNode::External(_) => {
                        external::execute_external_node(processor, node_id, current_forest, host)?
                    },
                }
            },
            Continuation::FinishJoin(node_id) => join::finish_join_node(
                processor,
                node_id,
                current_forest,
                continuation_stack,
                host,
                tracer,
                stopper,
            )
            .map_break(InternalBreakReason::from)?,
            Continuation::FinishSplit(node_id) => split::finish_split_node(
                processor,
                node_id,
                current_forest,
                continuation_stack,
                host,
                tracer,
                stopper,
            )
            .map_break(InternalBreakReason::from)?,
            Continuation::FinishLoop { node_id, was_entered } => r#loop::finish_loop_node(
                processor,
                was_entered,
                node_id,
                current_forest,
                continuation_stack,
                host,
                tracer,
                stopper,
            )
            .map_break(InternalBreakReason::from)?,
            Continuation::FinishCall(node_id) => call::finish_call_node(
                processor,
                node_id,
                current_forest,
                continuation_stack,
                host,
                tracer,
                stopper,
            )
            .map_break(InternalBreakReason::from)?,
            Continuation::FinishDyn(node_id) => r#dyn::finish_dyn_node(
                processor,
                node_id,
                current_forest,
                continuation_stack,
                host,
                tracer,
                stopper,
            )
            .map_break(InternalBreakReason::from)?,
            Continuation::FinishExternal(node_id) => {
                // Execute after_exit decorators when returning from an external node
                // Note: current_forest should already be restored by EnterForest continuation
                processor
                    .execute_after_exit_decorators(node_id, current_forest, host)
                    .map_break(InternalBreakReason::from)?;
            },
            Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                let basic_block_node =
                    current_forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

                basic_block::execute_basic_block_node_from_op_idx(
                    processor,
                    basic_block_node,
                    node_id,
                    batch_index,
                    op_idx_in_batch,
                    host,
                    continuation_stack,
                    current_forest,
                    tracer,
                    stopper,
                )?
            },
            Continuation::Respan { node_id, batch_index } => {
                let basic_block_node =
                    current_forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

                basic_block::execute_basic_block_node_from_batch(
                    processor,
                    basic_block_node,
                    node_id,
                    batch_index,
                    host,
                    continuation_stack,
                    current_forest,
                    tracer,
                    stopper,
                )?
            },
            Continuation::FinishBasicBlock(node_id) => {
                let basic_block_node =
                    current_forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

                basic_block::finish_basic_block(
                    processor,
                    basic_block_node,
                    node_id,
                    current_forest,
                    host,
                    continuation_stack,
                    tracer,
                    stopper,
                )
                .map_break(InternalBreakReason::from)?
            },
            Continuation::EnterForest(previous_forest) => {
                // Restore the previous forest
                *current_forest = previous_forest;
            },
            Continuation::AfterExitDecorators(node_id) => processor
                .execute_after_exit_decorators(node_id, current_forest, host)
                .map_break(InternalBreakReason::from)?,
            Continuation::AfterExitDecoratorsBasicBlock(node_id) => {
                let basic_block_node =
                    current_forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

                processor
                    .execute_end_of_block_decorators(
                        basic_block_node,
                        node_id,
                        current_forest,
                        host,
                    )
                    .map_break(InternalBreakReason::from)?;
                processor
                    .execute_after_exit_decorators(node_id, current_forest, host)
                    .map_break(InternalBreakReason::from)?;
            },
        }
    }

    ControlFlow::Continue(())
}

// INTERNAL BREAK REASON
// ================================================================================================

/// Represents either a user-initiated break or a break due to an operation that (potentially)
/// requires asynchronous handling outside of the main execution loop.
///
/// Each variant (except for `User`) has an associated continuation that can be used to resume
/// execution after the operation has been handled.
///
/// # Emit
///
/// - *Function to call after handling*: [`finish_emit_op_execution`]
///
/// The `Emit` variant is used to break execution when an `Emit` operation is encountered. The
/// associated data includes the ID of the basic block node where the `Emit` operation was executed
/// and the continuation that should be passed to [`finish_emit_op_execution`] to resume execution
/// after the host has processed the emitted event.
///
/// Handling an `Emit` operation typically involves invoking the host environment to process the
/// emitted event. After the host has processed the event, the processor *must* call
/// [`finish_emit_op_execution`] to complete the execution of the `Emit` operation and resume
/// execution immediately after the `Emit` operation.
///
/// # LoadMastForestFromDyn
///
/// - *Function to call after handling*: [`finish_load_mast_forest_from_dyn_start`]
///
/// The `LoadMastForestFromDyn` variant is used to break execution when `DynNode` is encountered
/// that requires loading a MAST forest containing a given procedure. The associated data includes
/// the ID of the dynamic node and the hash of the callee procedure to be loaded.
///
/// Handling this operation typically involves loading the MAST forest from the host environment.
/// After the MAST forest has been loaded, the processor *must* call
/// [`finish_load_mast_forest_from_dyn_start`] to complete the execution of the operation and resume
/// execution with the first operation of the called procedure.
///
/// # LoadMastForestFromExternal
///
/// - *Function to call after handling*: [`finish_load_mast_forest_from_external`]
///
/// The `LoadMastForestFromExternal` variant is used to break execution when an `ExternalNode` is
/// encountered that requires loading a MAST forest containing a given procedure. The associated
/// data includes the ID of the external node and the hash of the procedure to be loaded.
///
/// Handling this operation typically involves loading the MAST forest from the host environment.
/// After the MAST forest has been loaded, the processor *must* call
/// [`finish_load_mast_forest_from_external`] to complete the execution of the operation and resume
/// execution with the first operation of the called procedure.
pub enum InternalBreakReason {
    User(BreakReason),
    Emit {
        basic_block_node_id: MastNodeId,
        continuation: Continuation,
    },
    LoadMastForestFromDyn {
        dyn_node_id: MastNodeId,
        callee_hash: Word,
    },
    LoadMastForestFromExternal {
        external_node_id: MastNodeId,
        procedure_hash: Word,
    },
}

impl From<BreakReason> for InternalBreakReason {
    fn from(reason: BreakReason) -> Self {
        Self::User(reason)
    }
}

// HELPERS
// ================================================================================================

/// This function marks the end of a clock cycle.
///
/// Delegates to [`finalize_clock_cycle_with_continuation`] with a continuation closure that returns
/// no continuation.
#[inline(always)]
fn finalize_clock_cycle<P, S, T>(
    processor: &mut P,
    tracer: &mut T,
    stopper: &S,
    current_forest: &Arc<MastForest>,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
    T: Tracer<Processor = P>,
{
    finalize_clock_cycle_with_continuation(processor, tracer, stopper, || None, current_forest)
}

/// This function marks the end of a clock cycle.
///
/// Delegates to [`finalize_clock_cycle_with_continuation_and_op_helpers`] with the `Empty` variant
/// of [`OperationHelperRegisters`].
#[inline(always)]
fn finalize_clock_cycle_with_continuation<P, S, T>(
    processor: &mut P,
    tracer: &mut T,
    stopper: &S,
    continuation_after_stop: impl FnOnce() -> Option<Continuation>,
    current_forest: &Arc<MastForest>,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
    T: Tracer<Processor = P>,
{
    finalize_clock_cycle_with_continuation_and_op_helpers(
        processor,
        tracer,
        stopper,
        continuation_after_stop,
        OperationHelperRegisters::Empty,
        current_forest,
    )
}

/// This function marks the end of a clock cycle.
///
/// Specifically, it
/// 1. Calls `tracer.finish_clock_cycle()` to signal the end of the clock cycle to the tracer.
/// 2. Increments the processor's clock by 1.
/// 3. Checks if execution should stop using the provided `stopper`, providing the computed
///    continuation (from `continuation_after_stop()`) to the `BreakReason::Stopped` variant.
///
/// The `op_helper_registers` argument encodes the helper registers returned by [`execute_sync_op`]
/// when executing synchronous operations; pass in the `Empty` variant otherwise. These registers
/// are passed to the tracer when finalizing the clock cycle.
///
/// A continuation is computed using `continuation_after_stop()` in cases where simply resuming
/// execution from the top of the continuation stack is not sufficient to continue execution
/// correctly. For example, when stopping execution in the middle of a basic block, we need to
/// provide a `ResumeBasicBlock` continuation to ensure that execution resumes at the correct
/// operation within the basic block (i.e. the operation right after the one that was last executed
/// before being stopped). No continuation is provided in case of error, since it is expected that
/// execution will not be resumed.
#[inline(always)]
fn finalize_clock_cycle_with_continuation_and_op_helpers<P, S, T>(
    processor: &mut P,
    tracer: &mut T,
    stopper: &S,
    continuation_after_stop: impl FnOnce() -> Option<Continuation>,
    op_helper_registers: OperationHelperRegisters,
    current_forest: &Arc<MastForest>,
) -> ControlFlow<BreakReason>
where
    P: Processor,
    S: Stopper<Processor = P>,
    T: Tracer<Processor = P>,
{
    // Signal the end of clock cycle to tracer (before incrementing processor clock).
    tracer.finalize_clock_cycle(processor, op_helper_registers, current_forest);

    // Increment the processor clock.
    processor.system_mut().increment_clock();

    stopper.should_stop(processor, continuation_after_stop)
}

/// Returns the next context ID that would be created given the current state.
///
/// Note: This only applies to the context created upon a `CALL` or `DYNCALL` operation;
/// specifically the `SYSCALL` operation doesn't apply as it always goes back to the root
/// context.
fn get_next_ctx_id(processor: &impl Processor) -> ContextId {
    (processor.system().clock() + 1).into()
}
