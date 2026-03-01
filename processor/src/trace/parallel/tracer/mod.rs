use alloc::sync::Arc;

use miden_air::trace::{STACK_TRACE_WIDTH, SYS_TRACE_WIDTH};
use miden_core::program::MIN_STACK_DEPTH;

use super::{
    super::{
        decoder::block_stack::ExecutionContextInfo,
        trace_state::{
            BlockAddressReplay, BlockStackReplay, DecoderState, StackState, SystemState,
        },
    },
    core_trace_fragment::{BasicBlockContext, CoreTraceFragment},
    processor::ReplayProcessor,
};
use crate::{
    Felt, ONE, Word, ZERO,
    continuation_stack::{Continuation, ContinuationStack},
    mast::{MastForest, MastNode, MastNodeExt, MastNodeId},
    tracer::{OperationHelperRegisters, Tracer},
};

mod trace_row;

// CORE TRACE GENERATION TRACER
// ================================================================================================

/// A tracer implementation for generating a core trace fragment of a predetermined number of rows.
///
/// This tracer is used in conjunction with the [`ReplayProcessor`] to fill in trace rows for a
/// fragment of the execution. Trace rows are written in [`Tracer::finalize_clock_cycle`] after
/// collecting the necessary state in [`Tracer::start_clock_cycle`].
#[derive(Debug)]
pub(crate) struct CoreTraceGenerationTracer<'a> {
    /// The trace fragment being populated with rows by this tracer.
    fragment: &'a mut CoreTraceFragment<'a>,
    /// The index of the next row to write in the trace fragment.
    row_write_index: usize,

    /// The decoder state being replayed, tracking the current and parent block addresses.
    decoder_state: DecoderState,
    /// Replays the sequence of block addresses that were assigned during the initial execution.
    block_address_replay: BlockAddressReplay,
    /// Replays block stack push/pop operations (parent address and block context) from the
    /// initial execution.
    block_stack_replay: BlockStackReplay,

    /// Buffered stack trace row from the current clock cycle. Written to the fragment on the
    /// *next* clock cycle (since stack columns are one row behind), and returned via
    /// [`into_parts`](Self::into_parts) so the next fragment can continue from this state.
    stack_rows: Option<[Felt; STACK_TRACE_WIDTH]>,
    /// Buffered system trace row from the current clock cycle. Written to the fragment on the
    /// *next* clock cycle (since system columns are one row behind), and returned via
    /// [`into_parts`](Self::into_parts) so the next fragment can continue from this state.
    system_rows: Option<[Felt; SYS_TRACE_WIDTH]>,

    /// Execution context info captured at the beginning of a DYNCALL clock cycle (in
    /// [`start_clock_cycle`](Tracer::start_clock_cycle)) to be used when finalizing it.
    ctx_info: Option<ExecutionContextInfo>,
    /// Loop condition captured at the beginning of a `FinishLoop` clock cycle (in
    /// [`start_clock_cycle`](Tracer::start_clock_cycle)). `true` means the loop body will be
    /// re-executed (REPEAT); `false` means the loop is finished (END).
    finish_loop_condition: Option<bool>,
    /// Hash of the called procedure for `Dyn` nodes, captured at the beginning of a DYN clock
    /// cycle (in [`start_clock_cycle`](Tracer::start_clock_cycle)) to be used when finalizing
    /// it.
    dyn_callee_hash: Option<Word>,

    /// The continuation captured at the beginning of the clock cycle (in
    /// [`start_clock_cycle`](Tracer::start_clock_cycle)), describing what is being executed at
    /// this cycle.
    continuation: Option<Continuation>,
}

impl<'a> CoreTraceGenerationTracer<'a> {
    pub fn new(
        fragment: &'a mut CoreTraceFragment<'a>,
        decoder_state: DecoderState,
        block_address_replay: BlockAddressReplay,
        block_stack_replay: BlockStackReplay,
    ) -> Self {
        Self {
            fragment,
            row_write_index: 0,
            decoder_state,
            block_address_replay,
            block_stack_replay,
            stack_rows: None,
            system_rows: None,
            ctx_info: None,
            finish_loop_condition: None,
            dyn_callee_hash: None,
            continuation: None,
        }
    }

    /// Consumes this tracer and returns its final state.
    ///
    /// Returns a tuple containing:
    /// - The final stack trace row (or zeros if none was written).
    /// - The final system trace row (or zeros if none was written).
    /// - The number of trace rows that were built.
    pub fn into_parts(self) -> ([Felt; STACK_TRACE_WIDTH], [Felt; SYS_TRACE_WIDTH], usize) {
        let num_rows_built = self.row_write_index;

        (
            self.stack_rows.unwrap_or([ZERO; STACK_TRACE_WIDTH]),
            self.system_rows.unwrap_or([ZERO; SYS_TRACE_WIDTH]),
            num_rows_built,
        )
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Fills a trace row for a `StartNode` continuation based on the type of node being started.
    fn fill_start_row(
        &mut self,
        node_id: MastNodeId,
        processor: &ReplayProcessor,
        current_forest: &Arc<MastForest>,
    ) {
        let node = current_forest
            .get_node_by_id(node_id)
            .expect("invalid node ID stored in continuation");

        match node {
            MastNode::Block(basic_block_node) => {
                self.fill_basic_block_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    basic_block_node,
                );
            },
            MastNode::Join(join_node) => {
                self.fill_join_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    join_node,
                    current_forest,
                );
            },
            MastNode::Split(split_node) => {
                self.fill_split_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    split_node,
                    current_forest,
                );
            },
            MastNode::Loop(loop_node) => {
                self.fill_loop_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    loop_node,
                    current_forest,
                );
            },
            MastNode::Call(call_node) => {
                self.fill_call_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    call_node,
                    current_forest,
                );
            },
            MastNode::Dyn(dyn_node) => {
                let callee_hash = self
                    .dyn_callee_hash
                    .take()
                    .expect("dyn callee hash stored at start of clock cycle");

                if dyn_node.is_dyncall() {
                    let ctx_info = self.ctx_info.take().expect(
                        "execution context info stored at start of clock cycle for DYNCALL node",
                    );

                    self.fill_dyncall_start_trace_row(
                        &processor.system,
                        &processor.stack,
                        callee_hash,
                        ctx_info,
                    );
                } else {
                    self.fill_dyn_start_trace_row(&processor.system, &processor.stack, callee_hash);
                }
            },
            MastNode::External(_) => {
                unreachable!("The Tracer contract guarantees that external nodes do not occur here")
            },
        }
    }

    /// Returns the execution context info for a DYNCALL node, or `None` if the continuation does
    /// not represent a `StartNode` for a DYNCALL. The state of the processor is expected to be at
    /// the beginning of the DYNCALL execution (i.e., during `start_clock_cycle()`).
    ///
    /// Recall that DYNCALL drops the top stack element, which represents the memory address where
    /// the callee hash is stored. The execution context info is captured *after* the top stack
    /// element has been dropped, as per the semantics of DYNCALL.
    fn get_execution_context_for_dyncall(
        &self,
        current_forest: &MastForest,
        continuation: &Continuation,
        processor: &ReplayProcessor,
    ) -> Option<ExecutionContextInfo> {
        let Continuation::StartNode(node_id) = &continuation else {
            return None;
        };

        let node = current_forest
            .get_node_by_id(*node_id)
            .expect("invalid node ID stored in continuation");

        let MastNode::Dyn(dyn_node) = node else {
            return None;
        };

        if !dyn_node.is_dyncall() {
            return None;
        }

        let (stack_depth_after_drop, overflow_addr_after_drop) = if processor.stack.stack_depth()
            > MIN_STACK_DEPTH
        {
            // Stack is above minimum depth, so peek at the overflow replay for the post-pop
            // overflow address.
            let (_, overflow_addr_after_drop) =
                    processor.stack_overflow_replay.peek_replay_pop_overflow().expect("stack depth is above minimum, so we expect a corresponding overflow pop in the replay");
            let stack_depth_after_drop = processor.stack.stack_depth() - 1;

            (stack_depth_after_drop as u32, *overflow_addr_after_drop)
        } else {
            // Stack is at minimum depth already, so the overflow address is ZERO and the depth
            // remains the same after the drop.
            (processor.stack.stack_depth() as u32, ZERO)
        };

        Some(ExecutionContextInfo::new(
            processor.system.ctx,
            processor.system.fn_hash,
            stack_depth_after_drop,
            overflow_addr_after_drop,
        ))
    }

    /// Returns the loop condition sitting on top of the stack for a `FinishLoop` continuation, or
    /// `None` if the continuation is not a `FinishLoop`.
    ///
    /// The loop condition is `true` if the top of the stack equals ONE (meaning the loop body
    /// should be re-executed), and `false` otherwise (meaning the loop is finished).
    fn get_finish_loop_condition(
        &self,
        continuation: &Continuation,
        processor: &ReplayProcessor,
    ) -> Option<bool> {
        if let Continuation::FinishLoop { .. } = &continuation {
            let condition = processor.stack.get(0);
            return Some(condition == ONE);
        }

        None
    }

    /// Returns the callee hash for a `Dyn` node, or `None` if the continuation is not a
    /// `StartNode` for a `Dyn` node.
    ///
    /// The callee hash is read from the memory reads replay, as `Dyn` nodes read the procedure
    /// hash (as a word) from memory.
    fn get_dyn_callee_hash(
        &self,
        continuation: &Continuation,
        processor: &ReplayProcessor,
        current_forest: &MastForest,
    ) -> Option<Word> {
        if let Continuation::StartNode(node_id) = continuation {
            let node = current_forest
                .get_node_by_id(*node_id)
                .expect("invalid node ID stored in continuation");

            if let MastNode::Dyn(_) = node {
                let (word_read, _addr, _ctx, _clk) = processor
                    .memory_reads_replay
                    .iter_read_words()
                    .next()
                    .expect("dyn node reads the procedure hash (word) from memory");
                return Some(word_read);
            }
        }

        None
    }
}

// TRACER IMPLEMENTATION
// ================================================================================================

impl Tracer for CoreTraceGenerationTracer<'_> {
    type Processor = ReplayProcessor;

    fn start_clock_cycle(
        &mut self,
        processor: &ReplayProcessor,
        continuation: Continuation,
        _continuation_stack: &ContinuationStack,
        current_forest: &Arc<MastForest>,
    ) {
        // If this is a DYNCALL node, store execution context info needed when writing the trace
        // row in finalize_clock_cycle.
        self.ctx_info =
            self.get_execution_context_for_dyncall(current_forest, &continuation, processor);
        self.finish_loop_condition = self.get_finish_loop_condition(&continuation, processor);
        self.dyn_callee_hash = self.get_dyn_callee_hash(&continuation, processor, current_forest);

        // Store state for finalizing the clock cycle later.
        self.continuation = Some(continuation);
    }

    fn finalize_clock_cycle(
        &mut self,
        processor: &ReplayProcessor,
        op_helper_registers: OperationHelperRegisters,
        current_forest: &Arc<MastForest>,
    ) {
        use Continuation::*;

        match self.continuation.as_ref().expect("continuation stored at start of clock cycle") {
            StartNode(node_id) => {
                self.decoder_state.replay_node_start(
                    &mut self.block_address_replay,
                    &mut self.block_stack_replay,
                );

                self.fill_start_row(*node_id, processor, current_forest);
            },
            FinishJoin(node_id) => {
                let node = expect_node_in_forest(current_forest, *node_id);
                self.fill_end_trace_row(&processor.system, &processor.stack, node.digest());
            },
            FinishSplit(node_id) => {
                let node = expect_node_in_forest(current_forest, *node_id);
                self.fill_end_trace_row(&processor.system, &processor.stack, node.digest());
            },
            FinishLoop { node_id, was_entered: _ } => {
                let loop_condition = self.finish_loop_condition.take().expect(
                    "loop condition stored at start of clock cycle for FinishLoop continuation",
                );

                if loop_condition {
                    // Loop body is about to be re-executed, so fill in a REPEAT row.
                    let loop_node = current_forest
                        .get_node_by_id(*node_id)
                        .expect("node not found in forest")
                        .unwrap_loop();
                    let current_addr = self.decoder_state.current_addr;

                    self.fill_loop_repeat_trace_row(
                        &processor.system,
                        &processor.stack,
                        loop_node,
                        current_forest,
                        current_addr,
                    );
                } else {
                    // Loop is finished, so fill in an END row.
                    let node = expect_node_in_forest(current_forest, *node_id);
                    self.fill_end_trace_row(&processor.system, &processor.stack, node.digest());
                }
            },
            FinishCall(node_id) => {
                let node = expect_node_in_forest(current_forest, *node_id);
                self.fill_end_trace_row(&processor.system, &processor.stack, node.digest());
            },
            FinishDyn(node_id) => {
                let node = expect_node_in_forest(current_forest, *node_id);
                self.fill_end_trace_row(&processor.system, &processor.stack, node.digest());
            },
            ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                let basic_block_node = current_forest
                    .get_node_by_id(*node_id)
                    .expect("node not found in forest")
                    .unwrap_basic_block();

                let mut basic_block_context =
                    BasicBlockContext::new_at_op(basic_block_node, *batch_index, *op_idx_in_batch);
                let current_batch = &basic_block_node.op_batches()[*batch_index];
                let operation = current_batch.ops()[*op_idx_in_batch];
                let (_, op_idx_in_group) = current_batch
                    .op_idx_in_batch_to_group(*op_idx_in_batch)
                    .expect("invalid op index in batch");

                self.fill_operation_trace_row(
                    &processor.system,
                    &processor.stack,
                    operation,
                    op_idx_in_group,
                    op_helper_registers.to_user_op_helpers(),
                    &mut basic_block_context,
                );
            },
            Respan { node_id, batch_index } => {
                let basic_block_node = current_forest
                    .get_node_by_id(*node_id)
                    .expect("node not found in forest")
                    .unwrap_basic_block();

                let mut basic_block_context =
                    BasicBlockContext::new_at_batch_start(basic_block_node, *batch_index);
                let current_batch = &basic_block_node.op_batches()[*batch_index];

                self.fill_respan_trace_row(
                    &processor.system,
                    &processor.stack,
                    current_batch,
                    &mut basic_block_context,
                );
            },
            FinishBasicBlock(node_id) => {
                let basic_block_node = current_forest
                    .get_node_by_id(*node_id)
                    .expect("node not found in forest")
                    .unwrap_basic_block();

                self.fill_basic_block_end_trace_row(
                    &processor.system,
                    &processor.stack,
                    basic_block_node,
                );
            },
            FinishExternal(_)
            | EnterForest(_)
            | AfterExitDecorators(_)
            | AfterExitDecoratorsBasicBlock(_) => {
                unreachable!(
                    "Tracer contract guarantees that these continuations do not occur here"
                )
            },
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a reference to the node with the given ID from the forest.
///
/// # Panics
/// - Panics if the node ID is not found in the forest.
fn expect_node_in_forest(forest: &MastForest, node_id: MastNodeId) -> &MastNode {
    forest
        .get_node_by_id(node_id)
        .unwrap_or_else(|| panic!("invalid node ID stored in continuation: {}", node_id))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::mast::{DynNodeBuilder, MastForestContributor};

    use super::*;
    use crate::{
        ContextId,
        trace::{
            parallel::CORE_TRACE_WIDTH,
            trace_state::{
                AdviceReplay, ExecutionContextReplay, HasherResponseReplay,
                MastForestResolutionReplay, MemoryReadsReplay, StackOverflowReplay, StackState,
                SystemState,
            },
        },
    };

    /// Ensures that `get_execution_context_for_dyncall()` correctly populates the
    /// `parent_next_overflow_addr` field of the execution context info when the stack is at
    /// MIN_STACK_DEPTH with a non-empty overflow table replay.
    ///
    /// Scenario: the stack is at MIN_STACK_DEPTH (16), but the `StackOverflowReplay` contains a
    /// pending overflow pop (representing a future pop that will occur as the stack grows beyond
    /// the minimum depth) with a non-zero overflow address. This simulates a state where the
    /// overflow table replay is non-empty, even though the stack is currently at minimum depth. In
    /// this case, `get_execution_context_for_dyncall()` should return execution context info with
    /// `parent_next_overflow_addr` equal to the stack's `last_overflow_addr` (which is ZERO),
    /// rather than peeking at the replay queue and returning the post-pop overflow address from the
    /// future/unrelated overflow pop (which is non-zero).
    ///
    /// (`last_overflow_addr != ZERO`). The overflow replay queue contains a stale entry whose
    /// post-pop overflow address is 42. The method should return the stack's `last_overflow_addr`,
    /// but instead peeks at the replay queue and returns ZERO.
    #[test]
    fn get_execution_context_for_dyncall_at_min_stack_depth_with_overflow_entries() {
        // Build a MastForest with a single DYNCALL node.
        let mut forest = MastForest::new();
        let dyncall_node_id = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();

        let continuation = Continuation::StartNode(dyncall_node_id);

        // Create a stack of depth 16 (and hence `last_overflow_addr == ZERO`).
        let stack = StackState::new([ZERO; MIN_STACK_DEPTH], MIN_STACK_DEPTH, ZERO);

        // Place an entry in the overflow replay queue that corresponds to a future pop (once the
        // stack will have grown beyond the minimum depth).
        let overflow_addr_of_future_pop = Felt::new(42);
        let mut stack_overflow_replay = StackOverflowReplay::new();
        stack_overflow_replay.record_pop_overflow(Felt::new(99), overflow_addr_of_future_pop);

        let system = SystemState {
            clk: 0u32.into(),
            ctx: ContextId::root(),
            fn_hash: Word::default(),
            pc_transcript_state: Word::default(),
        };

        let processor = ReplayProcessor::new(
            system,
            stack,
            stack_overflow_replay,
            ExecutionContextReplay::default(),
            AdviceReplay::default(),
            MemoryReadsReplay::default(),
            HasherResponseReplay::default(),
            MastForestResolutionReplay::default(),
            1u32.into(),
        );

        // Create a minimal CoreTraceFragment — its contents are unused by the method under
        // test.
        let mut columns_data: Vec<Vec<Felt>> =
            (0..CORE_TRACE_WIDTH).map(|_| vec![ZERO; 1]).collect();
        let column_slices: Vec<&mut [Felt]> =
            columns_data.iter_mut().map(|v| v.as_mut_slice()).collect();
        let mut fragment = CoreTraceFragment {
            columns: column_slices.try_into().expect("CORE_TRACE_WIDTH columns"),
        };

        let tracer = CoreTraceGenerationTracer::new(
            &mut fragment,
            DecoderState { current_addr: ZERO, parent_addr: ZERO },
            BlockAddressReplay::default(),
            BlockStackReplay::default(),
        );

        // Call the method under test.
        let ctx_info = tracer
            .get_execution_context_for_dyncall(&forest, &continuation, &processor)
            .expect("should return Some for a DYNCALL StartNode continuation");

        // check for bug: When the stack is at MIN_STACK_DEPTH with a non-empty overflow table
        // replay queue, parent_next_overflow_addr should reflect the current overflow state of
        // ZERO; NOT the non-zero overflow address from the future pop in the replay queue (which
        // would indicate an incorrect peek at the replay queue).
        assert_eq!(
            ctx_info.parent_next_overflow_addr, ZERO,
            "parent_next_overflow_addr should be ZERO, reflecting the current overflow state of the stack, \
            and should not reflect the non-zero overflow address from the future pop in the replay queue"
        );
    }
}
