use alloc::sync::Arc;

use miden_air::{
    Felt,
    trace::{RowIndex, STACK_TRACE_WIDTH, SYS_TRACE_WIDTH, chiplets::hasher::STATE_WIDTH},
};
use miden_core::{
    ONE, Word, ZERO,
    crypto::merkle::MerklePath,
    mast::{MastForest, MastNode, MastNodeExt, MastNodeId},
    program::MIN_STACK_DEPTH,
};

use crate::{
    ContextId,
    continuation_stack::{Continuation, ContinuationStack},
    decoder::block_stack::ExecutionContextInfo,
    fast::trace_state::{BlockAddressReplay, BlockStackReplay, DecoderState},
    trace::{
        chiplets::CircuitEvaluation,
        parallel::{
            core_trace_fragment::{BasicBlockContext, CoreTraceFragment},
            processor::ReplayProcessor,
        },
    },
    tracer::{OperationHelperRegisters, Tracer},
};

mod trace_row;

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
    /// The MAST forest that is current at the beginning of the clock cycle, captured in
    /// [`start_clock_cycle`](Tracer::start_clock_cycle) for use when finalizing the cycle.
    current_forest: Option<Arc<MastForest>>,
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
            current_forest: None,
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
}

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
        self.current_forest = Some(Arc::clone(current_forest));
    }

    fn finalize_clock_cycle(
        &mut self,
        processor: &ReplayProcessor,
        op_helper_registers: OperationHelperRegisters,
    ) {
        use Continuation::*;

        match self.continuation.as_ref().expect("continuation stored at start of clock cycle") {
            StartNode(node_id) => {
                self.decoder_state.replay_node_start(
                    &mut self.block_address_replay,
                    &mut self.block_stack_replay,
                );

                self.fill_start_row(*node_id, processor);
            },
            FinishJoin(node_id) => {
                let node = expect_node_in_forest(&self.current_forest, *node_id);
                self.fill_end_trace_row(&processor.system, &processor.stack, node.digest());
            },
            FinishSplit(node_id) => {
                let node = expect_node_in_forest(&self.current_forest, *node_id);
                self.fill_end_trace_row(&processor.system, &processor.stack, node.digest());
            },
            FinishLoop { node_id, was_entered: _ } => {
                let loop_condition = self.finish_loop_condition.take().expect(
                    "loop condition stored at start of clock cycle for FinishLoop continuation",
                );

                if loop_condition {
                    // Loop body is about to be re-executed, so fill in a REPEAT row.
                    let current_forest = self
                        .current_forest
                        .clone()
                        .expect("current forest stored at start of clock cycle");

                    let loop_node = current_forest
                        .get_node_by_id(*node_id)
                        .expect("node not found in forest")
                        .unwrap_loop();
                    let current_addr = self.decoder_state.current_addr;

                    self.fill_loop_repeat_trace_row(
                        &processor.system,
                        &processor.stack,
                        loop_node,
                        &current_forest,
                        current_addr,
                    );
                } else {
                    // Loop is finished, so fill in an END row.
                    let node = expect_node_in_forest(&self.current_forest, *node_id);
                    self.fill_end_trace_row(&processor.system, &processor.stack, node.digest());
                }
            },
            FinishCall(node_id) => {
                let node = expect_node_in_forest(&self.current_forest, *node_id);
                self.fill_end_trace_row(&processor.system, &processor.stack, node.digest());
            },
            FinishDyn(node_id) => {
                let node = expect_node_in_forest(&self.current_forest, *node_id);
                self.fill_end_trace_row(&processor.system, &processor.stack, node.digest());
            },
            ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                let current_forest = self
                    .current_forest
                    .clone()
                    .expect("current forest stored at start of clock cycle");
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
                let current_forest = self
                    .current_forest
                    .clone()
                    .expect("current forest stored at start of clock cycle");
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
                let current_forest = self
                    .current_forest
                    .clone()
                    .expect("current forest stored at start of clock cycle");
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

    fn record_mast_forest_resolution(&mut self, _node_id: MastNodeId, _forest: &Arc<MastForest>) {
        // do nothing
    }

    fn record_hasher_permute(
        &mut self,
        _input_state: [Felt; STATE_WIDTH],
        _output_state: [Felt; STATE_WIDTH],
    ) {
        // do nothing
    }

    fn record_hasher_build_merkle_root(
        &mut self,
        _node: Word,
        _path: Option<&MerklePath>,
        _index: Felt,
        _output_root: Word,
    ) {
        // do nothing
    }

    fn record_hasher_update_merkle_root(
        &mut self,
        _old_value: Word,
        _new_value: Word,
        _path: Option<&MerklePath>,
        _index: Felt,
        _old_root: Word,
        _new_root: Word,
    ) {
        // do nothing
    }

    fn record_memory_read_element(
        &mut self,
        _element: Felt,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // do nothing
    }

    fn record_memory_read_word(
        &mut self,
        _word: Word,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // do nothing
    }

    fn record_memory_write_element(
        &mut self,
        _element: Felt,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // do nothing
    }

    fn record_memory_write_word(
        &mut self,
        _word: Word,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // do nothing
    }

    fn record_advice_pop_stack(&mut self, _value: Felt) {
        // do nothing
    }

    fn record_advice_pop_stack_word(&mut self, _word: Word) {
        // do nothing
    }

    fn record_advice_pop_stack_dword(&mut self, _words: [Word; 2]) {
        // do nothing
    }

    fn record_u32and(&mut self, _a: Felt, _b: Felt) {
        // do nothing
    }

    fn record_u32xor(&mut self, _a: Felt, _b: Felt) {
        // do nothing
    }

    fn record_u32_range_checks(&mut self, _clk: RowIndex, _u32_lo: Felt, _u32_hi: Felt) {
        // do nothing
    }

    fn record_kernel_proc_access(&mut self, _proc_hash: Word) {
        // do nothing
    }

    fn record_circuit_evaluation(&mut self, _clk: RowIndex, _circuit_eval: CircuitEvaluation) {
        // do nothing
    }

    fn increment_stack_size(&mut self, _processor: &ReplayProcessor) {
        // do nothing
    }

    fn decrement_stack_size(&mut self) {
        // do nothing
    }

    fn start_context(&mut self) {
        // do nothing
    }

    fn restore_context(&mut self) {
        // do nothing
    }
}

/// Helpers
impl<'a> CoreTraceGenerationTracer<'a> {
    /// Fills a trace row for a `StartNode` continuation based on the type of node being started.
    fn fill_start_row(&mut self, node_id: MastNodeId, processor: &ReplayProcessor) {
        let current_forest = self
            .current_forest
            .clone()
            .expect("current forest stored at start of clock cycle");
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
                    &current_forest,
                );
            },
            MastNode::Split(split_node) => {
                self.fill_split_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    split_node,
                    &current_forest,
                );
            },
            MastNode::Loop(loop_node) => {
                self.fill_loop_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    loop_node,
                    &current_forest,
                );
            },
            MastNode::Call(call_node) => {
                self.fill_call_start_trace_row(
                    &processor.system,
                    &processor.stack,
                    call_node,
                    &current_forest,
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
        if let Continuation::StartNode(node_id) = &continuation {
            let node = current_forest
                .get_node_by_id(*node_id)
                .expect("invalid node ID stored in continuation");

            if let MastNode::Dyn(dyn_node) = node
                && dyn_node.is_dyncall()
            {
                // Capture execution context info after dropping the top stack element.
                let stack_depth =
                    core::cmp::max(processor.stack.stack_depth() - 1, MIN_STACK_DEPTH) as u32;
                let overflow_addr = match processor.stack_overflow_replay.peek_replay_pop_overflow()
                {
                    Some((_, overflow_addr)) => *overflow_addr,
                    None => ZERO,
                };

                let ctx_info = ExecutionContextInfo::new(
                    processor.system.ctx,
                    processor.system.fn_hash,
                    stack_depth,
                    overflow_addr,
                );
                return Some(ctx_info);
            }
        }

        None
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

/// Returns a reference to the node with the given ID from the forest.
///
/// # Panics
/// - Panics if the forest is `None` or if the node ID is not found in the forest.
fn expect_node_in_forest(forest: &Option<Arc<MastForest>>, node_id: MastNodeId) -> &MastNode {
    forest
        .as_ref()
        .expect("current forest stored at start of clock cycle")
        .get_node_by_id(node_id)
        .unwrap_or_else(|| panic!("invalid node ID stored in continuation: {}", node_id))
}
