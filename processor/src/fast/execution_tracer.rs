use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Felt, ONE, Word, ZERO,
    crypto::merkle::MerklePath,
    mast::{BasicBlockNode, MastForest, MastNode, MastNodeId},
    stack::MIN_STACK_DEPTH,
};

use crate::{
    continuation_stack::ContinuationStack,
    decoder::block_stack::{BlockInfo, BlockStack, BlockType, ExecutionContextInfo},
    fast::{
        FastProcessor, NUM_ROWS_PER_CORE_FRAGMENT,
        trace_state::{
            AdviceReplay, BlockStackReplay, CoreTraceState, DecoderState,
            ExecutionContextSystemInfo, ExecutionReplay, ExternalNodeReplay, HasherReplay,
            MemoryReplay, NodeExecutionState, NodeFlags, StackOverflowReplay, StackState,
            SystemState, TraceFragmentContext,
        },
        tracer::Tracer,
    },
    stack::OverflowTable,
};

/// The number of rows in the execution trace required to compute a permutation of Rescue Prime
/// Optimized.
const HASH_CYCLE_LEN: Felt = Felt::new(miden_air::trace::chiplets::hasher::HASH_CYCLE_LEN as u64);

/// Execution state snapshot, used to record the state at the start of a trace fragment.
#[derive(Debug)]
struct StateSnapshot {
    state: CoreTraceState,
    continuation_stack: ContinuationStack,
    execution_state: NodeExecutionState,
    initial_mast_forest: Arc<MastForest>,
}

/// Builder for recording the context to generate trace fragments during execution.
///
/// Specifically, this records the information necessary to be able to generate the trace in
/// fragments of length [super::NUM_ROWS_PER_CORE_FRAGMENT]. This requires storing state at the very
/// beginning of the fragment before any operations are executed (stored in [StateSnapshot]), as
/// well as recording the various values read during execution in the corresponding "replays" (e.g.
/// values read from memory are recorded in [MemoryReplay], values read from the advice provider are
/// recorded in [AdviceReplay], etc).
///
/// Then, to generate a trace fragment, we initialize the state of the processor using the snapshot
/// stored in [StateSnapshot], and replay the recorded values as they are encountered during
/// execution (e.g. when encountering a memory read operation, we will replay the value rather than
/// querying the memory chiplet).
#[derive(Debug, Default)]
pub struct ExecutionTracer {
    // State stored at the start of a trace fragment.
    //
    // This field is only set to `None` at initialization, and is populated when starting a new
    // trace fragment with `Self::start_new_fragment_context()`. Hence, on the first call to
    // `Self::start_new_fragment_context()`, we don't extract a new `TraceFragmentContext`, but in
    // every other call, we do.
    state_snapshot: Option<StateSnapshot>,

    // Replay data aggregated throughout the execution of a fragment
    pub overflow_table: OverflowTable,
    pub overflow_replay: StackOverflowReplay,

    pub block_stack: BlockStack,
    pub block_stack_replay: BlockStackReplay,

    pub hasher: HasherChipletShim,
    pub memory: MemoryReplay,
    pub advice: AdviceReplay,
    pub external: ExternalNodeReplay,

    // Output
    fragment_contexts: Vec<TraceFragmentContext>,
}

impl ExecutionTracer {
    /// Convert the `ExecutionTracer` into the list of `TraceFragmentContext` built during
    /// execution.
    pub fn into_core_trace_states(mut self) -> Vec<TraceFragmentContext> {
        // If there is an ongoing trace state being built, finish it
        self.finish_current_fragment_context();

        self.fragment_contexts
    }

    // HELPERS
    // -------------------------------------------------------------------------------------------

    /// Captures the internal state into a new [TraceFragmentContext] (stored internally), resets
    /// the internal replay state of the builder, and records a new state snapshot, marking the
    /// beginning of the next trace state.
    ///
    /// This must be called at the beginning of a new trace fragment, before executing the first
    /// operation. Internal replay fields are expected to be accessed during execution of this new
    /// fragment to record data to be replayed by the trace fragment generators.
    fn start_new_fragment_context(
        &mut self,
        system_state: SystemState,
        stack_top: [Felt; MIN_STACK_DEPTH],
        continuation_stack: ContinuationStack,
        execution_state: NodeExecutionState,
        current_forest: Arc<MastForest>,
    ) {
        // If there is an ongoing snapshot, finish it
        self.finish_current_fragment_context();

        // Start a new snapshot
        self.state_snapshot = {
            let decoder_state = {
                if self.block_stack.is_empty() {
                    DecoderState { current_addr: ZERO, parent_addr: ZERO }
                } else {
                    let block_info = self.block_stack.peek();

                    DecoderState {
                        current_addr: block_info.addr,
                        parent_addr: block_info.parent_addr,
                    }
                }
            };
            let stack = {
                let stack_depth =
                    MIN_STACK_DEPTH + self.overflow_table.num_elements_in_current_ctx();
                let last_overflow_addr = self.overflow_table.last_update_clk_in_current_ctx();
                StackState::new(stack_top, stack_depth, last_overflow_addr)
            };

            Some(StateSnapshot {
                state: CoreTraceState {
                    system: system_state,
                    decoder: decoder_state,
                    stack,
                },
                continuation_stack,
                execution_state,
                initial_mast_forest: current_forest,
            })
        };
    }

    fn record_control_node_start(&mut self, mast_node: &MastNode, processor: &FastProcessor) {
        let (ctx_info, block_type) = match mast_node {
            MastNode::Join(_) => (None, BlockType::Join(false)),
            MastNode::Split(_) => (None, BlockType::Split),
            MastNode::Loop(_) => {
                let loop_entered = {
                    let condition = processor.stack_get(0);
                    condition == ONE
                };

                (None, BlockType::Loop(loop_entered))
            },
            MastNode::Call(call_node) => {
                let exec_ctx = {
                    let overflow_addr = self.overflow_table.last_update_clk_in_current_ctx();
                    ExecutionContextInfo::new(
                        processor.ctx,
                        processor.caller_hash,
                        processor.fmp,
                        processor.stack_depth(),
                        overflow_addr,
                    )
                };
                let block_type = if call_node.is_syscall() {
                    BlockType::SysCall
                } else {
                    BlockType::Call
                };

                (Some(exec_ctx), block_type)
            },
            MastNode::Dyn(dyn_node) => {
                if dyn_node.is_dyncall() {
                    let exec_ctx = {
                        let overflow_addr = self.overflow_table.last_update_clk_in_current_ctx();
                        // Note: the stack depth to record is the `current_stack_depth - 1` due to
                        // the semantics of DYNCALL. That is, the top of the
                        // stack contains the memory address to where the
                        // address to dynamically call is located. Then, the
                        // DYNCALL operation performs a drop, and
                        // records the stack depth after the drop as the beginning of
                        // the new context. For more information, look at the docs for how the
                        // constraints are designed; it's a bit tricky but it works.
                        let stack_depth_after_drop = processor.stack_depth() - 1;
                        ExecutionContextInfo::new(
                            processor.ctx,
                            processor.caller_hash,
                            processor.fmp,
                            stack_depth_after_drop,
                            overflow_addr,
                        )
                    };
                    (Some(exec_ctx), BlockType::Dyncall)
                } else {
                    (None, BlockType::Dyn)
                }
            },
            MastNode::Block(_) => panic!(
                "`ExecutionTracer::record_basic_block_start()` must be called instead for basic blocks"
            ),
            MastNode::External(_) => panic!(
                "External nodes are guaranteed to be resolved before record_control_node_start is called"
            ),
        };

        let block_addr = self.hasher.record_hash_control_block();
        let parent_addr = self.block_stack.push(block_addr, block_type, ctx_info);
        self.block_stack_replay.record_node_start(parent_addr);
    }

    /// Records the block address and flags for an END operation based on the block being popped.
    fn record_node_end(&mut self, block_info: &BlockInfo) {
        let flags = NodeFlags::new(
            block_info.is_loop_body() == ONE,
            block_info.is_entered_loop() == ONE,
            block_info.is_call() == ONE,
            block_info.is_syscall() == ONE,
        );
        let (prev_addr, prev_parent_addr) = if self.block_stack.is_empty() {
            (ZERO, ZERO)
        } else {
            let prev_block = self.block_stack.peek();
            (prev_block.addr, prev_block.parent_addr)
        };
        self.block_stack_replay.record_node_end(
            block_info.addr,
            flags,
            prev_addr,
            prev_parent_addr,
        );
    }

    /// Records the execution context system info for CALL/SYSCALL/DYNCALL operations.
    fn record_execution_context(&mut self, ctx_info: ExecutionContextSystemInfo) {
        self.block_stack_replay.record_execution_context(ctx_info);
    }

    /// Records the current core trace state, if any.
    ///
    /// Specifically, extracts the stored [SnapshotStart] as well as all the replay data recorded
    /// from the various components (e.g. memory, advice, etc) since the last call to this method.
    /// Resets the internal state to default values to prepare for the next trace fragment.
    ///
    /// Note that the very first time that this is called (at clock cycle 0), the snapshot will not
    /// contain any replay data, and so no core trace state will be recorded.
    fn finish_current_fragment_context(&mut self) {
        if let Some(snapshot) = self.state_snapshot.take() {
            // Extract the replays
            let hasher_replay = self.hasher.extract_replay();
            let memory_replay = core::mem::take(&mut self.memory);
            let advice_replay = core::mem::take(&mut self.advice);
            let external_replay = core::mem::take(&mut self.external);
            let stack_overflow_replay = core::mem::take(&mut self.overflow_replay);
            let block_stack_replay = core::mem::take(&mut self.block_stack_replay);

            let trace_state = TraceFragmentContext {
                state: snapshot.state,
                replay: ExecutionReplay {
                    hasher: hasher_replay,
                    memory: memory_replay,
                    advice: advice_replay,
                    external_node: external_replay,
                    stack_overflow: stack_overflow_replay,
                    block_stack: block_stack_replay,
                },
                continuation: snapshot.continuation_stack,
                initial_execution_state: snapshot.execution_state,
                initial_mast_forest: snapshot.initial_mast_forest,
            };

            self.fragment_contexts.push(trace_state);
        }
    }
}

impl Tracer for ExecutionTracer {
    /// When sufficiently many clock cycles have elapsed, starts a new trace state. Also updates the
    /// internal block stack.
    fn start_clock_cycle(
        &mut self,
        processor: &FastProcessor,
        execution_state: NodeExecutionState,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
    ) {
        // check if we need to start a new trace state
        if processor.clk.as_usize().is_multiple_of(NUM_ROWS_PER_CORE_FRAGMENT) {
            self.start_new_fragment_context(
                SystemState::from_processor(processor),
                processor
                    .stack_top()
                    .try_into()
                    .expect("stack_top expected to be MIN_STACK_DEPTH elements"),
                continuation_stack.clone(),
                execution_state.clone(),
                current_forest.clone(),
            );
        }

        // Update block stack
        match &execution_state {
            NodeExecutionState::BasicBlock { .. } => {
                // do nothing, since operations in a basic block don't update the block stack
            },
            NodeExecutionState::Start(mast_node_id) => match &current_forest[*mast_node_id] {
                MastNode::Join(_)
                | MastNode::Split(_)
                | MastNode::Loop(_)
                | MastNode::Dyn(_)
                | MastNode::Call(_) => {
                    self.record_control_node_start(&current_forest[*mast_node_id], processor);
                },
                MastNode::Block(basic_block_node) => {
                    let block_addr = self.hasher.record_hash_basic_block(basic_block_node);
                    let parent_addr = self.block_stack.push(block_addr, BlockType::Span, None);
                    self.block_stack_replay.record_node_start(parent_addr);
                },
                MastNode::External(_) => unreachable!(
                    "start_clock_cycle is guaranteed not to be called on external nodes"
                ),
            },
            NodeExecutionState::Respan { node_id: _, batch_index: _ } => {
                self.block_stack.peek_mut().addr += HASH_CYCLE_LEN;
            },
            NodeExecutionState::LoopRepeat(_) => {
                // do nothing, REPEAT doesn't affect the block stack
            },
            NodeExecutionState::End(_) => {
                let block_info = self.block_stack.pop();
                self.record_node_end(&block_info);

                if let Some(ctx_info) = block_info.ctx_info {
                    self.record_execution_context(ExecutionContextSystemInfo {
                        parent_ctx: ctx_info.parent_ctx,
                        parent_fn_hash: ctx_info.parent_fn_hash,
                        parent_fmp: ctx_info.parent_fmp,
                    });
                }
            },
        }
    }

    fn record_external_node_resolution(&mut self, node_id: MastNodeId, forest: &Arc<MastForest>) {
        self.external.record_resolution(node_id, forest.clone());
    }

    fn record_hasher_permute(&mut self, hashed_state: [Felt; 12]) {
        self.hasher.record_permute(hashed_state);
    }

    fn record_hasher_build_merkle_root(&mut self, path: &MerklePath, root: Word) {
        self.hasher.record_build_merkle_root(path, root);
    }

    fn record_hasher_update_merkle_root(
        &mut self,
        path: &MerklePath,
        old_root: Word,
        new_root: Word,
    ) {
        self.hasher.record_update_merkle_root(path, old_root, new_root);
    }

    fn record_memory_read_element(&mut self, element: Felt, addr: Felt) {
        self.memory.record_read_element(element, addr);
    }

    fn record_memory_read_word(&mut self, word: Word, addr: Felt) {
        self.memory.record_read_word(word, addr);
    }

    fn record_advice_pop_stack(&mut self, value: Felt) {
        self.advice.record_pop_stack(value);
    }

    fn record_advice_pop_stack_word(&mut self, word: Word) {
        self.advice.record_pop_stack_word(word);
    }

    fn record_advice_pop_stack_dword(&mut self, words: [Word; 2]) {
        self.advice.record_pop_stack_dword(words);
    }

    fn increment_clk(&mut self) {
        self.overflow_table.advance_clock();
    }

    fn increment_stack_size(&mut self, processor: &FastProcessor) {
        let new_overflow_value = processor.stack_get(15);
        self.overflow_table.push(new_overflow_value);
    }

    fn decrement_stack_size(&mut self) {
        // Record the popped value for replay, if present
        if let Some(popped_value) = self.overflow_table.pop() {
            let new_overflow_addr = self.overflow_table.last_update_clk_in_current_ctx();
            self.overflow_replay.record_pop_overflow(popped_value, new_overflow_addr);
        }
    }

    fn start_context(&mut self) {
        self.overflow_table.start_context();
    }

    fn restore_context(&mut self) {
        self.overflow_table.restore_context();
        self.overflow_replay.record_restore_context_overflow_addr(
            MIN_STACK_DEPTH + self.overflow_table.num_elements_in_current_ctx(),
            self.overflow_table.last_update_clk_in_current_ctx(),
        );
    }
}

// HASHER CHIPLET SHIM
// ================================================================================================

/// The number of hasher rows per permutation operation. This is used to compute the address for
/// the next operation in the hasher chiplet.
const NUM_HASHER_ROWS_PER_PERMUTATION: u32 = 8;

/// A shim for the hasher chiplet that records the result of operations performed on it throughout
/// the execution of a program.
#[derive(Debug)]
pub struct HasherChipletShim {
    /// The address of the next MAST node encountered during execution. This field is used to keep
    /// track of the number of rows in the hasher chiplet, from which the address of the next MAST
    /// node is derived.
    addr: u32,
    /// Replay for the hasher chiplet, recording all relevant data for trace generation.
    replay: HasherReplay,
}

impl HasherChipletShim {
    /// Creates a new [HasherChipletShim].
    pub fn new() -> Self {
        Self { addr: 1, replay: HasherReplay::default() }
    }

    /// Records the address returned from a call to `Hasher::hash_control_block()`.
    pub fn record_hash_control_block(&mut self) -> Felt {
        let block_addr = self.addr.into();

        self.replay.record_block_address(block_addr);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION;

        block_addr
    }

    /// Records the address returned from a call to `Hasher::hash_basic_block()`.
    pub fn record_hash_basic_block(&mut self, basic_block_node: &BasicBlockNode) -> Felt {
        let block_addr = self.addr.into();

        self.replay.record_block_address(block_addr);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION * basic_block_node.num_op_batches() as u32;

        block_addr
    }
    /// Records the result of a call to `Hasher::permute()`.
    pub fn record_permute(&mut self, hashed_state: [Felt; 12]) {
        self.replay.record_permute(self.addr.into(), hashed_state);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION;
    }

    /// Records the result of a call to `Hasher::build_merkle_root()`.
    pub fn record_build_merkle_root(&mut self, path: &MerklePath, computed_root: Word) {
        self.replay.record_build_merkle_root(self.addr.into(), computed_root);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION * path.depth() as u32;
    }

    /// Records the result of a call to `Hasher::update_merkle_root()`.
    pub fn record_update_merkle_root(&mut self, path: &MerklePath, old_root: Word, new_root: Word) {
        self.replay.record_update_merkle_root(self.addr.into(), old_root, new_root);

        // The Merkle path is verified twice: once for the old root and once for the new root.
        self.addr += 2 * NUM_HASHER_ROWS_PER_PERMUTATION * path.depth() as u32;
    }

    pub fn extract_replay(&mut self) -> HasherReplay {
        core::mem::take(&mut self.replay)
    }
}

impl Default for HasherChipletShim {
    fn default() -> Self {
        Self::new()
    }
}
