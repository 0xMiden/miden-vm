use alloc::{sync::Arc, vec::Vec};

use miden_air::trace::{RowIndex, chiplets::hasher::STATE_WIDTH};
use miden_core::{
    EMPTY_WORD, Felt, ONE, Word, ZERO,
    crypto::merkle::MerklePath,
    field::{PrimeCharacteristicRing, PrimeField64},
    mast::{
        BasicBlockNode, JoinNode, LoopNode, MastForest, MastNode, MastNodeExt, MastNodeId,
        SplitNode,
    },
    precompile::PrecompileTranscript,
    stack::MIN_STACK_DEPTH,
};

use crate::{
    chiplets::CircuitEvaluation,
    continuation_stack::{Continuation, ContinuationStack},
    decoder::block_stack::{BlockInfo, BlockStack, BlockType, ExecutionContextInfo},
    fast::{
        FastProcessor,
        trace_state::{
            AceReplay, AdviceReplay, BitwiseReplay, BlockStackReplay, CoreTraceFragmentContext,
            CoreTraceState, DecoderState, ExecutionContextSystemInfo, ExecutionReplay,
            HasherRequestReplay, HasherResponseReplay, KernelReplay, MastForestResolutionReplay,
            MemoryReadsReplay, MemoryWritesReplay, NodeExecutionState, NodeFlags,
            RangeCheckerReplay, StackOverflowReplay, StackState, SystemState,
        },
        tracer::Tracer,
    },
    stack::OverflowTable,
    system::ContextId,
    utils::{HASH_CYCLE_LEN_FELT, split_u32_into_u16},
};

/// Execution state snapshot, used to record the state at the start of a trace fragment.
#[derive(Debug)]
struct StateSnapshot {
    state: CoreTraceState,
    continuation_stack: ContinuationStack,
    initial_mast_forest: Arc<MastForest>,
}

pub struct TraceGenerationContext {
    /// The list of trace fragment contexts built during execution.
    pub core_trace_contexts: Vec<CoreTraceFragmentContext>,

    // Replays that contain additional data needed to generate the range checker and chiplets
    // columns.
    pub range_checker_replay: RangeCheckerReplay,
    pub memory_writes: MemoryWritesReplay,
    pub bitwise_replay: BitwiseReplay,
    pub hasher_for_chiplet: HasherRequestReplay,
    pub kernel_replay: KernelReplay,
    pub ace_replay: AceReplay,

    /// The final precompile transcript at the end of execution.
    pub final_pc_transcript: PrecompileTranscript,

    /// The number of rows per core trace fragment, except for the last fragment which may be
    /// shorter.
    pub fragment_size: usize,
}

/// Builder for recording the context to generate trace fragments during execution.
///
/// Specifically, this records the information necessary to be able to generate the trace in
/// fragments of configurable length. This requires storing state at the very beginning of the
/// fragment before any operations are executed, as well as recording the various values read during
/// execution in the corresponding "replays" (e.g. values read from memory are recorded in
/// [MemoryReadsReplay], values read from the advice provider are recorded in [AdviceReplay], etc).
///
/// Then, to generate a trace fragment, we initialize the state of the processor using the stored
/// snapshot from the beginning of the fragment, and replay the recorded values as they are
/// encountered during execution (e.g. when encountering a memory read operation, we will replay the
/// value rather than querying the memory chiplet).
#[derive(Debug)]
pub struct ExecutionTracer {
    // State stored at the start of a core trace fragment.
    //
    // This field is only set to `None` at initialization, and is populated when starting a new
    // trace fragment with `Self::start_new_fragment_context()`. Hence, on the first call to
    // `Self::start_new_fragment_context()`, we don't extract a new `TraceFragmentContext`, but in
    // every other call, we do.
    state_snapshot: Option<StateSnapshot>,

    // Replay data aggregated throughout the execution of a core trace fragment
    pub overflow_table: OverflowTable,
    pub overflow_replay: StackOverflowReplay,

    pub block_stack: BlockStack,
    pub block_stack_replay: BlockStackReplay,

    pub hasher_chiplet_shim: HasherChipletShim,
    pub memory_reads: MemoryReadsReplay,
    pub advice: AdviceReplay,
    pub external: MastForestResolutionReplay,

    // Replays that contain additional data needed to generate the range checker and chiplets
    // columns.
    pub range_checker: RangeCheckerReplay,
    pub memory_writes: MemoryWritesReplay,
    pub bitwise: BitwiseReplay,
    pub kernel: KernelReplay,
    pub hasher_for_chiplet: HasherRequestReplay,
    pub ace: AceReplay,

    // Output
    fragment_contexts: Vec<CoreTraceFragmentContext>,

    /// The number of rows per core trace fragment.
    fragment_size: usize,
}

impl ExecutionTracer {
    /// Creates a new `ExecutionTracer` with the given fragment size.
    pub fn new(fragment_size: usize) -> Self {
        Self {
            state_snapshot: None,
            overflow_table: OverflowTable::default(),
            overflow_replay: StackOverflowReplay::default(),
            block_stack: BlockStack::default(),
            block_stack_replay: BlockStackReplay::default(),
            hasher_chiplet_shim: HasherChipletShim::default(),
            memory_reads: MemoryReadsReplay::default(),
            range_checker: RangeCheckerReplay::default(),
            memory_writes: MemoryWritesReplay::default(),
            advice: AdviceReplay::default(),
            bitwise: BitwiseReplay::default(),
            kernel: KernelReplay::default(),
            hasher_for_chiplet: HasherRequestReplay::default(),
            ace: AceReplay::default(),
            external: MastForestResolutionReplay::default(),
            fragment_contexts: Vec::new(),
            fragment_size,
        }
    }

    /// Convert the `ExecutionTracer` into a [TraceGenerationContext] using the data accumulated
    /// during execution.
    ///
    /// The `final_pc_transcript` parameter represents the final precompile transcript at
    /// the end of execution, which is needed for the auxiliary trace column builder.
    pub fn into_trace_generation_context(
        mut self,
        final_pc_transcript: PrecompileTranscript,
    ) -> TraceGenerationContext {
        // If there is an ongoing trace state being built, finish it
        self.finish_current_fragment_context();

        TraceGenerationContext {
            core_trace_contexts: self.fragment_contexts,
            range_checker_replay: self.range_checker,
            memory_writes: self.memory_writes,
            bitwise_replay: self.bitwise,
            kernel_replay: self.kernel,
            hasher_for_chiplet: self.hasher_for_chiplet,
            ace_replay: self.ace,
            final_pc_transcript,
            fragment_size: self.fragment_size,
        }
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
        mut continuation_stack: ContinuationStack,
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

            // Push new continuation corresponding to the current execution state
            {
                let top_continuation =
                    continuation_from_execution_state(execution_state, &current_forest);
                continuation_stack.push_continuation(top_continuation);
            }

            Some(StateSnapshot {
                state: CoreTraceState {
                    system: system_state,
                    decoder: decoder_state,
                    stack,
                },
                continuation_stack,
                initial_mast_forest: current_forest,
            })
        };
    }

    fn record_control_node_start(
        &mut self,
        node: &MastNode,
        processor: &FastProcessor,
        current_forest: &MastForest,
    ) {
        let (ctx_info, block_type) = match node {
            MastNode::Join(node) => {
                let child1_hash = current_forest
                    .get_node_by_id(node.first())
                    .expect("join node's first child expected to be in the forest")
                    .digest();
                let child2_hash = current_forest
                    .get_node_by_id(node.second())
                    .expect("join node's second child expected to be in the forest")
                    .digest();
                self.hasher_for_chiplet.record_hash_control_block(
                    child1_hash,
                    child2_hash,
                    JoinNode::DOMAIN,
                    node.digest(),
                );

                (None, BlockType::Join(false))
            },
            MastNode::Split(node) => {
                let child1_hash = current_forest
                    .get_node_by_id(node.on_true())
                    .expect("split node's true child expected to be in the forest")
                    .digest();
                let child2_hash = current_forest
                    .get_node_by_id(node.on_false())
                    .expect("split node's false child expected to be in the forest")
                    .digest();
                self.hasher_for_chiplet.record_hash_control_block(
                    child1_hash,
                    child2_hash,
                    SplitNode::DOMAIN,
                    node.digest(),
                );

                (None, BlockType::Split)
            },
            MastNode::Loop(node) => {
                let body_hash = current_forest
                    .get_node_by_id(node.body())
                    .expect("loop node's body expected to be in the forest")
                    .digest();

                self.hasher_for_chiplet.record_hash_control_block(
                    body_hash,
                    EMPTY_WORD,
                    LoopNode::DOMAIN,
                    node.digest(),
                );

                let loop_entered = {
                    let condition = processor.stack_get(0);
                    condition == ONE
                };

                (None, BlockType::Loop(loop_entered))
            },
            MastNode::Call(node) => {
                let callee_hash = current_forest
                    .get_node_by_id(node.callee())
                    .expect("call node's callee expected to be in the forest")
                    .digest();

                self.hasher_for_chiplet.record_hash_control_block(
                    callee_hash,
                    EMPTY_WORD,
                    node.domain(),
                    node.digest(),
                );

                let exec_ctx = {
                    let overflow_addr = self.overflow_table.last_update_clk_in_current_ctx();
                    ExecutionContextInfo::new(
                        processor.ctx,
                        processor.caller_hash,
                        processor.stack_depth(),
                        overflow_addr,
                    )
                };
                let block_type = if node.is_syscall() {
                    BlockType::SysCall
                } else {
                    BlockType::Call
                };

                (Some(exec_ctx), block_type)
            },
            MastNode::Dyn(dyn_node) => {
                self.hasher_for_chiplet.record_hash_control_block(
                    EMPTY_WORD,
                    EMPTY_WORD,
                    dyn_node.domain(),
                    dyn_node.digest(),
                );

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

        let block_addr = self.hasher_chiplet_shim.record_hash_control_block();
        let parent_addr = self.block_stack.push(block_addr, block_type, ctx_info);
        self.block_stack_replay.record_node_start_parent_addr(parent_addr);
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
            let hasher_replay = self.hasher_chiplet_shim.extract_replay();
            let memory_reads_replay = core::mem::take(&mut self.memory_reads);
            let advice_replay = core::mem::take(&mut self.advice);
            let external_replay = core::mem::take(&mut self.external);
            let stack_overflow_replay = core::mem::take(&mut self.overflow_replay);
            let block_stack_replay = core::mem::take(&mut self.block_stack_replay);

            let trace_state = CoreTraceFragmentContext {
                state: snapshot.state,
                replay: ExecutionReplay {
                    hasher: hasher_replay,
                    memory_reads: memory_reads_replay,
                    advice: advice_replay,
                    mast_forest_resolution: external_replay,
                    stack_overflow: stack_overflow_replay,
                    block_stack: block_stack_replay,
                },
                continuation: snapshot.continuation_stack,
                initial_mast_forest: snapshot.initial_mast_forest,
            };

            self.fragment_contexts.push(trace_state);
        }
    }
}

/// Converts a [NodeExecutionState] into the corresponding [Continuation].
///
/// The [NodeExecutionState] represents the execution state at a given point in time, while the
/// [Continuation] represents the next action to be taken in the execution. This function maps
/// between the two representations.
fn continuation_from_execution_state(
    execution_state: NodeExecutionState,
    current_forest: &Arc<MastForest>,
) -> Continuation {
    let top_continuation = match execution_state {
        NodeExecutionState::BasicBlock { node_id, batch_index, op_idx_in_batch } => {
            Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch }
        },
        NodeExecutionState::Start(node_id) => Continuation::StartNode(node_id),
        NodeExecutionState::Respan { node_id, batch_index } => {
            Continuation::Respan { node_id, batch_index }
        },
        NodeExecutionState::LoopRepeat(node_id) => Continuation::FinishLoop(node_id),
        NodeExecutionState::End(node_id) => {
            let node = current_forest
                .get_node_by_id(node_id)
                .expect("Node ID expected to exist in current forest");
            match node {
                MastNode::Block(_basic_block_node) => Continuation::FinishBasicBlock(node_id),
                MastNode::Join(_join_node) => Continuation::FinishJoin(node_id),
                MastNode::Split(_split_node) => Continuation::FinishSplit(node_id),
                MastNode::Loop(_loop_node) => Continuation::FinishLoop(node_id),
                MastNode::Call(_call_node) => Continuation::FinishCall(node_id),
                MastNode::Dyn(_dyn_node) => Continuation::FinishDyn(node_id),
                MastNode::External(_external_node) => {
                    panic!("External nodes are guaranteed to be resolved")
                },
            }
        },
    };
    top_continuation
}

impl Tracer for ExecutionTracer {
    /// When sufficiently many clock cycles have elapsed, starts a new trace state. Also updates the
    /// internal block stack.
    fn start_clock_cycle(
        &mut self,
        processor: &FastProcessor,
        execution_state: NodeExecutionState,
        continuation_stack: &ContinuationStack,
        current_forest: &Arc<MastForest>,
    ) {
        // check if we need to start a new trace state
        if processor.clk.as_usize().is_multiple_of(self.fragment_size) {
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
                    self.record_control_node_start(
                        &current_forest[*mast_node_id],
                        processor,
                        current_forest,
                    );
                },
                MastNode::Block(basic_block_node) => {
                    self.hasher_for_chiplet.record_hash_basic_block(
                        basic_block_node.op_batches().to_vec(),
                        basic_block_node.digest(),
                    );
                    let block_addr =
                        self.hasher_chiplet_shim.record_hash_basic_block(basic_block_node);
                    let parent_addr =
                        self.block_stack.push(block_addr, BlockType::BasicBlock, None);
                    self.block_stack_replay.record_node_start_parent_addr(parent_addr);
                },
                MastNode::External(_) => unreachable!(
                    "start_clock_cycle is guaranteed not to be called on external nodes"
                ),
            },
            NodeExecutionState::Respan { node_id: _, batch_index: _ } => {
                self.block_stack.peek_mut().addr += HASH_CYCLE_LEN_FELT;
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
                    });
                }
            },
        }
    }

    fn record_mast_forest_resolution(&mut self, node_id: MastNodeId, forest: &Arc<MastForest>) {
        self.external.record_resolution(node_id, forest.clone());
    }

    fn record_hasher_permute(
        &mut self,
        input_state: [Felt; STATE_WIDTH],
        output_state: [Felt; STATE_WIDTH],
    ) {
        self.hasher_for_chiplet.record_permute_input(input_state);
        self.hasher_chiplet_shim.record_permute_output(output_state);
    }

    fn record_hasher_build_merkle_root(
        &mut self,
        node: Word,
        path: Option<&MerklePath>,
        index: Felt,
        output_root: Word,
    ) {
        let path = path.expect("execution tracer expects a valid Merkle path");
        self.hasher_chiplet_shim.record_build_merkle_root(path, output_root);
        self.hasher_for_chiplet.record_build_merkle_root(node, path.clone(), index);
    }

    fn record_hasher_update_merkle_root(
        &mut self,
        old_value: Word,
        new_value: Word,
        path: Option<&MerklePath>,
        index: Felt,
        old_root: Word,
        new_root: Word,
    ) {
        let path = path.expect("execution tracer expects a valid Merkle path");
        self.hasher_chiplet_shim.record_update_merkle_root(path, old_root, new_root);
        self.hasher_for_chiplet.record_update_merkle_root(
            old_value,
            new_value,
            path.clone(),
            index,
        );
    }

    fn record_memory_read_element(
        &mut self,
        element: Felt,
        addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    ) {
        self.memory_reads.record_read_element(element, addr, ctx, clk);
    }

    fn record_memory_read_word(&mut self, word: Word, addr: Felt, ctx: ContextId, clk: RowIndex) {
        self.memory_reads.record_read_word(word, addr, ctx, clk);
    }

    fn record_memory_write_element(
        &mut self,
        element: Felt,
        addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    ) {
        self.memory_writes.record_write_element(element, addr, ctx, clk);
    }

    fn record_memory_write_word(&mut self, word: Word, addr: Felt, ctx: ContextId, clk: RowIndex) {
        self.memory_writes.record_write_word(word, addr, ctx, clk);
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

    fn record_u32and(&mut self, a: Felt, b: Felt) {
        self.bitwise.record_u32and(a, b);
    }

    fn record_u32xor(&mut self, a: Felt, b: Felt) {
        self.bitwise.record_u32xor(a, b);
    }

    fn record_u32_range_checks(&mut self, clk: RowIndex, u32_lo: Felt, u32_hi: Felt) {
        let (t1, t0) = split_u32_into_u16(u32_lo.as_canonical_u64());
        let (t3, t2) = split_u32_into_u16(u32_hi.as_canonical_u64());

        self.range_checker.record_range_check_u32(clk, [t0, t1, t2, t3]);
    }

    fn record_kernel_proc_access(&mut self, proc_hash: Word) {
        self.kernel.record_kernel_proc_access(proc_hash);
    }

    fn record_circuit_evaluation(&mut self, clk: RowIndex, circuit_eval: CircuitEvaluation) {
        self.ace.record_circuit_evaluation(clk, circuit_eval);
    }

    fn increment_clk(&mut self) {
        // do nothing
    }

    fn increment_stack_size(&mut self, processor: &FastProcessor) {
        let new_overflow_value = processor.stack_get(15);
        self.overflow_table.push(new_overflow_value, processor.clk);
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

/// Implements a shim for the hasher chiplet, where the responses of the hasher chiplet are emulated
/// and recorded for later replay.
///
/// This is used to simulate hasher operations in parallel trace generation without needing to
/// actually generate the hasher trace. All hasher operations are recorded during fast execution and
/// then replayed during core trace generation.
#[derive(Debug)]
pub struct HasherChipletShim {
    /// The address of the next MAST node encountered during execution. This field is used to keep
    /// track of the number of rows in the hasher chiplet, from which the address of the next MAST
    /// node is derived.
    addr: u32,
    /// Replay for the hasher chiplet responses, recording only the hasher chiplet responses.
    replay: HasherResponseReplay,
}

impl HasherChipletShim {
    /// Creates a new [HasherChipletShim].
    pub fn new() -> Self {
        Self {
            addr: 1,
            replay: HasherResponseReplay::default(),
        }
    }

    /// Records the address returned from a call to `Hasher::hash_control_block()`.
    pub fn record_hash_control_block(&mut self) -> Felt {
        let block_addr = Felt::from_u32(self.addr);

        self.replay.record_block_address(block_addr);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION;

        block_addr
    }

    /// Records the address returned from a call to `Hasher::hash_basic_block()`.
    pub fn record_hash_basic_block(&mut self, basic_block_node: &BasicBlockNode) -> Felt {
        let block_addr = Felt::from_u32(self.addr);

        self.replay.record_block_address(block_addr);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION * basic_block_node.num_op_batches() as u32;

        block_addr
    }
    /// Records the result of a call to `Hasher::permute()`.
    pub fn record_permute_output(&mut self, hashed_state: [Felt; 12]) {
        self.replay.record_permute(Felt::from_u32(self.addr), hashed_state);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION;
    }

    /// Records the result of a call to `Hasher::build_merkle_root()`.
    pub fn record_build_merkle_root(&mut self, path: &MerklePath, computed_root: Word) {
        self.replay.record_build_merkle_root(Felt::from_u32(self.addr), computed_root);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION * path.depth() as u32;
    }

    /// Records the result of a call to `Hasher::update_merkle_root()`.
    pub fn record_update_merkle_root(&mut self, path: &MerklePath, old_root: Word, new_root: Word) {
        self.replay
            .record_update_merkle_root(Felt::from_u32(self.addr), old_root, new_root);

        // The Merkle path is verified twice: once for the old root and once for the new root.
        self.addr += 2 * NUM_HASHER_ROWS_PER_PERMUTATION * path.depth() as u32;
    }

    pub fn extract_replay(&mut self) -> HasherResponseReplay {
        core::mem::take(&mut self.replay)
    }
}

impl Default for HasherChipletShim {
    fn default() -> Self {
        Self::new()
    }
}
