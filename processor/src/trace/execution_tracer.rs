use alloc::{sync::Arc, vec::Vec};

use miden_air::trace::chiplets::hasher::{HASH_CYCLE_LEN, HASH_CYCLE_LEN_FELT, STATE_WIDTH};
use miden_core::{FMP_ADDR, FMP_INIT_VALUE, field::BasedVectorSpace, operations::Operation};

use super::{
    decoder::block_stack::{BlockInfo, BlockStack, BlockType, ExecutionContextInfo},
    stack::OverflowTable,
    trace_state::{
        AceReplay, AdviceReplay, BitwiseReplay, BlockAddressReplay, BlockStackReplay,
        CoreTraceFragmentContext, CoreTraceState, DecoderState, ExecutionContextReplay,
        ExecutionContextSystemInfo, ExecutionReplay, HasherRequestReplay, HasherResponseReplay,
        KernelReplay, MastForestResolutionReplay, MemoryReadsReplay, MemoryWritesReplay, NodeFlags,
        RangeCheckerReplay, StackOverflowReplay, StackState, SystemState,
    },
    utils::split_u32_into_u16,
};
use crate::{
    ContextId, EMPTY_WORD, FastProcessor, Felt, MIN_STACK_DEPTH, ONE, RowIndex, Word, ZERO,
    continuation_stack::{Continuation, ContinuationStack},
    crypto::merkle::MerklePath,
    field::{PrimeCharacteristicRing, PrimeField64},
    mast::{
        BasicBlockNode, JoinNode, LoopNode, MastForest, MastNode, MastNodeExt, MastNodeId,
        SplitNode,
    },
    precompile::PrecompileTranscript,
    processor::{Processor, StackInterface, SystemInterface},
    trace::chiplets::{CircuitEvaluation, PTR_OFFSET_ELEM, PTR_OFFSET_WORD},
    tracer::{OperationHelperRegisters, Tracer},
};

// STATE SNAPSHOT
// ================================================================================================

/// Execution state snapshot, used to record the state at the start of a trace fragment.
#[derive(Debug)]
struct StateSnapshot {
    state: CoreTraceState,
    continuation_stack: ContinuationStack,
    initial_mast_forest: Arc<MastForest>,
}

// TRACE GENERATION CONTEXT
// ================================================================================================

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
    pub execution_context_replay: ExecutionContextReplay,

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

    /// The hasher input state captured in `start_clock_cycle` for HPERM and LOG_PRECOMPILE
    /// operations, to be consumed in `finalize_clock_cycle`.
    pending_hasher_input: Option<[Felt; STATE_WIDTH]>,

    /// Tracks the operation being executed in the current clock cycle, for operations whose
    /// recording requires pre-mutation state (u32 bitwise) or post-mutation stack reads (advice
    /// pops). Captured in `start_clock_cycle`, consumed in `finalize_clock_cycle`.
    pending_op: Option<PendingOp>,

    /// Flag set in `start_clock_cycle` when a Call/Syscall/Dyncall node starts, consumed in
    /// `finalize_clock_cycle` to call `overflow_table.start_context()`. This is deferred to
    /// `finalize_clock_cycle` because for Dyncall, `decrement_size` (which interacts with the
    /// overflow table) is called between `start_clock_cycle` and the actual context start.
    pending_start_context: bool,

    /// Flag set in `start_clock_cycle` when a Call/Syscall/Dyncall END is encountered, consumed
    /// in `finalize_clock_cycle` to call `overflow_table.restore_context()`. This is deferred to
    /// `finalize_clock_cycle` because `finalize_clock_cycle` is only called when the operation
    /// succeeds (i.e., the stack depth check passes).
    pending_restore_context: bool,
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
            execution_context_replay: ExecutionContextReplay::default(),
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
            pending_hasher_input: None,
            pending_op: None,
            pending_start_context: false,
            pending_restore_context: false,
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
        continuation: Continuation,
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
            continuation_stack.push_continuation(continuation);

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

    /// Pops the overflow table and records the pop in the overflow replay, if the overflow table
    /// has an element to pop.
    // TODO(plafer): rename to `decrement_stack_size()` after we remove it from the `Tracer` trait
    fn try_pop_overflow(&mut self) {
        if let Some(popped_value) = self.overflow_table.pop() {
            let new_overflow_addr = self.overflow_table.last_update_clk_in_current_ctx();
            self.overflow_replay.record_pop_overflow(popped_value, new_overflow_addr);
        }
    }

    fn record_control_node_start<P: Processor>(
        &mut self,
        node: &MastNode,
        processor: &P,
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
                    let condition = processor.stack().get(0);
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

                if node.is_syscall() {
                    self.kernel.record_kernel_proc_access(callee_hash);
                } else {
                    // For non-syscall calls, record the FMP initialization write for the new
                    // context. The new context ID is clock + 1.
                    let new_ctx: ContextId = (processor.system().clock() + 1).into();
                    self.memory_writes.record_write_element(
                        FMP_INIT_VALUE,
                        FMP_ADDR,
                        new_ctx,
                        processor.system().clock(),
                    );
                }

                let exec_ctx = {
                    let overflow_addr = self.overflow_table.last_update_clk_in_current_ctx();
                    ExecutionContextInfo::new(
                        processor.system().ctx(),
                        processor.system().caller_hash(),
                        processor.stack().depth(),
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
                    // Record the FMP initialization write for the new context.
                    // The new context ID is clock + 1.
                    let new_ctx: ContextId = (processor.system().clock() + 1).into();
                    self.memory_writes.record_write_element(
                        FMP_INIT_VALUE,
                        FMP_ADDR,
                        new_ctx,
                        processor.system().clock(),
                    );

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
                        let stack_depth_after_drop = processor.stack().depth() - 1;
                        ExecutionContextInfo::new(
                            processor.system().ctx(),
                            processor.system().caller_hash(),
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
        self.execution_context_replay.record_execution_context(ctx_info);
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
            let (hasher_replay, block_addr_replay) = self.hasher_chiplet_shim.extract_replay();
            let memory_reads_replay = core::mem::take(&mut self.memory_reads);
            let advice_replay = core::mem::take(&mut self.advice);
            let external_replay = core::mem::take(&mut self.external);
            let stack_overflow_replay = core::mem::take(&mut self.overflow_replay);
            let block_stack_replay = core::mem::take(&mut self.block_stack_replay);
            let execution_context_replay = core::mem::take(&mut self.execution_context_replay);

            let trace_state = CoreTraceFragmentContext {
                state: snapshot.state,
                replay: ExecutionReplay {
                    hasher: hasher_replay,
                    block_address: block_addr_replay,
                    memory_reads: memory_reads_replay,
                    advice: advice_replay,
                    mast_forest_resolution: external_replay,
                    stack_overflow: stack_overflow_replay,
                    block_stack: block_stack_replay,
                    execution_context: execution_context_replay,
                },
                continuation: snapshot.continuation_stack,
                initial_mast_forest: snapshot.initial_mast_forest,
            };

            self.fragment_contexts.push(trace_state);
        }
    }
}

impl Tracer for ExecutionTracer {
    type Processor = FastProcessor;

    /// When sufficiently many clock cycles have elapsed, starts a new trace state. Also updates the
    /// internal block stack.
    fn start_clock_cycle(
        &mut self,
        processor: &FastProcessor,
        continuation: Continuation,
        continuation_stack: &ContinuationStack,
        current_forest: &Arc<MastForest>,
    ) {
        // check if we need to start a new trace state
        if processor.system().clock().as_usize().is_multiple_of(self.fragment_size) {
            self.start_new_fragment_context(
                SystemState::from_processor(processor),
                processor
                    .stack_top()
                    .try_into()
                    .expect("stack_top expected to be MIN_STACK_DEPTH elements"),
                continuation_stack.clone(),
                continuation.clone(),
                current_forest.clone(),
            );
        }

        // Capture hasher input state for HPERM/LogPrecompile operations, which will be
        // consumed in `finalize_clock_cycle`. We do this before the block stack match because
        // the processor state has not been mutated yet at this point.
        if let Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } =
            &continuation
        {
            let op = &current_forest[*node_id].unwrap_basic_block().op_batches()[*batch_index]
                .ops()[*op_idx_in_batch];

            match op {
                Operation::HPerm => {
                    self.pending_hasher_input =
                        Some(core::array::from_fn(|i| processor.stack_get(i)));
                },
                Operation::LogPrecompile => {
                    let cap_prev = processor.precompile_transcript_state();
                    let mut input_state = [ZERO; STATE_WIDTH];
                    for i in 0..8 {
                        input_state[i] = processor.stack_get(i);
                    }
                    input_state[8] = cap_prev[0];
                    input_state[9] = cap_prev[1];
                    input_state[10] = cap_prev[2];
                    input_state[11] = cap_prev[3];
                    self.pending_hasher_input = Some(input_state);
                },
                Operation::U32and => {
                    self.pending_op = Some(PendingOp::U32And {
                        a: processor.stack_get(0),
                        b: processor.stack_get(1),
                    });
                    self.try_pop_overflow();
                },
                Operation::U32xor => {
                    self.pending_op = Some(PendingOp::U32Xor {
                        a: processor.stack_get(0),
                        b: processor.stack_get(1),
                    });
                    self.try_pop_overflow();
                },
                Operation::AdvPop => {
                    self.pending_op = Some(PendingOp::AdvPop);
                    self.overflow_table.push(processor.stack_get(15), processor.system().clock());
                },
                Operation::AdvPopW => {
                    self.pending_op = Some(PendingOp::AdvPopW);
                },
                Operation::Pipe => {
                    self.pending_op =
                        Some(PendingOp::Pipe { addr_first_word: processor.stack_get(12) });
                },
                Operation::MStore => {
                    // Record memory write element directly: addr is at stack[0], value at
                    // stack[1]. The processor state has not been mutated yet.
                    self.memory_writes.record_write_element(
                        processor.stack_get(1),
                        processor.stack_get(0),
                        processor.system().ctx(),
                        processor.system().clock(),
                    );
                    self.try_pop_overflow();
                },
                Operation::MStoreW => {
                    // Record memory write word directly: addr is at stack[0], word at
                    // stack[1..5]. The processor state has not been mutated yet.
                    let word: Word = [
                        processor.stack_get(1),
                        processor.stack_get(2),
                        processor.stack_get(3),
                        processor.stack_get(4),
                    ]
                    .into();
                    self.memory_writes.record_write_word(
                        word,
                        processor.stack_get(0),
                        processor.system().ctx(),
                        processor.system().clock(),
                    );
                    self.try_pop_overflow();
                },
                Operation::MLoad => {
                    self.pending_op = Some(PendingOp::MLoad { addr: processor.stack_get(0) });
                },
                Operation::MLoadW => {
                    self.pending_op = Some(PendingOp::MLoadW { addr: processor.stack_get(0) });
                    self.try_pop_overflow();
                },
                Operation::MStream => {
                    self.pending_op =
                        Some(PendingOp::MStream { addr_first_word: processor.stack_get(12) });
                },
                Operation::MrUpdate => {
                    self.pending_op =
                        Some(PendingOp::MrUpdate { old_value: processor.stack_get_word(0) });
                },
                Operation::MpVerify(_) => {
                    self.pending_op = Some(PendingOp::MpVerify);
                },
                // All operations that increment the stack size (except AdvPop which
                // is handled above). The value at stack position 15 is what overflows,
                // and it must be captured before any mutations occur (increment_size is
                // always called before set()).
                Operation::Push(_)
                | Operation::Pad
                | Operation::Dup0
                | Operation::Dup1
                | Operation::Dup2
                | Operation::Dup3
                | Operation::Dup4
                | Operation::Dup5
                | Operation::Dup6
                | Operation::Dup7
                | Operation::Dup9
                | Operation::Dup11
                | Operation::Dup13
                | Operation::Dup15
                | Operation::U32split
                | Operation::SDepth
                | Operation::Clk => {
                    self.overflow_table.push(processor.stack_get(15), processor.system().clock());
                },
                Operation::CryptoStream => {
                    self.pending_op = Some(PendingOp::CryptoStream {
                        src_addr: processor.stack_get(12),
                        dst_addr: processor.stack_get(13),
                    });
                },
                Operation::EvalCircuit => {
                    self.pending_op = Some(PendingOp::EvalCircuit);
                },
                // All operations that decrement the stack size which don't already
                // have a match arm above.
                Operation::Assert(_)
                | Operation::Drop
                | Operation::Add
                | Operation::Mul
                | Operation::And
                | Operation::Or
                | Operation::Eq
                | Operation::U32add3
                | Operation::U32madd
                | Operation::CSwap
                | Operation::CSwapW
                | Operation::FriE2F4 => {
                    self.try_pop_overflow();
                },
                _ => {},
            }
        }

        // Update block stack
        match continuation {
            Continuation::ResumeBasicBlock { .. } => {
                // do nothing, since operations in a basic block don't update the block stack
            },
            Continuation::StartNode(mast_node_id) => match &current_forest[mast_node_id] {
                MastNode::Join(_) => {
                    self.record_control_node_start(
                        &current_forest[mast_node_id],
                        processor,
                        current_forest,
                    );
                },
                MastNode::Split(_) | MastNode::Loop(_) => {
                    // Split and Loop both drop the condition from the stack.
                    self.try_pop_overflow();
                    self.record_control_node_start(
                        &current_forest[mast_node_id],
                        processor,
                        current_forest,
                    );
                },
                MastNode::Call(_) => {
                    self.record_control_node_start(
                        &current_forest[mast_node_id],
                        processor,
                        current_forest,
                    );
                    // Defer overflow_table.start_context() to finalize_clock_cycle.
                    self.pending_start_context = true;
                },
                MastNode::Dyn(dyn_node) => {
                    // Record memory read for callee hash loaded from memory at stack[0].
                    let mem_addr = processor.stack_get(0);
                    let ctx = processor.system().ctx();
                    let clk = processor.system().clock();
                    let word = processor
                        .memory()
                        .read_word(ctx, mem_addr, clk)
                        .expect("dyn callee hash memory read should succeed");
                    self.memory_reads.record_read_word(word, mem_addr, ctx, clk);

                    // Dyn/Dyncall drops the memory address from the stack.
                    self.try_pop_overflow();

                    self.record_control_node_start(
                        &current_forest[mast_node_id],
                        processor,
                        current_forest,
                    );

                    if dyn_node.is_dyncall() {
                        // Defer overflow_table.start_context() to finalize_clock_cycle,
                        // because decrement_size (which interacts with the overflow table)
                        // is called before start_context for dyncall.
                        self.pending_start_context = true;
                    }
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
            Continuation::Respan { node_id: _, batch_index: _ } => {
                self.block_stack.peek_mut().addr += HASH_CYCLE_LEN_FELT;
            },
            Continuation::FinishLoop { node_id: _, was_entered }
                if was_entered && processor.stack_get(0) == ONE =>
            {
                // This is a REPEAT operation; it drops the condition from the stack
                // but doesn't affect the block stack.
                self.try_pop_overflow();
            },
            Continuation::FinishJoin(_)
            | Continuation::FinishSplit(_)
            | Continuation::FinishCall(_)
            | Continuation::FinishDyn(_)
            | Continuation::FinishLoop { .. } // not a REPEAT, which is handled separately above
            | Continuation::FinishBasicBlock(_) => {
                // FinishLoop END drops the condition from the stack only if the loop
                // was entered.
                if let Continuation::FinishLoop { was_entered, .. } = &continuation {
                    if *was_entered {
                        self.try_pop_overflow();
                    }
                }

                // This is an END operation; pop the block stack and record the node end
                let block_info = self.block_stack.pop();
                self.record_node_end(&block_info);

                if let Some(ctx_info) = block_info.ctx_info {
                    self.record_execution_context(ExecutionContextSystemInfo {
                        parent_ctx: ctx_info.parent_ctx,
                        parent_fn_hash: ctx_info.parent_fn_hash,
                    });

                    // Defer overflow_table.restore_context() to finalize_clock_cycle,
                    // because finalize_clock_cycle is only called when the operation
                    // succeeds (i.e., the stack depth check passes).
                    self.pending_restore_context = true;
                }
            },
            Continuation::FinishExternal(_)
            | Continuation::EnterForest(_)
            | Continuation::AfterExitDecorators(_)
            | Continuation::AfterExitDecoratorsBasicBlock(_) => {
                panic!(
                    "FinishExternal, EnterForest, AfterExitDecorators and AfterExitDecoratorsBasicBlock continuations are guaranteed not to be passed here"
                )
            },
        }
    }

    fn record_mast_forest_resolution(&mut self, node_id: MastNodeId, forest: &Arc<MastForest>) {
        self.external.record_resolution(node_id, forest.clone());
    }

    fn record_hasher_permute(
        &mut self,
        _input_state: [Felt; STATE_WIDTH],
        _output_state: [Felt; STATE_WIDTH],
    ) {
        // no-op: hasher permutation recording is handled in `finalize_clock_cycle` by detecting
        // HPerm/LogPrecompile from the OperationHelperRegisters and reading the input/output
        // states from the processor stack.
    }

    fn record_hasher_build_merkle_root(
        &mut self,
        _node: Word,
        _path: Option<&MerklePath>,
        _index: Felt,
        _output_root: Word,
    ) {
        // no-op: Merkle root build recording is handled in `finalize_clock_cycle` by detecting
        // MpVerify operations. The path is obtained from the advice provider's Merkle store
        // via `get_merkle_path`, and other values come from the unchanged stack.
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
        // no-op: Merkle root update recording is handled in `finalize_clock_cycle` by detecting
        // MrUpdate operations. The path is obtained from the advice provider's updated Merkle
        // store via `get_merkle_path`, and other values come from the pre/post-mutation stack.
    }

    fn record_memory_read_element(
        &mut self,
        _element: Felt,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // no-op: memory read element recording is handled in `start_clock_cycle` and
        // `finalize_clock_cycle`:
        // - For MLoad: addr captured in start_clock_cycle, element from post-mutation stack in
        //   finalize_clock_cycle.
        // - For HornerEvalBase: values from OperationHelperRegisters in finalize_clock_cycle.
        // - For EvalCircuit: values re-read from memory in finalize_clock_cycle.
    }

    fn record_memory_read_word(
        &mut self,
        _word: Word,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // no-op: memory read word recording is handled in `start_clock_cycle` and
        // `finalize_clock_cycle`:
        // - For MLoadW: addr captured in start_clock_cycle, word from post-mutation stack in
        //   finalize_clock_cycle.
        // - For MStream: addr captured in start_clock_cycle, words from post-mutation stack in
        //   finalize_clock_cycle.
        // - For HornerEvalExt: values from OperationHelperRegisters in finalize_clock_cycle.
        // - For CryptoStream: src_addr captured in start_clock_cycle, values re-read from memory in
        //   finalize_clock_cycle.
        // - For EvalCircuit: values re-read from memory in finalize_clock_cycle.
        // - For Dyn/Dyncall: recorded directly in start_clock_cycle.
    }

    fn record_memory_write_element(
        &mut self,
        _element: Felt,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // no-op: memory write element recording is handled in `start_clock_cycle`:
        // - For MStore operations: addr and value are read from the pre-mutation stack.
        // - For Call (non-syscall) and Dyncall: FMP initialization is recorded in
        //   `record_control_node_start`.
    }

    fn record_memory_write_word(
        &mut self,
        _word: Word,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // no-op: memory write word recording is handled in `start_clock_cycle` and
        // `finalize_clock_cycle`:
        // - For MStoreW: word and addr are read from the pre-mutation stack in `start_clock_cycle`.
        // - For Pipe: words are read from the post-mutation stack, addrs captured in
        //   `start_clock_cycle`, both recorded in `finalize_clock_cycle`.
        // - For CryptoStream: ciphertext words are read from the post-mutation stack, dst_addr
        //   captured in `start_clock_cycle`, both recorded in `finalize_clock_cycle`.
    }

    fn record_advice_pop_stack(&mut self, _value: Felt) {
        // no-op: advice pop recording is handled in `finalize_clock_cycle` by detecting
        // AdvPop operations and reading the value from the post-mutation stack.
    }

    fn record_advice_pop_stack_word(&mut self, _word: Word) {
        // no-op: advice pop word recording is handled in `finalize_clock_cycle` by detecting
        // AdvPopW operations and reading the word from the post-mutation stack.
    }

    fn record_advice_pop_stack_dword(&mut self, _words: [Word; 2]) {
        // no-op: advice pop dword recording is handled in `finalize_clock_cycle` by detecting
        // Pipe operations and reading the words from the post-mutation stack.
    }

    fn record_u32and(&mut self, _a: Felt, _b: Felt) {
        // no-op: u32and recording is handled in `finalize_clock_cycle` using operands captured
        // in `start_clock_cycle`.
    }

    fn record_u32xor(&mut self, _a: Felt, _b: Felt) {
        // no-op: u32xor recording is handled in `finalize_clock_cycle` using operands captured
        // in `start_clock_cycle`.
    }

    fn record_u32_range_checks(&mut self, _clk: RowIndex, _u32_lo: Felt, _u32_hi: Felt) {
        // no-op: u32 range check recording is handled in `finalize_clock_cycle` by extracting
        // lo/hi values from OperationHelperRegisters.
    }

    fn record_kernel_proc_access(&mut self, _proc_hash: Word) {
        // no-op: kernel proc access recording is handled in `start_clock_cycle` via
        // `record_control_node_start` when a syscall Call node is encountered.
    }

    fn record_circuit_evaluation(&mut self, _clk: RowIndex, _circuit_eval: CircuitEvaluation) {
        // no-op: circuit evaluation recording is handled in `finalize_clock_cycle` by detecting
        // EvalCircuit operations and fetching the circuit from the processor's Ace chiplet.
    }

    fn finalize_clock_cycle(
        &mut self,
        processor: &FastProcessor,
        op_helper_registers: OperationHelperRegisters,
        _current_forest: &Arc<MastForest>,
    ) {
        // Record hasher permutation for HPERM and LOG_PRECOMPILE operations.
        // The input_state was captured in `start_clock_cycle`; the output_state is on the stack
        // after the operation.
        if matches!(
            op_helper_registers,
            OperationHelperRegisters::HPerm { .. } | OperationHelperRegisters::LogPrecompile { .. }
        ) {
            let input_state = self
                .pending_hasher_input
                .take()
                .expect("pending_hasher_input should be set for HPerm/LogPrecompile");

            let output_state: [Felt; STATE_WIDTH] =
                core::array::from_fn(|i| processor.stack_get(i));

            self.hasher_for_chiplet.record_permute_input(input_state);
            self.hasher_chiplet_shim.record_permute_output(output_state);
        }

        // Record u32 range checks from OperationHelperRegisters. The lo/hi values used for
        // range checking are embedded in the helper register variants for all u32 operations.
        let range_check_values = match &op_helper_registers {
            OperationHelperRegisters::U32Split { lo, hi } => Some((*lo, *hi)),
            OperationHelperRegisters::U32Add { sum, carry } => Some((*sum, *carry)),
            OperationHelperRegisters::U32Add3 { sum, carry } => Some((*sum, *carry)),
            OperationHelperRegisters::U32Sub { second_new } => Some((*second_new, ZERO)),
            OperationHelperRegisters::U32Mul { lo, hi } => Some((*lo, *hi)),
            OperationHelperRegisters::U32Madd { lo, hi } => Some((*lo, *hi)),
            OperationHelperRegisters::U32Div { lo, hi } => Some((*lo, *hi)),
            OperationHelperRegisters::U32Assert2 { first, second } => Some((*first, *second)),
            _ => None,
        };
        if let Some((u32_lo, u32_hi)) = range_check_values {
            let (t1, t0) = split_u32_into_u16(u32_lo.as_canonical_u64());
            let (t3, t2) = split_u32_into_u16(u32_hi.as_canonical_u64());
            self.range_checker
                .record_range_check_u32(processor.system().clock(), [t0, t1, t2, t3]);
        }

        // Record memory reads for HornerEvalBase and HornerEvalExt operations.
        // The evaluation point alpha (and k0, k1 for ext) come from the helper registers, and
        // the memory address is at stack[13] which is unchanged by these operations.
        match &op_helper_registers {
            OperationHelperRegisters::HornerEvalBase { alpha, .. } => {
                let addr = processor.stack_get(13);
                let ctx = processor.system().ctx();
                let clk = processor.system().clock();
                let coeffs = alpha.as_basis_coefficients_slice();
                self.memory_reads.record_read_element(coeffs[0], addr, ctx, clk);
                self.memory_reads.record_read_element(coeffs[1], addr + ONE, ctx, clk);
            },
            OperationHelperRegisters::HornerEvalExt { alpha, k0, k1, .. } => {
                let addr = processor.stack_get(13);
                let ctx = processor.system().ctx();
                let clk = processor.system().clock();
                let coeffs = alpha.as_basis_coefficients_slice();
                let word: Word = [coeffs[0], coeffs[1], *k0, *k1].into();
                self.memory_reads.record_read_word(word, addr, ctx, clk);
            },
            _ => {},
        }

        // Handle pending operations that were detected in `start_clock_cycle`.
        if let Some(pending_op) = self.pending_op.take() {
            match pending_op {
                PendingOp::U32And { a, b } => {
                    self.bitwise.record_u32and(a, b);
                },
                PendingOp::U32Xor { a, b } => {
                    self.bitwise.record_u32xor(a, b);
                },
                PendingOp::AdvPop => {
                    let value = processor.stack_get(0);
                    self.advice.record_pop_stack(value);
                },
                PendingOp::AdvPopW => {
                    let word = processor.stack_get_word(0);
                    self.advice.record_pop_stack_word(word);
                },
                PendingOp::Pipe { addr_first_word } => {
                    let words = [processor.stack_get_word(0), processor.stack_get_word(4)];
                    self.advice.record_pop_stack_dword(words);

                    // Record memory writes for the two words piped from advice to memory.
                    let ctx = processor.system().ctx();
                    let clk = processor.system().clock();
                    let addr_second_word = addr_first_word + Felt::new(4);
                    self.memory_writes.record_write_word(words[0], addr_first_word, ctx, clk);
                    self.memory_writes.record_write_word(words[1], addr_second_word, ctx, clk);
                },
                PendingOp::CryptoStream { src_addr, dst_addr } => {
                    let ctx = processor.system().ctx();
                    let clk = processor.system().clock();
                    let src_addr_word2 = src_addr + Felt::new(4);
                    let dst_addr_word2 = dst_addr + Felt::new(4);

                    // Record memory reads for the two plaintext words from source.
                    let plaintext_word1 = processor
                        .memory()
                        .read_word(ctx, src_addr, clk)
                        .expect("CryptoStream source memory read should succeed");
                    let plaintext_word2 = processor
                        .memory()
                        .read_word(ctx, src_addr_word2, clk)
                        .expect("CryptoStream source memory read should succeed");
                    self.memory_reads.record_read_word(plaintext_word1, src_addr, ctx, clk);
                    self.memory_reads.record_read_word(plaintext_word2, src_addr_word2, ctx, clk);

                    // Record memory writes for the two ciphertext words to destination.
                    let ciphertext_word1 = processor.stack_get_word(0);
                    let ciphertext_word2 = processor.stack_get_word(4);
                    self.memory_writes.record_write_word(ciphertext_word1, dst_addr, ctx, clk);
                    self.memory_writes.record_write_word(
                        ciphertext_word2,
                        dst_addr_word2,
                        ctx,
                        clk,
                    );
                },
                PendingOp::EvalCircuit => {
                    let clk = processor.system().clock();
                    let ctx = processor.system().ctx();

                    // Record circuit evaluation.
                    let circuit_eval = processor.ace.circuit_evaluations[&clk].clone();
                    self.ace.record_circuit_evaluation(clk, circuit_eval);

                    // Record memory reads for the circuit evaluation.
                    let mut ptr = processor.stack_get(0);
                    let num_vars = processor.stack_get(1).as_canonical_u64();
                    let num_eval = processor.stack_get(2).as_canonical_u64();
                    let num_read_rows = num_vars / 2;

                    // Word reads for the READ section.
                    for _ in 0..num_read_rows {
                        let word = processor
                            .memory()
                            .read_word(ctx, ptr, clk)
                            .expect("EvalCircuit memory read should succeed");
                        self.memory_reads.record_read_word(word, ptr, ctx, clk);
                        ptr += PTR_OFFSET_WORD;
                    }
                    // Element reads for the EVAL section.
                    for _ in 0..num_eval {
                        let element = processor
                            .memory()
                            .read_element(ctx, ptr)
                            .expect("EvalCircuit memory read should succeed");
                        self.memory_reads.record_read_element(element, ptr, ctx, clk);
                        ptr += PTR_OFFSET_ELEM;
                    }
                },
                PendingOp::MLoad { addr } => {
                    // Post-mutation: the read element is at stack[0].
                    let element = processor.stack_get(0);
                    let ctx = processor.system().ctx();
                    let clk = processor.system().clock();
                    self.memory_reads.record_read_element(element, addr, ctx, clk);
                },
                PendingOp::MLoadW { addr } => {
                    // Post-mutation: the read word is at stack[0..4].
                    let word = processor.stack_get_word(0);
                    let ctx = processor.system().ctx();
                    let clk = processor.system().clock();
                    self.memory_reads.record_read_word(word, addr, ctx, clk);
                },
                PendingOp::MStream { addr_first_word } => {
                    // Post-mutation: the two words are at stack[0..8].
                    let word1 = processor.stack_get_word(0);
                    let word2 = processor.stack_get_word(4);
                    let ctx = processor.system().ctx();
                    let clk = processor.system().clock();
                    let addr_second_word = addr_first_word + Felt::new(4);
                    self.memory_reads.record_read_word(word1, addr_first_word, ctx, clk);
                    self.memory_reads.record_read_word(word2, addr_second_word, ctx, clk);
                },
                PendingOp::MrUpdate { old_value } => {
                    // Post-mutation: new_root replaced old_value at stack[0..4].
                    // depth, index, old_root, new_value are unchanged.
                    let new_root = processor.stack_get_word(0);
                    let depth = processor.stack_get(4);
                    let index = processor.stack_get(5);
                    let old_root = processor.stack_get_word(6);
                    let new_value = processor.stack_get_word(10);

                    // After update_merkle_node, the advice provider contains the updated
                    // tree, so get_merkle_path with the new root returns the correct path.
                    let path = processor
                        .advice_provider()
                        .get_merkle_path(new_root, depth, index)
                        .expect("MrUpdate Merkle path should be available after update");

                    self.hasher_chiplet_shim.record_update_merkle_root(&path, old_root, new_root);
                    self.hasher_for_chiplet
                        .record_update_merkle_root(old_value, new_value, path, index);
                },
                PendingOp::MpVerify => {
                    // Stack is unchanged by MpVerify, so all values are available post-mutation.
                    let node = processor.stack_get_word(0);
                    let depth = processor.stack_get(4);
                    let index = processor.stack_get(5);
                    let root = processor.stack_get_word(6);

                    // The advice provider is not modified by MpVerify, so we can get the
                    // Merkle path directly.
                    let path = processor
                        .advice_provider()
                        .get_merkle_path(root, depth, index)
                        .expect("MpVerify Merkle path should be available");

                    self.hasher_chiplet_shim.record_build_merkle_root(&path, root);
                    self.hasher_for_chiplet.record_build_merkle_root(node, path, index);
                },
            }
        }

        // Start a new overflow table context for Call/Syscall/Dyncall. This is deferred from
        // start_clock_cycle because for Dyncall, decrement_size (which pops from the overflow
        // table in the current context) happens before start_context.
        if self.pending_start_context {
            self.overflow_table.start_context();
            self.pending_start_context = false;
        }

        // Restore the overflow table context for Call/Syscall/Dyncall END. This is deferred
        // from start_clock_cycle because finalize_clock_cycle is only called when the operation
        // succeeds (i.e., the stack depth check in processor.restore_context() passes).
        if self.pending_restore_context {
            self.overflow_table.restore_context();
            self.overflow_replay.record_restore_context_overflow_addr(
                MIN_STACK_DEPTH + self.overflow_table.num_elements_in_current_ctx(),
                self.overflow_table.last_update_clk_in_current_ctx(),
            );
            self.pending_restore_context = false;
        }
    }

    fn increment_stack_size(&mut self, _processor: &FastProcessor) {
        // no-op: overflow table push is handled in `start_clock_cycle` by detecting all
        // operations that increment the stack size (Push, Pad, Dup*, U32split, SDepth, Clk,
        // AdvPop) and capturing `stack_get(15)` before any mutations occur.
    }

    fn decrement_stack_size(&mut self) {
        // no-op: overflow table pop is handled in `start_clock_cycle` by detecting all
        // operations and control flow continuations that decrement the stack size.
    }

    fn start_context(&mut self) {
        // no-op: overflow table context start is handled in `finalize_clock_cycle` when
        // `pending_start_context` flag is set. The flag is set in `start_clock_cycle` for
        // Call/Syscall/Dyncall nodes.
    }

    fn restore_context(&mut self) {
        // no-op: overflow table context restore is handled in `start_clock_cycle` when
        // encountering FinishCall/FinishDyn continuations with context info.
    }
}

/// Tracks which operation is being executed in the current clock cycle, along with any
/// pre-mutation state that needs to be captured in `start_clock_cycle` for consumption in
/// `finalize_clock_cycle`.
#[derive(Debug)]
enum PendingOp {
    /// U32and operation: operands captured before the operation.
    U32And { a: Felt, b: Felt },
    /// U32xor operation: operands captured before the operation.
    U32Xor { a: Felt, b: Felt },
    /// AdvPop operation: value will be read from stack after the operation.
    AdvPop,
    /// AdvPopW operation: word will be read from stack after the operation.
    AdvPopW,
    /// Pipe operation: two words will be read from stack after the operation.
    /// Also records memory writes of the two words to `addr_first_word` and `addr_first_word + 4`.
    Pipe { addr_first_word: Felt },
    /// CryptoStream operation: records memory reads of two plaintext words from `src_addr` and
    /// `src_addr + 4`, and memory writes of two ciphertext words to `dst_addr` and `dst_addr + 4`.
    CryptoStream { src_addr: Felt, dst_addr: Felt },
    /// EvalCircuit operation: circuit evaluation will be fetched from the processor's Ace chiplet
    /// after the operation, and memory reads will be replayed.
    EvalCircuit,
    /// MLoad operation: memory read element will be recorded using the captured addr and the
    /// post-mutation stack value.
    MLoad { addr: Felt },
    /// MLoadW operation: memory read word will be recorded using the captured addr and the
    /// post-mutation stack word.
    MLoadW { addr: Felt },
    /// MStream operation: two memory read words will be recorded using the captured addr and the
    /// post-mutation stack values.
    MStream { addr_first_word: Felt },
    /// MrUpdate operation: old_value is captured before the operation overwrites stack[0..4]
    /// with new_root.
    MrUpdate { old_value: Word },
    /// MpVerify operation: all values are available post-mutation since the stack is unchanged.
    MpVerify,
}

// HASHER CHIPLET SHIM
// ================================================================================================

/// The number of hasher rows per permutation operation. This is used to compute the address for
/// the next operation in the hasher chiplet.
const NUM_HASHER_ROWS_PER_PERMUTATION: u32 = HASH_CYCLE_LEN as u32;

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
    hasher_replay: HasherResponseReplay,
    block_addr_replay: BlockAddressReplay,
}

impl HasherChipletShim {
    /// Creates a new [HasherChipletShim].
    pub fn new() -> Self {
        Self {
            addr: 1,
            hasher_replay: HasherResponseReplay::default(),
            block_addr_replay: BlockAddressReplay::default(),
        }
    }

    /// Records the address returned from a call to `Hasher::hash_control_block()`.
    pub fn record_hash_control_block(&mut self) -> Felt {
        let block_addr = Felt::from_u32(self.addr);

        self.block_addr_replay.record_block_address(block_addr);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION;

        block_addr
    }

    /// Records the address returned from a call to `Hasher::hash_basic_block()`.
    pub fn record_hash_basic_block(&mut self, basic_block_node: &BasicBlockNode) -> Felt {
        let block_addr = Felt::from_u32(self.addr);

        self.block_addr_replay.record_block_address(block_addr);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION * basic_block_node.num_op_batches() as u32;

        block_addr
    }
    /// Records the result of a call to `Hasher::permute()`.
    pub fn record_permute_output(&mut self, hashed_state: [Felt; 12]) {
        self.hasher_replay.record_permute(Felt::from_u32(self.addr), hashed_state);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION;
    }

    /// Records the result of a call to `Hasher::build_merkle_root()`.
    pub fn record_build_merkle_root(&mut self, path: &MerklePath, computed_root: Word) {
        self.hasher_replay
            .record_build_merkle_root(Felt::from_u32(self.addr), computed_root);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION * path.depth() as u32;
    }

    /// Records the result of a call to `Hasher::update_merkle_root()`.
    pub fn record_update_merkle_root(&mut self, path: &MerklePath, old_root: Word, new_root: Word) {
        self.hasher_replay
            .record_update_merkle_root(Felt::from_u32(self.addr), old_root, new_root);

        // The Merkle path is verified twice: once for the old root and once for the new root.
        self.addr += 2 * NUM_HASHER_ROWS_PER_PERMUTATION * path.depth() as u32;
    }

    pub fn extract_replay(&mut self) -> (HasherResponseReplay, BlockAddressReplay) {
        (
            core::mem::take(&mut self.hasher_replay),
            core::mem::take(&mut self.block_addr_replay),
        )
    }
}

impl Default for HasherChipletShim {
    fn default() -> Self {
        Self::new()
    }
}
