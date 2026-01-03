use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use miden_air::trace::{
    RowIndex,
    chiplets::hasher::{HasherState, STATE_WIDTH},
};
use miden_core::{
    Felt, ONE, Word, ZERO,
    crypto::merkle::MerklePath,
    mast::{MastForest, MastNodeId, OpBatch},
    precompile::PrecompileTranscriptState,
    stack::MIN_STACK_DEPTH,
};

use crate::{
    AdviceError, ContextId, ErrorContext, ExecutionError,
    chiplets::CircuitEvaluation,
    continuation_stack::ContinuationStack,
    fast::FastProcessor,
    processor::{AdviceProviderInterface, HasherInterface, MemoryInterface},
};

// TRACE FRAGMENT CONTEXT
// ================================================================================================

/// Information required to build a core trace fragment (i.e. the system, decoder and stack
/// columns).
///
/// This struct is meant to be built by the processor, and consumed mutably by a core trace fragment
/// builder. That is, as core trace generation progresses, this struct can be mutated to represent
/// the generation context at any clock cycle within the fragment.
///
/// This struct is conceptually divided into 4 main components:
/// 1. core trace state: the state of the processor at any clock cycle in the fragment, initialized
///    to the state at the first clock cycle in the fragment,
/// 2. execution replay: information needed to replay the execution of the processor for the
///    remainder of the fragment,
/// 3. continuation: a stack of continuations for the processor representing the nodes in the MAST
///    forest to execute when the current node is done executing,
/// 4. initial state: some information about the state of the execution at the start of the
///    fragment. This includes the [`MastForest`] that is being executed at the start of the
///    fragment (which can change when encountering an [`miden_core::mast::ExternalNode`] or
///    [`miden_core::mast::DynNode`]), and the current node's execution state, which contains
///    additional information to pinpoint exactly where in the processing of the node we're at when
///    this fragment begins.
#[derive(Debug)]
pub struct CoreTraceFragmentContext {
    pub state: CoreTraceState,
    pub replay: ExecutionReplay,
    pub continuation: ContinuationStack,
    pub initial_mast_forest: Arc<MastForest>,
    pub initial_execution_state: NodeExecutionState,
}

// CORE TRACE STATE
// ================================================================================================

/// Subset of the processor state used to build the core trace (system, decoder and stack sets of
/// columns).
#[derive(Debug)]
pub struct CoreTraceState {
    pub system: SystemState,
    pub decoder: DecoderState,
    pub stack: StackState,
}

// SYSTEM STATE
// ================================================================================================

/// The `SystemState` represents all the information needed to build one row of the System trace.
///
/// This struct captures the complete state of the system at a specific clock cycle, allowing for
/// reconstruction of the system trace during concurrent execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemState {
    /// Current clock cycle (row index in the trace)
    pub clk: RowIndex,

    /// Execution context ID - starts at 0 (root context), changes on CALL/SYSCALL operations
    pub ctx: ContextId,

    /// Hash of the function that initiated the current execution context
    /// - For root context: [ZERO; 4]
    /// - For CALL/DYNCALL contexts: hash of the called function
    /// - For SYSCALL contexts: hash remains from the calling function
    pub fn_hash: Word,

    /// Precompile transcript state (sponge capacity) used for recording `log_precompile` calls
    /// - Initially [ZERO; 4]
    /// - Updated with each `log_precompile` invocation
    pub pc_transcript_state: PrecompileTranscriptState,
}

impl SystemState {
    /// Convenience constructor that creates a new `SystemState` from a `FastProcessor`.
    pub fn from_processor(processor: &FastProcessor) -> Self {
        Self {
            clk: processor.clk,
            ctx: processor.ctx,
            fn_hash: processor.caller_hash,
            pc_transcript_state: processor.pc_transcript.state(),
        }
    }
}

// DECODER STATE
// ================================================================================================

/// The subset of the decoder state required to build the trace.
#[derive(Debug)]
pub struct DecoderState {
    /// The value of the [miden_air::trace::decoder::ADDR_COL_IDX] column
    pub current_addr: Felt,
    /// The address of the current MAST node's parent.
    pub parent_addr: Felt,
}

impl DecoderState {
    /// This function is called when start executing a node (e.g. `JOIN`, `SPLIT`, etc). It emulates
    /// pushing a new node onto the block stack, and updates the decoder state to point to the
    /// current node in the block stack. Hence, the `current_addr` is set to the (replayed) address
    /// of the current node, and the `parent_addr` is set to the (replayed) address of the parent
    /// node (i.e. the node previously on top of the block stack).
    pub fn replay_node_start(&mut self, replay: &mut ExecutionReplay) {
        self.current_addr = replay.hasher.replay_block_address();
        self.parent_addr = replay.block_stack.replay_node_start_parent_addr();
    }

    /// This function is called when we hit an `END` operation, signaling the end of execution for a
    /// node. It updates the decoder state to point to the previous node in the block stack (which
    /// could be renamed to "node stack"), and returns the address of the node that just ended,
    /// along with any flags associated with it.
    pub fn replay_node_end(&mut self, replay: &mut ExecutionReplay) -> (Felt, NodeFlags) {
        let node_end_data = replay.block_stack.replay_node_end();

        self.current_addr = node_end_data.prev_addr;
        self.parent_addr = node_end_data.prev_parent_addr;

        (node_end_data.ended_node_addr, node_end_data.flags)
    }
}

// STACK STATE
// ================================================================================================

/// This struct captures the state of the top 16 elements of the stack at a specific clock cycle;
/// that is, those elements that are written directly into the trace.
///
/// The stack trace consists of 19 columns total: 16 stack columns + 3 helper columns. The helper
/// columns (stack_depth, overflow_addr, and overflow_helper) are computed from the stack_depth and
/// last_overflow_addr fields.
#[derive(Debug)]
pub struct StackState {
    /// Top 16 stack slots (s0 to s15). These represent the top elements of the stack that are
    /// directly accessible.
    pub stack_top: [Felt; MIN_STACK_DEPTH], // 16 columns

    /// Current number of elements on the stack. It is guaranteed to be >= 16.
    stack_depth: usize,

    /// The last recorded overflow address for the stack - which is the clock cycle at which the
    /// last item was pushed to the overflow
    last_overflow_addr: Felt,
}

impl StackState {
    /// Creates a new StackState with the provided parameters.
    ///
    /// `stack_top` should be the top 16 elements of the stack stored in reverse order, i.e.,
    /// `stack_top[15]` is the topmost element (s0), and `stack_top[0]` is the bottommost element
    /// (s15).
    pub fn new(
        stack_top: [Felt; MIN_STACK_DEPTH],
        stack_depth: usize,
        last_overflow_addr: Felt,
    ) -> Self {
        Self {
            stack_top,
            stack_depth,
            last_overflow_addr,
        }
    }

    /// Returns the value at the specified index in the stack top.
    ///
    /// # Panics
    /// - if the index is greater than or equal to [MIN_STACK_DEPTH].
    pub fn get(&self, index: usize) -> Felt {
        self.stack_top[MIN_STACK_DEPTH - index - 1]
    }

    /// Returns the stack depth (b0 helper column)
    pub fn stack_depth(&self) -> usize {
        self.stack_depth
    }

    /// Returns the overflow address (b1 helper column) using the stack overflow replay
    pub fn overflow_addr(&mut self) -> Felt {
        self.last_overflow_addr
    }

    /// Returns the number of elements in the current context's overflow stack.
    pub fn num_overflow_elements_in_current_ctx(&self) -> usize {
        debug_assert!(self.stack_depth >= MIN_STACK_DEPTH);
        self.stack_depth - MIN_STACK_DEPTH
    }

    /// Pushes the given element onto the overflow stack at the provided clock cycle.
    pub fn push_overflow(&mut self, _element: Felt, clk: RowIndex) {
        self.stack_depth += 1;
        self.last_overflow_addr = clk.into();
    }

    /// Pops the top element from the overflow stack at the provided clock cycle, if any.
    ///
    /// If the overflow table is empty (i.e. stack depth is 16), the stack depth is unchanged, and
    /// None is returned.
    pub fn pop_overflow(
        &mut self,
        stack_overflow_replay: &mut StackOverflowReplay,
    ) -> Option<Felt> {
        debug_assert!(self.stack_depth >= MIN_STACK_DEPTH);

        if self.stack_depth > MIN_STACK_DEPTH {
            let (stack_value, new_overflow_addr) = stack_overflow_replay.replay_pop_overflow();
            self.stack_depth -= 1;
            self.last_overflow_addr = new_overflow_addr;
            Some(stack_value)
        } else {
            self.last_overflow_addr = ZERO;
            None
        }
    }

    /// Derives the denominator of the overflow helper (h0 helper column) from the current stack
    /// depth.
    ///
    /// It is expected that this values gets later inverted via batch inversion.
    pub fn overflow_helper(&self) -> Felt {
        let denominator = self.stack_depth() - MIN_STACK_DEPTH;
        Felt::new(denominator as u64)
    }

    /// Starts a new execution context for this stack and returns a tuple consisting of the current
    /// stack depth and the address of the overflow table row prior to starting the new context.
    ///
    /// This has the effect of hiding the contents of the overflow table such that it appears as
    /// if the overflow table in the new context is empty.
    pub fn start_context(&mut self) -> (usize, Felt) {
        // Return the current stack depth and overflow address at the start of a new context
        let current_depth = self.stack_depth;
        let current_overflow_addr = self.last_overflow_addr;

        // Reset stack depth to minimum (parallel to Process Stack behavior)
        self.stack_depth = MIN_STACK_DEPTH;
        self.last_overflow_addr = ZERO;

        (current_depth, current_overflow_addr)
    }

    /// Restores the prior context for this stack.
    ///
    /// This has the effect bringing back items previously hidden from the overflow table.
    pub fn restore_context(&mut self, stack_overflow_replay: &mut StackOverflowReplay) {
        let (stack_depth, last_overflow_addr) =
            stack_overflow_replay.replay_restore_context_overflow_addr();
        // Restore stack depth to the value from before the context switch (parallel to Process
        // Stack behavior)
        self.stack_depth = stack_depth;
        self.last_overflow_addr = last_overflow_addr;
    }
}

/// Replay data necessary to build a trace fragment.
///
/// During execution, the processor records information to be replayed by the corresponding trace
/// generator. This is done due to the fact that the trace generators don't have access to some
/// components needed to produce those values, such as the memory chiplet, advice provider, etc. It
/// also packages up all the necessary data for trace generators to generate trace fragments, which
/// can be done on separate machines in parallel, for example.
#[derive(Debug, Default)]
pub struct ExecutionReplay {
    pub block_stack: BlockStackReplay,
    pub stack_overflow: StackOverflowReplay,
    pub memory_reads: MemoryReadsReplay,
    pub advice: AdviceReplay,
    pub hasher: HasherResponseReplay,
    pub mast_forest_resolution: MastForestResolutionReplay,
}

// BLOCK STACK REPLAY
// ================================================================================================

/// Replay data for the block stack.
#[derive(Debug, Default)]
pub struct BlockStackReplay {
    /// The parent address, recorded when a new node is started (JOIN, SPLIT, etc).
    node_start_parent_addr: VecDeque<Felt>,
    /// The data needed to recover the state on an END operation.
    node_end: VecDeque<NodeEndData>,
    /// Extra data needed to recover the state on an END operation specifically for
    /// CALL/SYSCALL/DYNCALL nodes (which start/end a new execution context).
    execution_contexts: VecDeque<ExecutionContextSystemInfo>,
}

impl BlockStackReplay {
    /// Creates a new instance of `BlockStackReplay`.
    pub fn new() -> Self {
        Self {
            node_start_parent_addr: VecDeque::new(),
            node_end: VecDeque::new(),
            execution_contexts: VecDeque::new(),
        }
    }

    /// Records the node's parent address
    pub fn record_node_start_parent_addr(&mut self, parent_addr: Felt) {
        self.node_start_parent_addr.push_back(parent_addr);
    }

    /// Records the necessary data needed to properly recover the state on an END operation.
    ///
    /// See [NodeEndData] for more details.
    pub fn record_node_end(
        &mut self,
        ended_node_addr: Felt,
        flags: NodeFlags,
        prev_addr: Felt,
        prev_parent_addr: Felt,
    ) {
        self.node_end.push_back(NodeEndData {
            ended_node_addr,
            flags,
            prev_addr,
            prev_parent_addr,
        });
    }

    /// Records an execution context system info for a CALL/SYSCALL/DYNCALL operation.
    pub fn record_execution_context(&mut self, ctx_info: ExecutionContextSystemInfo) {
        self.execution_contexts.push_back(ctx_info);
    }

    /// Replays the node's parent address
    pub fn replay_node_start_parent_addr(&mut self) -> Felt {
        self.node_start_parent_addr
            .pop_front()
            .expect("No node start parent address recorded")
    }

    /// Replays the data needed to recover the state on an END operation.
    pub fn replay_node_end(&mut self) -> NodeEndData {
        self.node_end.pop_front().expect("No node address and flags recorded")
    }

    /// Replays the next recorded execution context system info.
    pub fn replay_execution_context(&mut self) -> ExecutionContextSystemInfo {
        self.execution_contexts.pop_front().expect("No execution context recorded")
    }
}

/// The flags written in the second word of the hasher state for END operations.
#[derive(Debug)]
pub struct NodeFlags {
    is_loop_body: bool,
    loop_entered: bool,
    is_call: bool,
    is_syscall: bool,
}

impl NodeFlags {
    /// Creates a new instance of `NodeFlags`.
    pub fn new(is_loop_body: bool, loop_entered: bool, is_call: bool, is_syscall: bool) -> Self {
        Self {
            is_loop_body,
            loop_entered,
            is_call,
            is_syscall,
        }
    }

    /// Returns ONE if this node is a body of a LOOP node; otherwise returns ZERO.
    pub fn is_loop_body(&self) -> Felt {
        if self.is_loop_body { ONE } else { ZERO }
    }

    /// Returns ONE if this is a LOOP node and the body of the loop was executed at
    /// least once; otherwise, returns ZERO.
    pub fn loop_entered(&self) -> Felt {
        if self.loop_entered { ONE } else { ZERO }
    }

    /// Returns ONE if this node is a CALL or DYNCALL; otherwise returns ZERO.
    pub fn is_call(&self) -> Felt {
        if self.is_call { ONE } else { ZERO }
    }

    /// Returns ONE if this node is a SYSCALL; otherwise returns ZERO.
    pub fn is_syscall(&self) -> Felt {
        if self.is_syscall { ONE } else { ZERO }
    }

    /// Convenience method that writes the flags in the proper order to be written to the second
    /// word of the hasher state for the trace row of an END operation.
    pub fn to_hasher_state_second_word(&self) -> Word {
        [self.is_loop_body(), self.loop_entered(), self.is_call(), self.is_syscall()].into()
    }
}

/// The data needed to fully recover the state on an END operation.
///
/// We record `ended_node_addr` and `flags` in order to be able to properly populate the trace
/// row for the node operation. Additionally, we record `prev_addr` and `prev_parent_addr` to
/// allow emulating peeking into the block stack, which is needed when processing REPEAT or RESPAN
/// nodes.
#[derive(Debug)]
pub struct NodeEndData {
    /// the address of the node that is ending
    pub ended_node_addr: Felt,
    /// the flags associated with the node that is ending
    pub flags: NodeFlags,
    /// the address of the node sitting on top of the block stack after the END operation (or 0 if
    /// the block stack is empty)
    pub prev_addr: Felt,
    /// the parent address of the node sitting on top of the block stack after the END operation
    /// (or 0 if the block stack is empty)
    pub prev_parent_addr: Felt,
}

/// Data required to recover the state of an execution context when restoring it during an END
/// operation.
#[derive(Debug)]
pub struct ExecutionContextSystemInfo {
    pub parent_ctx: ContextId,
    pub parent_fn_hash: Word,
}

// MAST FOREST RESOLUTION REPLAY
// ================================================================================================

/// Records and replays the resolutions of [`crate::host::AsyncHost::get_mast_forest`] or
/// [`crate::host::SyncHost::get_mast_forest`].
///
/// These calls are made when encountering an [`miden_core::mast::ExternalNode`], or when
/// encountering a [`miden_core::mast::DynNode`] where the procedure hash on the stack refers to
/// a procedure not present in the current forest.
#[derive(Debug, Default)]
pub struct MastForestResolutionReplay {
    mast_forest_resolutions: VecDeque<(MastNodeId, Arc<MastForest>)>,
}

impl MastForestResolutionReplay {
    /// Records a resolution of a MastNodeId with its associated MastForest when encountering an
    /// External node, or `DYN`/`DYNCALL` node with an external procedure hash on the stack.
    pub fn record_resolution(&mut self, node_id: MastNodeId, forest: Arc<MastForest>) {
        self.mast_forest_resolutions.push_back((node_id, forest));
    }

    /// Replays the next recorded MastForest resolution, returning both the node ID and forest
    pub fn replay_resolution(&mut self) -> (MastNodeId, Arc<MastForest>) {
        self.mast_forest_resolutions
            .pop_front()
            .expect("No MastForest resolutions recorded")
    }
}

// MEMORY REPLAY
// ================================================================================================

/// Records and replays all the reads made to memory, in which all elements and words read from
/// memory during a given fragment are recorded by the fast processor, and replayed by the main
/// trace fragment generators.
///
/// This is used to simulate memory reads in parallel trace generation without needing to actually
/// access the memory chiplet.
///
/// Elements/words read are stored with their addresses and are assumed to be read from the same
/// addresses that they were recorded at. This works naturally since the fast processor has exactly
/// the same access patterns as the main trace generators (which re-executes part of the program).
/// The read methods include debug assertions to verify address consistency.
#[derive(Debug, Default)]
pub struct MemoryReadsReplay {
    elements_read: VecDeque<(Felt, Felt, ContextId, RowIndex)>,
    words_read: VecDeque<(Word, Felt, ContextId, RowIndex)>,
}

impl MemoryReadsReplay {
    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records a read element from memory
    pub fn record_read_element(
        &mut self,
        element: Felt,
        addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    ) {
        self.elements_read.push_back((element, addr, ctx, clk));
    }

    /// Records a read word from memory
    pub fn record_read_word(&mut self, word: Word, addr: Felt, ctx: ContextId, clk: RowIndex) {
        self.words_read.push_back((word, addr, ctx, clk));
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------

    pub fn replay_read_element(&mut self, addr: Felt) -> Felt {
        let (element, stored_addr, _ctx, _clk) =
            self.elements_read.pop_front().expect("No elements read from memory");
        debug_assert_eq!(stored_addr, addr, "Address mismatch: expected {addr}, got {stored_addr}");
        element
    }

    pub fn replay_read_word(&mut self, addr: Felt) -> Word {
        let (word, stored_addr, _ctx, _clk) =
            self.words_read.pop_front().expect("No words read from memory");
        debug_assert_eq!(stored_addr, addr, "Address mismatch: expected {addr}, got {stored_addr}");
        word
    }

    /// Returns an iterator over all recorded memory element reads, yielding tuples of
    /// (element, address, context ID, clock cycle).
    pub fn iter_read_elements(&self) -> impl Iterator<Item = (Felt, Felt, ContextId, RowIndex)> {
        self.elements_read.iter().copied()
    }

    /// Returns an iterator over all recorded memory word reads, yielding tuples of
    /// (word, address, context ID, clock cycle).
    pub fn iter_read_words(&self) -> impl Iterator<Item = (Word, Felt, ContextId, RowIndex)> {
        self.words_read.iter().copied()
    }
}

/// Records and replays all the writes made to memory, in which all elements written to memory
/// throughout a program's execution are recorded by the fast processor.
///
/// This is separated from [MemoryReadsReplay] since writes are not needed for core trace generation
/// (as reads are), but only to be able to fully build the memory chiplet trace.
#[derive(Debug, Default)]
pub struct MemoryWritesReplay {
    elements_written: VecDeque<(Felt, Felt, ContextId, RowIndex)>,
    words_written: VecDeque<(Word, Felt, ContextId, RowIndex)>,
}

impl MemoryWritesReplay {
    /// Records a write element to memory
    pub fn record_write_element(
        &mut self,
        element: Felt,
        addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    ) {
        self.elements_written.push_back((element, addr, ctx, clk));
    }

    /// Records a write word to memory
    pub fn record_write_word(&mut self, word: Word, addr: Felt, ctx: ContextId, clk: RowIndex) {
        self.words_written.push_back((word, addr, ctx, clk));
    }

    /// Returns an iterator over all recorded memory element writes, yielding tuples of
    /// (element, address, context ID, clock cycle).
    pub fn iter_elements_written(
        &self,
    ) -> impl Iterator<Item = &(Felt, Felt, ContextId, RowIndex)> {
        self.elements_written.iter()
    }

    /// Returns an iterator over all recorded memory word writes, yielding tuples of
    /// (word, address, context ID, clock cycle).
    pub fn iter_words_written(&self) -> impl Iterator<Item = &(Word, Felt, ContextId, RowIndex)> {
        self.words_written.iter()
    }
}

impl MemoryInterface for MemoryReadsReplay {
    fn read_element(
        &mut self,
        _ctx: ContextId,
        addr: Felt,
        _err_ctx: &impl ErrorContext,
    ) -> Result<Felt, crate::MemoryError> {
        Ok(self.replay_read_element(addr))
    }

    fn read_word(
        &mut self,
        _ctx: ContextId,
        addr: Felt,
        _clk: RowIndex,
        _err_ctx: &impl ErrorContext,
    ) -> Result<Word, crate::MemoryError> {
        Ok(self.replay_read_word(addr))
    }

    fn write_element(
        &mut self,
        _ctx: ContextId,
        _addr: Felt,
        _element: Felt,
        _err_ctx: &impl ErrorContext,
    ) -> Result<(), crate::MemoryError> {
        Ok(())
    }

    fn write_word(
        &mut self,
        _ctx: ContextId,
        _addr: Felt,
        _clk: RowIndex,
        _word: Word,
        _err_ctx: &impl ErrorContext,
    ) -> Result<(), crate::MemoryError> {
        Ok(())
    }
}

// ADVICE REPLAY
// ================================================================================================

/// Implements a shim for the advice provider, in which all advice provider operations during a
/// given fragment are pre-recorded by the fast processor.
///
/// This is used to simulate advice provider interactions in parallel trace generation without
/// needing to actually access the advice provider. All advice provider operations are recorded
/// during fast execution and then replayed during parallel trace generation.
///
/// The shim records all operations with their parameters and results, and provides replay methods
/// that return the pre-recorded results. This works naturally since the fast processor has exactly
/// the same access patterns as the main trace generators (which re-executes part of the program).
/// The read methods include debug assertions to verify parameter consistency.
#[derive(Debug, Default)]
pub struct AdviceReplay {
    // Stack operations
    stack_pops: VecDeque<Felt>,
    stack_word_pops: VecDeque<Word>,
    stack_dword_pops: VecDeque<[Word; 2]>,
}

impl AdviceReplay {
    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records the value returned by a pop_stack operation
    pub fn record_pop_stack(&mut self, value: Felt) {
        self.stack_pops.push_back(value);
    }

    /// Records the word returned by a pop_stack_word operation
    pub fn record_pop_stack_word(&mut self, word: Word) {
        self.stack_word_pops.push_back(word);
    }

    /// Records the double word returned by a pop_stack_dword operation
    pub fn record_pop_stack_dword(&mut self, dword: [Word; 2]) {
        self.stack_dword_pops.push_back(dword);
    }

    // ACCESSORS (used during parallel trace generation)
    // --------------------------------------------------------------------------------

    /// Replays a pop_stack operation, returning the previously recorded value
    pub fn replay_pop_stack(&mut self) -> Felt {
        self.stack_pops.pop_front().expect("No stack pop operations recorded")
    }

    /// Replays a pop_stack_word operation, returning the previously recorded word
    pub fn replay_pop_stack_word(&mut self) -> Word {
        self.stack_word_pops.pop_front().expect("No stack word pop operations recorded")
    }

    /// Replays a pop_stack_dword operation, returning the previously recorded double word
    pub fn replay_pop_stack_dword(&mut self) -> [Word; 2] {
        self.stack_dword_pops
            .pop_front()
            .expect("No stack dword pop operations recorded")
    }
}

impl AdviceProviderInterface for AdviceReplay {
    fn pop_stack(&mut self) -> Result<Felt, AdviceError> {
        Ok(self.replay_pop_stack())
    }

    fn pop_stack_word(&mut self) -> Result<Word, AdviceError> {
        Ok(self.replay_pop_stack_word())
    }

    fn pop_stack_dword(&mut self) -> Result<[Word; 2], AdviceError> {
        Ok(self.replay_pop_stack_dword())
    }

    /// Returns an empty Merkle path, as Merkle paths are ignored in parallel trace generation.
    fn get_merkle_path(
        &self,
        _root: Word,
        _depth: Felt,
        _index: Felt,
    ) -> Result<Option<MerklePath>, AdviceError> {
        Ok(None)
    }

    /// Returns an empty Merkle path and root, as they are ignored in parallel trace generation.
    fn update_merkle_node(
        &mut self,
        _root: Word,
        _depth: Felt,
        _index: Felt,
        _value: Word,
    ) -> Result<Option<MerklePath>, AdviceError> {
        Ok(None)
    }
}

// BITWISE REPLAY
// ================================================================================================

/// Enum representing the different bitwise operations that can be recorded.
#[derive(Debug)]
pub enum BitwiseOp {
    U32And,
    U32Xor,
}

/// Replay data for bitwise operations.
#[derive(Debug, Default)]
pub struct BitwiseReplay {
    u32op_with_operands: VecDeque<(BitwiseOp, Felt, Felt)>,
}

impl BitwiseReplay {
    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records the operands of a u32and operation.
    pub fn record_u32and(&mut self, a: Felt, b: Felt) {
        self.u32op_with_operands.push_back((BitwiseOp::U32And, a, b));
    }

    /// Records the operands of a u32xor operation.
    pub fn record_u32xor(&mut self, a: Felt, b: Felt) {
        self.u32op_with_operands.push_back((BitwiseOp::U32Xor, a, b));
    }
}

impl IntoIterator for BitwiseReplay {
    type Item = (BitwiseOp, Felt, Felt);
    type IntoIter = <VecDeque<(BitwiseOp, Felt, Felt)> as IntoIterator>::IntoIter;

    /// Returns an iterator over all recorded u32 operations with their operands.
    fn into_iter(self) -> Self::IntoIter {
        self.u32op_with_operands.into_iter()
    }
}

// KERNEL REPLAY
// ================================================================================================

/// Replay data for kernel operations.
#[derive(Debug, Default)]
pub struct KernelReplay {
    kernel_proc_accesses: VecDeque<Word>,
}

impl KernelReplay {
    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records the procedure hash of a syscall.
    pub fn record_kernel_proc_access(&mut self, proc_hash: Word) {
        self.kernel_proc_accesses.push_back(proc_hash);
    }
}

impl IntoIterator for KernelReplay {
    type Item = Word;
    type IntoIter = <VecDeque<Word> as IntoIterator>::IntoIter;

    /// Returns an iterator over all recorded kernel procedure accesses.
    fn into_iter(self) -> Self::IntoIter {
        self.kernel_proc_accesses.into_iter()
    }
}

// ACE REPLAY
// ================================================================================================

/// Replay data for ACE operations.
#[derive(Debug, Default)]
pub struct AceReplay {
    circuit_evaluations: VecDeque<(RowIndex, CircuitEvaluation)>,
}

impl AceReplay {
    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records the procedure hash of a syscall.
    pub fn record_circuit_evaluation(&mut self, clk: RowIndex, circuit_eval: CircuitEvaluation) {
        self.circuit_evaluations.push_back((clk, circuit_eval));
    }
}

impl IntoIterator for AceReplay {
    type Item = (RowIndex, CircuitEvaluation);
    type IntoIter = <VecDeque<(RowIndex, CircuitEvaluation)> as IntoIterator>::IntoIter;

    /// Returns an iterator over all recorded circuit evaluations.
    fn into_iter(self) -> Self::IntoIter {
        self.circuit_evaluations.into_iter()
    }
}

// RANGE CHECKER REPLAY
// ================================================================================================

/// Replay data for range checking operations.
///
/// This currently only records
#[derive(Debug, Default)]
pub struct RangeCheckerReplay {
    range_checks_u32_ops: VecDeque<(RowIndex, [u16; 4])>,
}

impl RangeCheckerReplay {
    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records the set of range checks which result from a u32 operation.
    pub fn record_range_check_u32(&mut self, row_index: RowIndex, u16_limbs: [u16; 4]) {
        self.range_checks_u32_ops.push_back((row_index, u16_limbs));
    }
}

impl IntoIterator for RangeCheckerReplay {
    type Item = (RowIndex, [u16; 4]);
    type IntoIter = <VecDeque<(RowIndex, [u16; 4])> as IntoIterator>::IntoIter;

    /// Returns an iterator over all recorded range checks resulting from u32 operations.
    fn into_iter(self) -> Self::IntoIter {
        self.range_checks_u32_ops.into_iter()
    }
}

// HASHER RESPONSE REPLAY
// ================================================================================================

/// Records and replays the response of requests made to the hasher chiplet during the execution of
/// a program.
///
/// The hasher responses are recorded during fast processor execution and then replayed during core
/// trace generation.
#[derive(Debug, Default)]
pub struct HasherResponseReplay {
    /// Recorded hasher addresses from operations like hash_control_block, hash_basic_block, etc.
    block_addresses: VecDeque<Felt>,

    /// Recorded hasher operations from permutation operations (HPerm).
    ///
    /// Each entry contains (address, output_state)
    permutation_operations: VecDeque<(Felt, [Felt; 12])>,

    /// Recorded hasher operations from Merkle path verification operations.
    ///
    /// Each entry contains (address, computed_root)
    build_merkle_root_operations: VecDeque<(Felt, Word)>,

    /// Recorded hasher operations from Merkle root update operations.
    ///
    /// Each entry contains (address, old_root, new_root)
    mrupdate_operations: VecDeque<(Felt, Word, Word)>,
}

impl HasherResponseReplay {
    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------------------

    /// Records the address associated with a `Hasher::hash_control_block` or
    /// `Hasher::hash_basic_block` operation.
    pub fn record_block_address(&mut self, addr: Felt) {
        self.block_addresses.push_back(addr);
    }

    /// Records a `Hasher::permute` operation with its address and result (after applying the
    /// permutation)
    pub fn record_permute(&mut self, addr: Felt, hashed_state: [Felt; 12]) {
        self.permutation_operations.push_back((addr, hashed_state));
    }

    /// Records a Merkle path verification with its address and computed root
    pub fn record_build_merkle_root(&mut self, addr: Felt, computed_root: Word) {
        self.build_merkle_root_operations.push_back((addr, computed_root));
    }

    /// Records a Merkle root update with its address, old root, and new root
    pub fn record_update_merkle_root(&mut self, addr: Felt, old_root: Word, new_root: Word) {
        self.mrupdate_operations.push_back((addr, old_root, new_root));
    }

    // ACCESSORS (used by parallel trace generators)
    // --------------------------------------------------------------------------------------------

    /// Replays a `Hasher::hash_control_block` or `Hasher::hash_basic_block` operation, returning
    /// the pre-recorded address
    pub fn replay_block_address(&mut self) -> Felt {
        self.block_addresses.pop_front().expect("No block address operations recorded")
    }

    /// Replays a `Hasher::permute` operation, returning its address and result
    pub fn replay_permute(&mut self) -> (Felt, [Felt; 12]) {
        self.permutation_operations
            .pop_front()
            .expect("No permutation operations recorded")
    }

    /// Replays a Merkle path verification, returning the pre-recorded address and computed root
    pub fn replay_build_merkle_root(&mut self) -> (Felt, Word) {
        self.build_merkle_root_operations
            .pop_front()
            .expect("No build merkle root operations recorded")
    }

    /// Replays a Merkle root update, returning the pre-recorded address, old root, and new root
    pub fn replay_update_merkle_root(&mut self) -> (Felt, Word, Word) {
        self.mrupdate_operations.pop_front().expect("No mrupdate operations recorded")
    }
}

impl HasherInterface for HasherResponseReplay {
    fn permute(&mut self, _state: HasherState) -> (Felt, HasherState) {
        self.replay_permute()
    }

    fn verify_merkle_root(
        &mut self,
        claimed_root: Word,
        _value: Word,
        _path: Option<&MerklePath>,
        _index: Felt,
        on_err: impl FnOnce() -> ExecutionError,
    ) -> Result<Felt, ExecutionError> {
        let (addr, computed_root) = self.replay_build_merkle_root();
        if claimed_root == computed_root {
            Ok(addr)
        } else {
            // If the hasher doesn't compute the same root (using the same path),
            // then it means that `node` is not the value currently in the tree at `index`
            Err(on_err())
        }
    }

    fn update_merkle_root(
        &mut self,
        claimed_old_root: Word,
        _old_value: Word,
        _new_value: Word,
        _path: Option<&MerklePath>,
        _index: Felt,
        on_err: impl FnOnce() -> ExecutionError,
    ) -> Result<(Felt, Word), ExecutionError> {
        let (address, old_root, new_root) = self.replay_update_merkle_root();

        if claimed_old_root == old_root {
            Ok((address, new_root))
        } else {
            Err(on_err())
        }
    }
}

/// Enum representing the different hasher operations that can be recorded, along with their
/// operands.
#[derive(Debug)]
pub enum HasherOp {
    Permute([Felt; STATE_WIDTH]),
    HashControlBlock((Word, Word, Felt, Word)),
    HashBasicBlock((Vec<OpBatch>, Word)),
    BuildMerkleRoot((Word, MerklePath, Felt)),
    UpdateMerkleRoot((Word, Word, MerklePath, Felt)),
}

/// Records and replays all the requests made to the hasher chiplet during the execution of a
/// program, for the purposes of generating the hasher chiplet's trace.
///
/// The hasher requests are recorded during fast processor execution and then replayed during hasher
/// chiplet trace generation.
#[derive(Debug, Default)]
pub struct HasherRequestReplay {
    hasher_ops: VecDeque<HasherOp>,
}

impl HasherRequestReplay {
    /// Records a `Hasher::permute()` request.
    pub fn record_permute_input(&mut self, state: [Felt; STATE_WIDTH]) {
        self.hasher_ops.push_back(HasherOp::Permute(state));
    }

    /// Records a `Hasher::hash_control_block()` request.
    pub fn record_hash_control_block(
        &mut self,
        h1: Word,
        h2: Word,
        domain: Felt,
        expected_hash: Word,
    ) {
        self.hasher_ops
            .push_back(HasherOp::HashControlBlock((h1, h2, domain, expected_hash)));
    }

    /// Records a `Hasher::hash_basic_block()` request.
    pub fn record_hash_basic_block(&mut self, op_batches: Vec<OpBatch>, expected_hash: Word) {
        self.hasher_ops.push_back(HasherOp::HashBasicBlock((op_batches, expected_hash)));
    }

    /// Records a `Hasher::build_merkle_root()` request.
    pub fn record_build_merkle_root(&mut self, leaf: Word, path: MerklePath, index: Felt) {
        self.hasher_ops.push_back(HasherOp::BuildMerkleRoot((leaf, path, index)));
    }

    /// Records a `Hasher::update_merkle_root()` request.
    pub fn record_update_merkle_root(
        &mut self,
        old_value: Word,
        new_value: Word,
        path: MerklePath,
        index: Felt,
    ) {
        self.hasher_ops
            .push_back(HasherOp::UpdateMerkleRoot((old_value, new_value, path, index)));
    }
}

impl IntoIterator for HasherRequestReplay {
    type Item = HasherOp;
    type IntoIter = <VecDeque<HasherOp> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.hasher_ops.into_iter()
    }
}

// STACK OVERFLOW REPLAY
// ================================================================================================

/// Implements a shim for stack overflow operations, in which all overflow values and addresses
/// during a given fragment are pre-recorded by the fast processor and replayed by the main trace
/// fragment generators.
///
/// This is used to simulate stack overflow functionality in parallel trace generation without
/// needing to maintain the actual overflow table. All overflow operations are recorded during
/// fast execution and then replayed during parallel trace generation.
///
/// The shim records overflow values (from pop operations) and overflow addresses (representing
/// the clock cycle of the last overflow update) and provides replay methods that return the
/// pre-recorded values. This works naturally since the fast processor has exactly the same
/// access patterns as the main trace generators.
#[derive(Debug)]
pub struct StackOverflowReplay {
    /// Recorded overflow values and overflow addresses from pop_overflow operations. Each entry
    /// represents a value that was popped from the overflow stack, and the overflow address of the
    /// entry at the top of the overflow stack *after* the pop operation.
    ///
    /// For example, given the following table:
    ///
    /// | Overflow Value | Overflow Address |
    /// |----------------|------------------|
    /// |      8         |         14       |
    /// |      2         |         16       |
    /// |      7         |         18       |
    ///
    /// a `pop_overflow()` operation would return (popped_value, prev_addr) = (7, 16).
    overflow_values: VecDeque<(Felt, Felt)>,

    /// Recorded (stack depth, overflow address) returned when restoring a context
    restore_context_info: VecDeque<(usize, Felt)>,
}

impl Default for StackOverflowReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl StackOverflowReplay {
    /// Creates a new StackOverflowReplay with empty operation vectors
    pub fn new() -> Self {
        Self {
            overflow_values: VecDeque::new(),
            restore_context_info: VecDeque::new(),
        }
    }

    // MUTATORS
    // --------------------------------------------------------------------------------

    /// Records the value returned by a pop_overflow operation, along with the overflow address
    /// stored in the overflow table *after* the pop. That is, `new_overflow_addr` represents the
    /// clock cycle at which the value *before* `value` was added to the overflow table. See the
    /// docstring for the `overflow_values` field for more information.
    ///
    /// This *must* only be called if there is an actual value in the overflow table to pop; that
    /// is, don't call if the stack depth is 16.
    pub fn record_pop_overflow(&mut self, value: Felt, new_overflow_addr: Felt) {
        self.overflow_values.push_back((value, new_overflow_addr));
    }

    /// Records the overflow address when restoring a context
    pub fn record_restore_context_overflow_addr(&mut self, stack_depth: usize, addr: Felt) {
        self.restore_context_info.push_back((stack_depth, addr));
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------

    /// Replays a pop_overflow operation, returning the previously recorded value and
    /// `new_overflow_addr`.
    ///
    /// This *must* only be called if there is an actual value in the overflow table to pop; that
    /// is, don't call if the stack depth is 16.
    ///
    /// See [Self::record_pop_overflow] for more details.
    pub fn replay_pop_overflow(&mut self) -> (Felt, Felt) {
        self.overflow_values.pop_front().expect("No overflow pop operations recorded")
    }

    /// Replays the overflow address when restoring a context
    pub fn replay_restore_context_overflow_addr(&mut self) -> (usize, Felt) {
        self.restore_context_info
            .pop_front()
            .expect("No overflow address operations recorded")
    }
}

// NODE EXECUTION STATE
// ================================================================================================

/// Specifies the execution state of a node.
///
/// Each MAST node has at least 2 different states associated with it: processing the START and END
/// nodes (e.g. JOIN and END in the case of [miden_core::mast::JoinNode]). Some have more; for
/// example, [miden_core::mast::BasicBlockNode] has SPAN and END, in addition to one state for each
/// operation in the basic block. Since a trace fragment can begin at any clock cycle (determined by
/// the configured fragment size), specifying which MAST node we're executing is
/// insufficient; we also have to specify *at what point* during the execution of this node we are
/// at. This is the information that this type is meant to encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeExecutionState {
    /// Resume execution within a basic block at a specific batch and operation index.
    /// This is used when continuing execution mid-way through a basic block.
    BasicBlock {
        /// Node ID of the basic block being executed
        node_id: MastNodeId,
        /// Index of the operation batch within the basic block
        batch_index: usize,
        /// Index of the operation within the batch
        op_idx_in_batch: usize,
    },
    /// Execute a control flow node (JOIN, SPLIT, LOOP, etc.) from the start. This is used when
    /// beginning execution of a control flow construct.
    Start(MastNodeId),
    /// Execute a RESPAN for the specified batch within the specified basic block.
    Respan {
        /// Node ID of the basic block being executed
        node_id: MastNodeId,
        /// Index of the operation batch within the basic block
        batch_index: usize,
    },
    /// Execute a Loop node, starting at a REPEAT operation.
    LoopRepeat(MastNodeId),
    /// Execute the END phase of a control flow node (JOIN, SPLIT, LOOP, etc.).
    /// This is used when completing execution of a control flow construct.
    End(MastNodeId),
}
