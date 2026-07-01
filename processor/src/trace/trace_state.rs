use alloc::{collections::VecDeque, string::ToString};

use miden_air::trace::{
    RowIndex,
    chiplets::hasher::{HasherState, STATE_WIDTH},
};
use miden_core::{
    serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        read_bounded_len,
    },
    utils::{SerializableVecDeque, read_vec_deque},
};

use crate::{
    ContextId, ExecutionError, Felt, MIN_STACK_DEPTH, MemoryError, ONE, Word, ZERO,
    advice::AdviceError,
    continuation_stack::ContinuationStack,
    crypto::merkle::MerklePath,
    errors::OperationError,
    mast::{MastForestId, MastNodeId},
    precompile::PrecompileTranscriptState,
    processor::{
        AdviceProviderInterface, HasherInterface, MemoryInterface, Processor, SystemInterface,
    },
    trace::chiplets::CircuitEvaluation,
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
/// This struct is conceptually divided into 4 components:
/// 1. core trace state: the state of the processor at any clock cycle in the fragment, initialized
///    to the state at the first clock cycle in the fragment,
/// 2. execution replay: information needed to replay the execution of the processor for the
///    remainder of the fragment,
/// 3. continuation: a stack of continuations for the processor representing the nodes in the MAST
///    forest to execute when the current node is done executing,
/// 4. initial MAST forest: the MAST forest being executed at the start of the fragment (which can
///    change during execution when encountering an [`miden_core::mast::ExternalNode`] or
///    [`miden_core::mast::DynNode`]).
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, PartialEq, Eq)]
pub struct CoreTraceFragmentContext {
    pub state: CoreTraceState,
    pub replay: ExecutionReplay,
    /// Continuation stack with forest references encoded as [`MastForestId`]s into the
    /// `mast_forest_store` of the owning [`crate::TraceGenerationContext`].
    pub continuation: ContinuationStack<MastForestId>,
    /// MAST forest active at the start of this fragment.
    pub initial_mast_forest_id: MastForestId,
}

// CORE TRACE STATE
// ================================================================================================

/// Subset of the processor state used to build the core trace (system, decoder and stack sets of
/// columns).
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, PartialEq, Eq)]
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
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

    /// Precompile-transcript state (rolling digest) used for recording `log_precompile` calls
    /// - Initially [ZERO; 4]
    /// - Updated with each `log_precompile` invocation
    pub pc_transcript_state: PrecompileTranscriptState,
}

impl SystemState {
    /// Convenience constructor that creates a new `SystemState` from a `Processor`.
    pub(crate) fn from_processor<P: Processor>(processor: &P) -> Self {
        Self {
            clk: processor.system().clock(),
            ctx: processor.system().ctx(),
            fn_hash: processor.system().caller_hash(),
            pc_transcript_state: processor.system().precompile_transcript_state(),
        }
    }
}

// DECODER STATE
// ================================================================================================

/// The subset of the decoder state required to build the trace.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, PartialEq, Eq)]
pub struct DecoderState {
    /// The value of the decoder's `addr` column.
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
    pub fn replay_node_start(
        &mut self,
        block_address_replay: &mut BlockAddressReplay,
        block_stack_replay: &mut BlockStackReplay,
    ) -> Result<(), ExecutionError> {
        self.current_addr = block_address_replay.replay_block_address()?;
        self.parent_addr = block_stack_replay.replay_node_start_parent_addr()?;
        Ok(())
    }

    /// This function is called when we hit an `END` operation, signaling the end of execution for a
    /// node. It updates the decoder state to point to the previous node in the block stack (which
    /// could be renamed to "node stack"), and returns the address of the node that just ended.
    pub fn replay_node_end(
        &mut self,
        block_stack_replay: &mut BlockStackReplay,
    ) -> Result<Felt, ExecutionError> {
        let node_end_data = block_stack_replay.replay_node_end()?;

        self.current_addr = node_end_data.prev_addr;
        self.parent_addr = node_end_data.prev_parent_addr;

        Ok(node_end_data.ended_node_addr)
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, PartialEq, Eq)]
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
    pub fn overflow_addr(&self) -> Felt {
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
    ) -> Result<Option<Felt>, OperationError> {
        debug_assert!(self.stack_depth >= MIN_STACK_DEPTH);

        if self.stack_depth > MIN_STACK_DEPTH {
            let (stack_value, new_overflow_addr) = stack_overflow_replay.replay_pop_overflow()?;
            self.stack_depth -= 1;
            self.last_overflow_addr = new_overflow_addr;
            Ok(Some(stack_value))
        } else {
            self.last_overflow_addr = ZERO;
            Ok(None)
        }
    }

    /// Derives the denominator of the overflow helper (h0 helper column) from the current stack
    /// depth.
    ///
    /// It is expected that this values gets later inverted via batch inversion.
    pub fn overflow_helper(&self) -> Felt {
        let denominator = self.stack_depth() - MIN_STACK_DEPTH;
        Felt::new_unchecked(denominator as u64)
    }

    /// Starts a new execution context for this stack, resetting the stack depth to its minimum
    /// value, and last overflow address to 0.
    ///
    /// This has the effect of hiding the contents of the overflow table such that it appears as if
    /// the overflow table in the new context is empty.
    pub fn start_context(&mut self) {
        self.stack_depth = MIN_STACK_DEPTH;
        self.last_overflow_addr = ZERO;
    }

    /// Restores the prior context for this stack.
    ///
    /// This has the effect bringing back items previously hidden from the overflow table.
    pub fn restore_context(
        &mut self,
        stack_overflow_replay: &mut StackOverflowReplay,
    ) -> Result<(), OperationError> {
        let (stack_depth, last_overflow_addr) =
            stack_overflow_replay.replay_restore_context_overflow_addr()?;
        // Restore stack depth to the value from before the context switch (parallel to Process
        // Stack behavior)
        self.stack_depth = stack_depth;
        self.last_overflow_addr = last_overflow_addr;
        Ok(())
    }
}

/// Replay data necessary to build a trace fragment.
///
/// During execution, the processor records information to be replayed by the corresponding trace
/// generator. This is done due to the fact that the trace generators don't have access to some
/// components needed to produce those values, such as the memory chiplet, advice provider, etc. It
/// also packages up all the necessary data for trace generators to generate trace fragments, which
/// can be done on separate machines in parallel, for example.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExecutionReplay {
    pub block_stack: BlockStackReplay,
    pub execution_context: ExecutionContextReplay,
    pub stack_overflow: StackOverflowReplay,
    pub memory_reads: MemoryReadsReplay,
    pub advice: AdviceReplay,
    pub hasher: HasherResponseReplay,
    pub block_address: BlockAddressReplay,
    pub mast_forest_resolution: MastForestResolutionReplay,
}

// EXECUTION CONTEXT REPLAY
// ================================================================================================

#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExecutionContextReplay {
    /// Extra data needed to recover the state on an END operation specifically for
    /// CALL/SYSCALL/DYNCALL nodes (which start/end a new execution context).
    execution_contexts: VecDeque<ExecutionContextSystemInfo>,
}

impl ExecutionContextReplay {
    /// Records an execution context system info for a CALL/SYSCALL/DYNCALL operation.
    pub fn record_execution_context(&mut self, ctx_info: ExecutionContextSystemInfo) {
        self.execution_contexts.push_back(ctx_info);
    }

    /// Replays the next recorded execution context system info.
    pub fn replay_execution_context(
        &mut self,
    ) -> Result<ExecutionContextSystemInfo, OperationError> {
        self.execution_contexts
            .pop_front()
            .ok_or(OperationError::Internal("no execution context recorded"))
    }
}

// BLOCK STACK REPLAY
// ================================================================================================

/// Replay data for the block stack.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BlockStackReplay {
    /// The parent address, recorded when a new node is started (JOIN, SPLIT, etc).
    node_start_parent_addr: VecDeque<Felt>,
    /// The data needed to recover the state on an END operation.
    node_end: VecDeque<NodeEndData>,
}

impl BlockStackReplay {
    /// Creates a new instance of `BlockStackReplay`.
    pub fn new() -> Self {
        Self {
            node_start_parent_addr: VecDeque::new(),
            node_end: VecDeque::new(),
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
        prev_addr: Felt,
        prev_parent_addr: Felt,
    ) {
        self.node_end.push_back(NodeEndData {
            ended_node_addr,
            prev_addr,
            prev_parent_addr,
        });
    }

    /// Replays the node's parent address
    pub fn replay_node_start_parent_addr(&mut self) -> Result<Felt, ExecutionError> {
        self.node_start_parent_addr
            .pop_front()
            .ok_or(ExecutionError::Internal("no node start parent address recorded"))
    }

    /// Replays the data needed to recover the state on an END operation.
    pub fn replay_node_end(&mut self) -> Result<NodeEndData, ExecutionError> {
        self.node_end
            .pop_front()
            .ok_or(ExecutionError::Internal("no node address and flags recorded"))
    }
}

/// The flags written in the second word of the hasher state for END operations.
#[derive(Debug)]
pub struct NodeFlags {
    is_loop_body: bool,
    is_loop: bool,
    is_call: bool,
    is_syscall: bool,
}

impl NodeFlags {
    /// Creates a new instance of `NodeFlags`.
    pub fn new(is_loop_body: bool, is_loop: bool, is_call: bool, is_syscall: bool) -> Self {
        Self {
            is_loop_body,
            is_loop,
            is_call,
            is_syscall,
        }
    }

    /// Returns ONE if this node is a body of a LOOP node; otherwise returns ZERO.
    pub fn is_loop_body(&self) -> Felt {
        if self.is_loop_body { ONE } else { ZERO }
    }

    /// Returns ONE if this END is closing a LOOP node; otherwise returns ZERO.
    pub fn is_loop(&self) -> Felt {
        if self.is_loop { ONE } else { ZERO }
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
        [self.is_loop_body(), self.is_loop(), self.is_call(), self.is_syscall()].into()
    }
}

/// The data needed to fully recover the state on an END operation.
///
/// We record `ended_node_addr` in order to be able to properly populate the trace row for the
/// node operation. Additionally, we record `prev_addr` and `prev_parent_addr` to allow emulating
/// peeking into the block stack, which is needed when processing REPEAT or RESPAN nodes.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, PartialEq, Eq)]
pub struct NodeEndData {
    /// the address of the node that is ending
    pub ended_node_addr: Felt,
    /// the address of the node sitting on top of the block stack after the END operation (or 0 if
    /// the block stack is empty)
    pub prev_addr: Felt,
    /// the parent address of the node sitting on top of the block stack after the END operation
    /// (or 0 if the block stack is empty)
    pub prev_parent_addr: Felt,
}

/// Data required to recover the state of an execution context when restoring it during an END
/// operation.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, PartialEq, Eq)]
pub struct ExecutionContextSystemInfo {
    pub parent_ctx: ContextId,
    pub parent_fn_hash: Word,
}

// MAST FOREST RESOLUTION REPLAY
// ================================================================================================

/// Records and replays the resolutions of [`crate::host::Host::get_mast_forest`].
///
/// These calls are made when encountering an [`miden_core::mast::ExternalNode`], or when
/// encountering a [`miden_core::mast::DynNode`] where the procedure hash on the stack refers to
/// a procedure not present in the current forest.
///
/// The forest reference is stored as a [`MastForestId`] into the `mast_forest_store` of the
/// [`crate::TraceGenerationContext`] that owns this replay. This avoids holding a strong
/// `Arc<MastForest>` reference per resolution, allowing the trace generation context to deduplicate
/// forests across fragments.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MastForestResolutionReplay {
    mast_forest_resolutions: VecDeque<(MastNodeId, MastForestId)>,
}

impl MastForestResolutionReplay {
    /// Records a resolution of a MastNodeId with the id of its associated MAST forest in the
    /// trace generation context's `mast_forest_store`.
    pub fn record_resolution(&mut self, node_id: MastNodeId, forest_id: MastForestId) {
        self.mast_forest_resolutions.push_back((node_id, forest_id));
    }

    /// Replays the next recorded MastForest resolution, returning both the node ID and the forest
    /// id.
    pub fn replay_resolution(&mut self) -> Result<(MastNodeId, MastForestId), ExecutionError> {
        self.mast_forest_resolutions
            .pop_front()
            .ok_or(ExecutionError::Internal("no MastForest resolutions recorded"))
    }

    pub(crate) fn iter_forest_ids(&self) -> impl Iterator<Item = MastForestId> + '_ {
        self.mast_forest_resolutions.iter().map(|(_node_id, forest_id)| *forest_id)
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
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

    pub fn replay_read_element(&mut self, addr: Felt) -> Result<Felt, MemoryError> {
        let (element, stored_addr, _ctx, _clk) = self
            .elements_read
            .pop_front()
            .ok_or(MemoryError::MemoryReadFailed("memory elements replay is empty".to_string()))?;
        debug_assert_eq!(stored_addr, addr, "Address mismatch: expected {addr}, got {stored_addr}");
        Ok(element)
    }

    pub fn replay_read_word(&mut self, addr: Felt) -> Result<Word, MemoryError> {
        let (word, stored_addr, _ctx, _clk) = self
            .words_read
            .pop_front()
            .ok_or(MemoryError::MemoryReadFailed("memory words replay is empty".to_string()))?;
        debug_assert_eq!(stored_addr, addr, "Address mismatch: expected {addr}, got {stored_addr}");
        Ok(word)
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
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
    fn read_element(&mut self, _ctx: ContextId, addr: Felt) -> Result<Felt, MemoryError> {
        self.replay_read_element(addr)
    }

    fn read_word(
        &mut self,
        _ctx: ContextId,
        addr: Felt,
        _clk: RowIndex,
    ) -> Result<Word, MemoryError> {
        self.replay_read_word(addr)
    }

    fn write_element(
        &mut self,
        _ctx: ContextId,
        _addr: Felt,
        _element: Felt,
    ) -> Result<(), MemoryError> {
        Ok(())
    }

    fn write_word(
        &mut self,
        _ctx: ContextId,
        _addr: Felt,
        _clk: RowIndex,
        _word: Word,
    ) -> Result<(), MemoryError> {
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
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
    pub fn replay_pop_stack(&mut self) -> Result<Felt, ExecutionError> {
        self.stack_pops
            .pop_front()
            .ok_or(ExecutionError::Internal("no stack pop operations recorded"))
    }

    /// Replays a pop_stack_word operation, returning the previously recorded word
    pub fn replay_pop_stack_word(&mut self) -> Result<Word, ExecutionError> {
        self.stack_word_pops
            .pop_front()
            .ok_or(ExecutionError::Internal("no stack word pop operations recorded"))
    }

    /// Replays a pop_stack_dword operation, returning the previously recorded double word
    pub fn replay_pop_stack_dword(&mut self) -> Result<[Word; 2], ExecutionError> {
        self.stack_dword_pops
            .pop_front()
            .ok_or(ExecutionError::Internal("no stack dword pop operations recorded"))
    }
}

impl AdviceProviderInterface for AdviceReplay {
    fn pop_stack(&mut self) -> Result<Felt, AdviceError> {
        self.replay_pop_stack().map_err(|_| AdviceError::StackReadFailed)
    }

    fn pop_stack_word(&mut self) -> Result<Word, AdviceError> {
        self.replay_pop_stack_word().map_err(|_| AdviceError::StackReadFailed)
    }

    fn pop_stack_dword(&mut self) -> Result<[Word; 2], AdviceError> {
        self.replay_pop_stack_dword().map_err(|_| AdviceError::StackReadFailed)
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitwiseOp {
    U32And,
    U32Xor,
}

/// Replay data for bitwise operations.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AceReplay {
    circuit_evaluations: VecDeque<(RowIndex, CircuitEvaluation)>,
}

impl AceReplay {
    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records the evaluation of a circuit.
    pub fn record_circuit_evaluation(&mut self, circuit_eval: CircuitEvaluation) {
        let clk = RowIndex::from(circuit_eval.clk());
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RangeCheckerReplay {
    range_checks_u32_ops: VecDeque<[u16; 4]>,
}

impl RangeCheckerReplay {
    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records the set of range checks which result from a u32 operation.
    pub fn record_range_check_u32(&mut self, u16_limbs: [u16; 4]) {
        self.range_checks_u32_ops.push_back(u16_limbs);
    }
}

impl IntoIterator for RangeCheckerReplay {
    type Item = [u16; 4];
    type IntoIter = <VecDeque<[u16; 4]> as IntoIterator>::IntoIter;

    /// Returns an iterator over all recorded range checks resulting from u32 operations.
    fn into_iter(self) -> Self::IntoIter {
        self.range_checks_u32_ops.into_iter()
    }
}

// BLOCK ADDRESS REPLAY
// ================================================================================================

#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BlockAddressReplay {
    /// Recorded hasher addresses from operations like hash_control_block, hash_basic_block, etc.
    block_addresses: VecDeque<Felt>,
}

impl BlockAddressReplay {
    /// Records the address associated with a `Hasher::hash_control_block` or
    /// `Hasher::hash_basic_block` operation.
    pub fn record_block_address(&mut self, addr: Felt) {
        self.block_addresses.push_back(addr);
    }

    /// Replays a `Hasher::hash_control_block` or `Hasher::hash_basic_block` operation, returning
    /// the pre-recorded address
    pub fn replay_block_address(&mut self) -> Result<Felt, ExecutionError> {
        self.block_addresses
            .pop_front()
            .ok_or(ExecutionError::Internal("no block address operations recorded"))
    }
}

// HASHER RESPONSE REPLAY
// ================================================================================================

/// Records and replays the response of requests made to the hasher chiplet during the execution of
/// a program.
///
/// The hasher responses are recorded during fast processor execution and then replayed during core
/// trace generation.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HasherResponseReplay {
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

    /// Replays a `Hasher::permute` operation, returning its address and result
    pub fn replay_permute(&mut self) -> Result<(Felt, [Felt; 12]), OperationError> {
        self.permutation_operations
            .pop_front()
            .ok_or(OperationError::Internal("no permutation operations recorded"))
    }

    /// Replays a Merkle path verification, returning the pre-recorded address and computed root
    pub fn replay_build_merkle_root(&mut self) -> Result<(Felt, Word), OperationError> {
        self.build_merkle_root_operations
            .pop_front()
            .ok_or(OperationError::Internal("no build merkle root operations recorded"))
    }

    /// Replays a Merkle root update, returning the pre-recorded address, old root, and new root
    pub fn replay_update_merkle_root(&mut self) -> Result<(Felt, Word, Word), OperationError> {
        self.mrupdate_operations
            .pop_front()
            .ok_or(OperationError::Internal("no mrupdate operations recorded"))
    }
}

impl HasherInterface for HasherResponseReplay {
    fn permute(&mut self, _state: HasherState) -> Result<(Felt, HasherState), OperationError> {
        self.replay_permute()
    }

    fn verify_merkle_root(
        &mut self,
        claimed_root: Word,
        _value: Word,
        _path: Option<&MerklePath>,
        _index: Felt,
        on_err: impl FnOnce() -> OperationError,
    ) -> Result<Felt, OperationError> {
        let (addr, computed_root) = self.replay_build_merkle_root()?;
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
        on_err: impl FnOnce() -> OperationError,
    ) -> Result<(Felt, Word), OperationError> {
        let (address, old_root, new_root) = self.replay_update_merkle_root()?;

        if claimed_old_root == old_root {
            Ok((address, new_root))
        } else {
            Err(on_err())
        }
    }
}

/// Enum representing the different hasher operations that can be recorded, along with their
/// operands.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, PartialEq, Eq)]
pub enum HasherOp {
    Permute([Felt; STATE_WIDTH]),
    HashControlBlock((Word, Word, Felt, Word)),
    /// `(forest_id, node_id, expected_hash)` — `forest_id` is an id into the
    /// `mast_forest_store` of the [`crate::TraceGenerationContext`] that owns this replay.
    HashBasicBlock((MastForestId, MastNodeId, Word)),
    BuildMerkleRoot((Word, MerklePath, Felt)),
    UpdateMerkleRoot((Word, Word, MerklePath, Felt)),
}

/// Records and replays all the requests made to the hasher chiplet during the execution of a
/// program, for the purposes of generating the hasher chiplet's trace.
///
/// The hasher requests are recorded during fast processor execution and then replayed during hasher
/// chiplet trace generation.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq, Eq)]
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
    pub fn record_hash_basic_block(
        &mut self,
        forest_id: MastForestId,
        node_id: MastNodeId,
        expected_hash: Word,
    ) {
        self.hasher_ops
            .push_back(HasherOp::HashBasicBlock((forest_id, node_id, expected_hash)));
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

    pub(crate) fn iter_hash_basic_block_forest_ids(
        &self,
    ) -> impl Iterator<Item = MastForestId> + '_ {
        self.hasher_ops.iter().filter_map(|op| match op {
            HasherOp::HashBasicBlock((forest_id, _node_id, _expected_hash)) => Some(*forest_id),
            _ => None,
        })
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, PartialEq, Eq)]
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

    /// Peeks at the next recorded pop_overflow operation, returning the previously recorded value
    /// and `new_overflow_addr` without removing it from the queue.
    pub fn peek_replay_pop_overflow(&self) -> Option<&(Felt, Felt)> {
        self.overflow_values.front()
    }

    /// Replays a pop_overflow operation, returning the previously recorded value and
    /// `new_overflow_addr`.
    ///
    /// This *must* only be called if there is an actual value in the overflow table to pop; that
    /// is, don't call if the stack depth is 16.
    ///
    /// See [Self::record_pop_overflow] for more details.
    pub fn replay_pop_overflow(&mut self) -> Result<(Felt, Felt), OperationError> {
        self.overflow_values
            .pop_front()
            .ok_or(OperationError::Internal("no overflow pop operations recorded"))
    }

    /// Replays the overflow address when restoring a context
    pub fn replay_restore_context_overflow_addr(
        &mut self,
    ) -> Result<(usize, Felt), OperationError> {
        self.restore_context_info
            .pop_front()
            .ok_or(OperationError::Internal("no overflow address operations recorded"))
    }
}

// SERIALIZATION
// ================================================================================================

fn write_row_index<W: ByteWriter>(row: RowIndex, target: &mut W) {
    u32::from(row).write_into(target);
}

fn read_row_index<R: ByteReader>(source: &mut R) -> Result<RowIndex, DeserializationError> {
    Ok(RowIndex::from(u32::read_from(source)?))
}

fn write_memory_element_queue<W: ByteWriter>(
    queue: &VecDeque<(Felt, Felt, ContextId, RowIndex)>,
    target: &mut W,
) {
    target.write_usize(queue.len());
    for &(element, addr, ctx, clk) in queue {
        element.write_into(target);
        addr.write_into(target);
        ctx.write_into(target);
        write_row_index(clk, target);
    }
}

fn read_memory_element_queue<R: ByteReader>(
    source: &mut R,
) -> Result<VecDeque<(Felt, Felt, ContextId, RowIndex)>, DeserializationError> {
    let len = source.read_usize()?;
    let element_size =
        Felt::min_serialized_size() * 2 + u32::min_serialized_size() + u32::min_serialized_size();
    let max_len = source.max_alloc(element_size);
    if len > max_len {
        return Err(DeserializationError::InvalidValue(format!(
            "memory element replay length {len} exceeds reader allocation bound {max_len}"
        )));
    }

    let mut values = VecDeque::with_capacity(len);
    for _ in 0..len {
        values.push_back((
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            ContextId::read_from(source)?,
            read_row_index(source)?,
        ));
    }
    Ok(values)
}

fn write_memory_word_queue<W: ByteWriter>(
    queue: &VecDeque<(Word, Felt, ContextId, RowIndex)>,
    target: &mut W,
) {
    target.write_usize(queue.len());
    for &(word, addr, ctx, clk) in queue {
        word.write_into(target);
        addr.write_into(target);
        ctx.write_into(target);
        write_row_index(clk, target);
    }
}

fn read_memory_word_queue<R: ByteReader>(
    source: &mut R,
) -> Result<VecDeque<(Word, Felt, ContextId, RowIndex)>, DeserializationError> {
    let len = source.read_usize()?;
    let element_size =
        Word::min_serialized_size() + Felt::min_serialized_size() + u32::min_serialized_size() * 2;
    let max_len = source.max_alloc(element_size);
    if len > max_len {
        return Err(DeserializationError::InvalidValue(format!(
            "memory word replay length {len} exceeds reader allocation bound {max_len}"
        )));
    }

    let mut values = VecDeque::with_capacity(len);
    for _ in 0..len {
        values.push_back((
            Word::read_from(source)?,
            Felt::read_from(source)?,
            ContextId::read_from(source)?,
            read_row_index(source)?,
        ));
    }
    Ok(values)
}

impl Serializable for SystemState {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_row_index(self.clk, target);
        self.ctx.write_into(target);
        self.fn_hash.write_into(target);
        self.pc_transcript_state.write_into(target);
    }
}

impl Deserializable for SystemState {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            clk: read_row_index(source)?,
            ctx: ContextId::read_from(source)?,
            fn_hash: Word::read_from(source)?,
            pc_transcript_state: Word::read_from(source)?,
        })
    }
}

impl Serializable for DecoderState {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.current_addr.write_into(target);
        self.parent_addr.write_into(target);
    }
}

impl Deserializable for DecoderState {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            current_addr: Felt::read_from(source)?,
            parent_addr: Felt::read_from(source)?,
        })
    }
}

impl Serializable for StackState {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.stack_top.write_into(target);
        self.stack_depth.write_into(target);
        self.last_overflow_addr.write_into(target);
    }
}

impl Deserializable for StackState {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let stack_top = <[Felt; MIN_STACK_DEPTH]>::read_from(source)?;
        let stack_depth = usize::read_from(source)?;
        if stack_depth < MIN_STACK_DEPTH {
            return Err(DeserializationError::InvalidValue(format!(
                "stack depth {stack_depth} is below minimum {MIN_STACK_DEPTH}"
            )));
        }
        Ok(Self {
            stack_top,
            stack_depth,
            last_overflow_addr: Felt::read_from(source)?,
        })
    }
}

impl Serializable for CoreTraceState {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.system.write_into(target);
        self.decoder.write_into(target);
        self.stack.write_into(target);
    }
}

impl Deserializable for CoreTraceState {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            system: SystemState::read_from(source)?,
            decoder: DecoderState::read_from(source)?,
            stack: StackState::read_from(source)?,
        })
    }
}

impl Serializable for CoreTraceFragmentContext {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.state.write_into(target);
        self.replay.write_into(target);
        self.continuation.write_into(target);
        self.initial_mast_forest_id.write_into(target);
    }
}

impl Deserializable for CoreTraceFragmentContext {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            state: CoreTraceState::read_from(source)?,
            replay: ExecutionReplay::read_from(source)?,
            continuation: ContinuationStack::<MastForestId>::read_from(source)?,
            initial_mast_forest_id: MastForestId::read_from(source)?,
        })
    }
}

impl Serializable for NodeEndData {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.ended_node_addr.write_into(target);
        self.prev_addr.write_into(target);
        self.prev_parent_addr.write_into(target);
    }
}

impl Deserializable for NodeEndData {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            ended_node_addr: Felt::read_from(source)?,
            prev_addr: Felt::read_from(source)?,
            prev_parent_addr: Felt::read_from(source)?,
        })
    }
}

impl Serializable for ExecutionContextSystemInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.parent_ctx.write_into(target);
        self.parent_fn_hash.write_into(target);
    }
}

impl Deserializable for ExecutionContextSystemInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            parent_ctx: ContextId::read_from(source)?,
            parent_fn_hash: Word::read_from(source)?,
        })
    }

    fn min_serialized_size() -> usize {
        ContextId::min_serialized_size() + Word::min_serialized_size()
    }
}

impl Serializable for ExecutionContextReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        SerializableVecDeque(&self.execution_contexts).write_into(target);
    }
}

impl Deserializable for ExecutionContextReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            execution_contexts: read_vec_deque(source)?,
        })
    }
}

impl Serializable for BlockStackReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        SerializableVecDeque(&self.node_start_parent_addr).write_into(target);
        SerializableVecDeque(&self.node_end).write_into(target);
    }
}

impl Deserializable for BlockStackReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            node_start_parent_addr: read_vec_deque(source)?,
            node_end: read_vec_deque(source)?,
        })
    }
}

impl Serializable for MastForestResolutionReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        SerializableVecDeque(&self.mast_forest_resolutions).write_into(target);
    }
}

impl Deserializable for MastForestResolutionReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            mast_forest_resolutions: read_mast_forest_resolution_queue(source)?,
        })
    }
}

fn read_mast_forest_resolution_queue<R: ByteReader>(
    source: &mut R,
) -> Result<VecDeque<(MastNodeId, MastForestId)>, DeserializationError> {
    let len = read_bounded_len(
        source,
        "MastForestResolutionReplay",
        u32::min_serialized_size() + MastForestId::min_serialized_size(),
    )?;
    let mut values = VecDeque::with_capacity(len);
    for _ in 0..len {
        values.push_back((
            MastNodeId::from(u32::read_from(source)?),
            MastForestId::read_from(source)?,
        ));
    }
    Ok(values)
}

impl Serializable for MemoryReadsReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_memory_element_queue(&self.elements_read, target);
        write_memory_word_queue(&self.words_read, target);
    }
}

impl Deserializable for MemoryReadsReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            elements_read: read_memory_element_queue(source)?,
            words_read: read_memory_word_queue(source)?,
        })
    }
}

impl Serializable for MemoryWritesReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_memory_element_queue(&self.elements_written, target);
        write_memory_word_queue(&self.words_written, target);
    }
}

impl Deserializable for MemoryWritesReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            elements_written: read_memory_element_queue(source)?,
            words_written: read_memory_word_queue(source)?,
        })
    }
}

impl Serializable for AdviceReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        SerializableVecDeque(&self.stack_pops).write_into(target);
        SerializableVecDeque(&self.stack_word_pops).write_into(target);
        SerializableVecDeque(&self.stack_dword_pops).write_into(target);
    }
}

impl Deserializable for AdviceReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            stack_pops: read_vec_deque(source)?,
            stack_word_pops: read_vec_deque(source)?,
            stack_dword_pops: read_vec_deque(source)?,
        })
    }
}

impl Serializable for BitwiseOp {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::U32And => 0u8,
            Self::U32Xor => 1u8,
        }
        .write_into(target);
    }
}

impl Deserializable for BitwiseOp {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match u8::read_from(source)? {
            0 => Ok(Self::U32And),
            1 => Ok(Self::U32Xor),
            tag => Err(DeserializationError::InvalidValue(format!(
                "invalid bitwise replay op tag {tag}"
            ))),
        }
    }
}

impl Serializable for BitwiseReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        SerializableVecDeque(&self.u32op_with_operands).write_into(target);
    }
}

impl Deserializable for BitwiseReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            u32op_with_operands: read_vec_deque(source)?,
        })
    }
}

impl Serializable for KernelReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        SerializableVecDeque(&self.kernel_proc_accesses).write_into(target);
    }
}

impl Deserializable for KernelReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            kernel_proc_accesses: read_vec_deque(source)?,
        })
    }
}

fn write_ace_queue<W: ByteWriter>(queue: &VecDeque<(RowIndex, CircuitEvaluation)>, target: &mut W) {
    target.write_usize(queue.len());
    for &(row, ref evaluation) in queue {
        write_row_index(row, target);
        evaluation.write_into(target);
    }
}

fn read_ace_queue<R: ByteReader>(
    source: &mut R,
) -> Result<VecDeque<(RowIndex, CircuitEvaluation)>, DeserializationError> {
    let len = source.read_usize()?;
    let max_len =
        source.max_alloc(u32::min_serialized_size() + CircuitEvaluation::min_serialized_size());
    if len > max_len {
        return Err(DeserializationError::InvalidValue(format!(
            "ACE replay length {len} exceeds reader allocation bound {max_len}"
        )));
    }

    let mut values = VecDeque::with_capacity(len);
    for _ in 0..len {
        values.push_back((read_row_index(source)?, CircuitEvaluation::read_from(source)?));
    }
    Ok(values)
}

impl Serializable for AceReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_ace_queue(&self.circuit_evaluations, target);
    }
}

impl Deserializable for AceReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            circuit_evaluations: read_ace_queue(source)?,
        })
    }
}

impl Serializable for RangeCheckerReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        SerializableVecDeque(&self.range_checks_u32_ops).write_into(target);
    }
}

impl Deserializable for RangeCheckerReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            range_checks_u32_ops: read_vec_deque(source)?,
        })
    }
}

impl Serializable for BlockAddressReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        SerializableVecDeque(&self.block_addresses).write_into(target);
    }
}

impl Deserializable for BlockAddressReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self { block_addresses: read_vec_deque(source)? })
    }
}

impl Serializable for HasherResponseReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        SerializableVecDeque(&self.permutation_operations).write_into(target);
        SerializableVecDeque(&self.build_merkle_root_operations).write_into(target);
        SerializableVecDeque(&self.mrupdate_operations).write_into(target);
    }
}

impl Deserializable for HasherResponseReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            permutation_operations: read_vec_deque(source)?,
            build_merkle_root_operations: read_vec_deque(source)?,
            mrupdate_operations: read_vec_deque(source)?,
        })
    }
}

impl Serializable for HasherOp {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Permute(state) => {
                0u8.write_into(target);
                state.write_into(target);
            },
            Self::HashControlBlock((h1, h2, domain, expected_hash)) => {
                1u8.write_into(target);
                h1.write_into(target);
                h2.write_into(target);
                domain.write_into(target);
                expected_hash.write_into(target);
            },
            Self::HashBasicBlock((forest_id, node_id, expected_hash)) => {
                2u8.write_into(target);
                forest_id.write_into(target);
                node_id.write_into(target);
                expected_hash.write_into(target);
            },
            Self::BuildMerkleRoot((leaf, path, index)) => {
                3u8.write_into(target);
                leaf.write_into(target);
                path.write_into(target);
                index.write_into(target);
            },
            Self::UpdateMerkleRoot((old_value, new_value, path, index)) => {
                4u8.write_into(target);
                old_value.write_into(target);
                new_value.write_into(target);
                path.write_into(target);
                index.write_into(target);
            },
        }
    }
}

impl Deserializable for HasherOp {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match u8::read_from(source)? {
            0 => Ok(Self::Permute(<[Felt; STATE_WIDTH]>::read_from(source)?)),
            1 => Ok(Self::HashControlBlock((
                Word::read_from(source)?,
                Word::read_from(source)?,
                Felt::read_from(source)?,
                Word::read_from(source)?,
            ))),
            2 => Ok(Self::HashBasicBlock((
                MastForestId::read_from(source)?,
                MastNodeId::from(u32::read_from(source)?),
                Word::read_from(source)?,
            ))),
            3 => Ok(Self::BuildMerkleRoot((
                Word::read_from(source)?,
                MerklePath::read_from(source)?,
                Felt::read_from(source)?,
            ))),
            4 => Ok(Self::UpdateMerkleRoot((
                Word::read_from(source)?,
                Word::read_from(source)?,
                MerklePath::read_from(source)?,
                Felt::read_from(source)?,
            ))),
            tag => Err(DeserializationError::InvalidValue(format!(
                "invalid hasher replay op tag {tag}"
            ))),
        }
    }

    fn min_serialized_size() -> usize {
        u8::min_serialized_size()
            + (MastForestId::min_serialized_size()
                + u32::min_serialized_size()
                + Word::min_serialized_size())
    }
}

impl Serializable for HasherRequestReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        SerializableVecDeque(&self.hasher_ops).write_into(target);
    }
}

impl Deserializable for HasherRequestReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self { hasher_ops: read_vec_deque(source)? })
    }
}

impl Serializable for StackOverflowReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        SerializableVecDeque(&self.overflow_values).write_into(target);
        SerializableVecDeque(&self.restore_context_info).write_into(target);
    }
}

impl Deserializable for StackOverflowReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            overflow_values: read_vec_deque(source)?,
            restore_context_info: read_vec_deque(source)?,
        })
    }
}

impl Serializable for ExecutionReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.block_stack.write_into(target);
        self.execution_context.write_into(target);
        self.stack_overflow.write_into(target);
        self.memory_reads.write_into(target);
        self.advice.write_into(target);
        self.hasher.write_into(target);
        self.block_address.write_into(target);
        self.mast_forest_resolution.write_into(target);
    }
}

impl Deserializable for ExecutionReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            block_stack: BlockStackReplay::read_from(source)?,
            execution_context: ExecutionContextReplay::read_from(source)?,
            stack_overflow: StackOverflowReplay::read_from(source)?,
            memory_reads: MemoryReadsReplay::read_from(source)?,
            advice: AdviceReplay::read_from(source)?,
            hasher: HasherResponseReplay::read_from(source)?,
            block_address: BlockAddressReplay::read_from(source)?,
            mast_forest_resolution: MastForestResolutionReplay::read_from(source)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
mod arbitrary;
