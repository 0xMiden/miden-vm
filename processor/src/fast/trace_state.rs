use alloc::{collections::VecDeque, sync::Arc};

use miden_air::RowIndex;
use miden_core::{
    Felt, ONE, Word, ZERO,
    mast::{MastForest, MastNodeId},
    stack::MIN_STACK_DEPTH,
};

use crate::{ContextId, continuation_stack::ContinuationStack, fast::FastProcessor};

// TRACE FRAGMENT CONTEXT
// ================================================================================================

/// Information required to build a trace fragment of length [super::NUM_ROWS_PER_CORE_FRAGMENT].
///
/// This struct is meant to be built by the processor, and consumed mutably by a trace fragment
/// builder. That is, as trace generation progresses, this struct can be mutated to represent the
/// generation context at any clock cycle within the fragment.
///
/// This struct is conceptually divided into 4 main components:
/// 1. core trace state: the state of the processor at any clock cycle in the fragment, initialized
///    to the state at the first clock cycle in the fragment,
/// 2. execution replay: information needed to replay the execution of the processor for the
///    remainder of the fragment,
/// 3. continuation: a stack of continuations for the processor representing the nodes in the MAST
///    forest to execute when the current node is done executing,
/// 4. initial state: some information about the state of the execution at the start of the
///    fragment. This includes the [MastForest] that is being executed at the start of the fragment
///    (which can change when encountering an [miden_core::mast::ExternalNode]), and the current
///    node's execution state, which contains additional information to pinpoint exactly where in
///    the processing of the node we're at when this fragment begins.
#[derive(Debug)]
pub struct TraceFragmentContext {
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

    /// Free memory pointer - initially set to 2^30, used for local memory offsets
    pub fmp: Felt,

    /// Flag indicating whether currently executing within a SYSCALL block
    pub in_syscall: bool,

    /// Hash of the function that initiated the current execution context
    /// - For root context: [ZERO; 4]
    /// - For CALL/DYNCALL contexts: hash of the called function
    /// - For SYSCALL contexts: hash remains from the calling function
    pub fn_hash: Word,
}

impl SystemState {
    /// Convenience constructor that creates a new `SystemState` from a `FastProcessor`.
    pub fn from_processor(processor: &FastProcessor) -> Self {
        Self {
            clk: processor.clk,
            ctx: processor.ctx,
            fmp: processor.fmp,
            in_syscall: processor.in_syscall,
            fn_hash: processor.caller_hash,
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
    pub memory: MemoryReplay,
    pub advice: AdviceReplay,
    pub hasher: HasherReplay,
    pub external_node: ExternalNodeReplay,
}

// BLOCK STACK REPLAY
// ================================================================================================

/// Replay data for the block stack.
#[derive(Debug, Default)]
pub struct BlockStackReplay {
    /// The parent address - needed for each node start operation (JOIN, SPLIT, etc).
    node_start: VecDeque<Felt>,
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
            node_start: VecDeque::new(),
            node_end: VecDeque::new(),
            execution_contexts: VecDeque::new(),
        }
    }

    /// Records the node's parent address
    pub fn record_node_start(&mut self, parent_addr: Felt) {
        self.node_start.push_back(parent_addr);
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
    pub fn replay_node_start(&mut self) -> Felt {
        self.node_start.pop_front().expect("No node start address recorded")
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
    pub parent_fmp: Felt,
}

// EXTERNAL NODE REPLAY
// ================================================================================================

#[derive(Debug)]
pub struct ExternalNodeReplay {
    external_node_resolutions: VecDeque<(MastNodeId, Arc<MastForest>)>,
}

impl Default for ExternalNodeReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalNodeReplay {
    /// Creates a new ExternalNodeReplay with an empty resolution queue
    pub fn new() -> Self {
        Self {
            external_node_resolutions: VecDeque::new(),
        }
    }

    /// Records a resolution of an external node to a MastNodeId with its associated MastForest
    pub fn record_resolution(&mut self, node_id: MastNodeId, forest: Arc<MastForest>) {
        self.external_node_resolutions.push_back((node_id, forest));
    }

    /// Replays the next recorded external node resolution, returning both the node ID and forest
    pub fn replay_resolution(&mut self) -> (MastNodeId, Arc<MastForest>) {
        self.external_node_resolutions
            .pop_front()
            .expect("No external node resolutions recorded")
    }
}

// MEMORY REPLAY
// ================================================================================================

/// Implements a shim for the memory chiplet, in which all elements read from memory during a given
/// fragment are recorded by the fast processor, and replayed by the main trace fragment generators.
///
/// This is used to simulate memory reads in parallel trace generation without needing to actually
/// access the memory chiplet. Writes are not recorded here, as they are not needed for the trace
/// generation process.
///
/// Elements/words read are stored with their addresses and are assumed to be read from the same
/// addresses that they were recorded at. This works naturally since the fast processor has exactly
/// the same access patterns as the main trace generators (which re-executes part of the program).
/// The read methods include debug assertions to verify address consistency.
#[derive(Debug, Default)]
pub struct MemoryReplay {
    elements_read: VecDeque<(Felt, Felt)>,
    words_read: VecDeque<(Felt, Word)>,
}

impl MemoryReplay {
    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records a read element from memory
    pub fn record_read_element(&mut self, element: Felt, addr: Felt) {
        self.elements_read.push_back((addr, element));
    }

    /// Records a read word from memory
    pub fn record_read_word(&mut self, word: Word, addr: Felt) {
        self.words_read.push_back((addr, word));
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------

    pub fn replay_read_element(&mut self, addr: Felt) -> Felt {
        let (stored_addr, element) =
            self.elements_read.pop_front().expect("No elements read from memory");
        debug_assert_eq!(stored_addr, addr, "Address mismatch: expected {addr}, got {stored_addr}");
        element
    }

    pub fn replay_read_word(&mut self, addr: Felt) -> Word {
        let (stored_addr, word) = self.words_read.pop_front().expect("No words read from memory");
        debug_assert_eq!(stored_addr, addr, "Address mismatch: expected {addr}, got {stored_addr}");
        word
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

// HASHER REPLAY
// ================================================================================================

/// Implements a shim for the hasher chiplet, in which all hasher operations during a given
/// fragment are pre-recorded by the fast processor.
///
/// This is used to simulate hasher operations in parallel trace generation without needing
/// to actually perform hash computations. All hasher operations are recorded during fast
/// execution and then replayed during parallel trace generation.
#[derive(Debug, Default)]
pub struct HasherReplay {
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

impl HasherReplay {
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
/// [super::NUM_ROWS_PER_CORE_FRAGMENT]), specifying which MAST node we're executing is
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
