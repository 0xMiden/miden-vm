use alloc::{collections::VecDeque, sync::Arc};

use miden_air::RowIndex;
use miden_core::{
    Felt, Word, ZERO,
    mast::{MastForest, MastNodeId},
    stack::MIN_STACK_DEPTH,
};

use crate::{
    ContextId, continuation_stack::ContinuationStack, decoder::block_stack::BlockStack,
    stack::OverflowTable,
};

// NODE EXECUTION PHASE
// ================================================================================================

/// Specifies the execution phase when starting fragment generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeExecutionPhase {
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
    /// Execute the START phase of a control flow node (JOIN, SPLIT, LOOP, etc.).
    /// This is used when beginning execution of a control flow construct.
    Start(MastNodeId),
    /// Execute a RESPAN for the specified batch within the specified basic block.
    Respan {
        /// Node ID of the basic block being executed
        node_id: MastNodeId,
        /// Index of the operation batch within the basic block
        batch_index: usize,
    },
    /// Execute the REPEAT phase of a Loop node.
    LoopRepeat(MastNodeId),
    /// Execute the END phase of a control flow node (JOIN, SPLIT, LOOP, etc.).
    /// This is used when completing execution of a control flow construct.
    End(MastNodeId),
}

// CORE TRACE STATE
// ================================================================================================

/// The main state for the core processor, which captures all the necessary
/// information to reconstruct the trace during parallel execution.
#[derive(Debug)]
pub struct CoreTraceState {
    pub system: SystemState,
    pub stack: StackState,
    pub block_stack: BlockStack,
    pub traversal: ContinuationStack,
    pub memory: MemoryReplay,
    pub advice: AdviceReplay,
    pub hasher: HasherReplay,
    pub external_node_replay: ExternalNodeReplay,
    pub exec_phase: NodeExecutionPhase,
    pub initial_mast_forest: Arc<MastForest>,
}

/// The `SystemState` represents all the information needed to build one row of the System trace.
///
/// This struct captures the complete state of the system at a specific clock cycle,
/// allowing for reconstruction of the system trace during concurrent execution.
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

/// A checkpoint represents all the information for one row of the Stack trace.
///
/// This struct captures the complete state of the stack at a specific clock cycle,
/// allowing for reconstruction of the stack trace during concurrent execution.
/// The stack trace consists of 19 columns total: 16 stack columns + 3 helper columns.
/// The helper columns (stack_depth, overflow_addr, and overflow_helper) are derived from the
/// OverflowTable.
#[derive(Debug)]
pub struct StackState {
    /// Top 16 stack slots (s0 to s15)
    /// These represent the top elements of the stack that are directly accessible
    stack_top: [Felt; MIN_STACK_DEPTH], // 16 columns

    /// Overflow table containing all stack elements beyond the top 16
    /// Used to derive the helper columns (b0, b1, h0) for the stack trace
    overflow: OverflowTable,
}

impl StackState {
    /// Creates a new StackState with the provided parameters.
    ///
    /// `stack_top` should be the top 16 elements of the stack stored in reverse order, i.e.,
    /// `stack_top[15]` is the topmost element (s0), and `stack_top[0]` is the bottommost element
    /// (s15).
    pub fn new(stack_top: [Felt; MIN_STACK_DEPTH], overflow: OverflowTable) -> Self {
        Self { stack_top, overflow }
    }

    pub fn stack_top(&self) -> &[Felt; MIN_STACK_DEPTH] {
        &self.stack_top
    }

    pub fn stack_top_mut(&mut self) -> &mut [Felt; MIN_STACK_DEPTH] {
        &mut self.stack_top
    }

    /// Returns the value at the specified index in the stack top.
    ///
    /// # Panics
    /// - if the index is greater than or equal to [MIN_STACK_DEPTH].
    pub fn get(&self, index: usize) -> Felt {
        self.stack_top[MIN_STACK_DEPTH - index - 1]
    }

    /// Derives the stack depth (b0 helper column) from the overflow table
    pub fn stack_depth(&self) -> Felt {
        Felt::new((MIN_STACK_DEPTH + self.overflow.num_elements_in_current_ctx()) as u64)
    }

    /// Derives the overflow address (b1 helper column) from the overflow table
    pub fn overflow_addr(&self) -> Felt {
        self.overflow.last_update_clk_in_current_ctx()
    }

    pub fn num_overflow_elements_in_current_ctx(&self) -> usize {
        self.overflow.num_elements_in_current_ctx()
    }

    pub fn advance_clock(&mut self) {
        // Advance the overflow table clock to the next row
        self.overflow.advance_clock();
    }

    pub fn push_overflow(&mut self, element: Felt) {
        self.overflow.push(element);
    }

    pub fn pop_overflow(&mut self) -> Option<Felt> {
        self.overflow.pop()
    }

    /// Derives the overflow helper (h0 helper column) from the current stack depth
    pub fn overflow_helper(&self) -> Felt {
        let stack_depth = self.stack_depth();
        let depth_value = stack_depth.as_int() as usize;

        if depth_value > MIN_STACK_DEPTH {
            // Note: In the actual trace, this gets inverted later via batch inversion
            Felt::new((depth_value - MIN_STACK_DEPTH) as u64)
        } else {
            ZERO
        }
    }

    pub fn start_context(&mut self) -> (usize, Felt) {
        // Return the current stack depth and overflow address at the start of a new context
        let current_depth = self.stack_depth().as_int() as usize;
        let current_overflow_addr = self.overflow_addr();
        self.overflow.start_context();

        (current_depth, current_overflow_addr)
    }

    pub fn restore_context(&mut self) {
        self.overflow.restore_context();
    }
}

#[derive(Debug)]
pub struct ExternalNodeReplay {
    pub external_node_resolutions: VecDeque<(MastNodeId, Arc<MastForest>)>,
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
#[derive(Debug)]
pub struct MemoryReplay {
    pub elements_read: VecDeque<(Felt, Felt)>,
    pub words_read: VecDeque<(Felt, Word)>,
}

impl Default for MemoryReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryReplay {
    /// Creates a new MemoryReplay with empty read vectors
    pub fn new() -> Self {
        Self {
            elements_read: VecDeque::new(),
            words_read: VecDeque::new(),
        }
    }

    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records a read element from memory
    pub fn record_element(&mut self, element: Felt, addr: Felt) {
        self.elements_read.push_back((addr, element));
    }

    /// Records a read word from memory
    pub fn record_word(&mut self, word: Word, addr: Felt) {
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
#[derive(Debug)]
pub struct AdviceReplay {
    // Stack operations
    pub stack_pops: VecDeque<Felt>,
    pub stack_word_pops: VecDeque<Word>,
    pub stack_dword_pops: VecDeque<[Word; 2]>,
}

impl Default for AdviceReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl AdviceReplay {
    /// Creates a new AdviceReplay with empty operation vectors
    pub fn new() -> Self {
        Self {
            stack_pops: VecDeque::new(),
            stack_word_pops: VecDeque::new(),
            stack_dword_pops: VecDeque::new(),
        }
    }

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

/// Implements a shim for the hasher chiplet, in which all hasher operations during a given
/// fragment are pre-recorded by the fast processor.
///
/// This is used to simulate hasher operations in parallel trace generation without needing
/// to actually perform hash computations. All hasher operations are recorded during fast
/// execution and then replayed during parallel trace generation.
#[derive(Debug)]
pub struct HasherReplay {
    /// Recorded hasher addresses from operations like hash_control_block, hash_basic_block, etc.
    pub block_addresses: VecDeque<Felt>,

    /// Recorded hasher operations from permutation operations (HPerm)
    /// Each entry contains (address, output_state)
    pub permutation_operations: VecDeque<(Felt, [Felt; 12])>,

    /// Recorded hasher operations from Merkle path verification operations
    /// Each entry contains (address, computed_root)
    pub build_merkle_root_operations: VecDeque<(Felt, Word)>,

    /// Recorded hasher operations from Merkle root update operations
    /// Each entry contains (address, old_root, new_root)
    pub mrupdate_operations: VecDeque<(Felt, Word, Word)>,
}

impl Default for HasherReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl HasherReplay {
    pub fn new() -> Self {
        Self {
            block_addresses: VecDeque::new(),
            permutation_operations: VecDeque::new(),
            build_merkle_root_operations: VecDeque::new(),
            mrupdate_operations: VecDeque::new(),
        }
    }

    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

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
    // --------------------------------------------------------------------------------

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
