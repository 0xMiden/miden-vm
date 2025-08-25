use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Felt, ONE, Word, ZERO,
    crypto::merkle::MerklePath,
    mast::{BasicBlockNode, MastForest},
    stack::MIN_STACK_DEPTH,
};

use crate::{
    continuation_stack::ContinuationStack,
    decoder::block_stack::{BlockInfo, BlockStack},
    fast::trace_state::{
        AdviceReplay, BlockStackReplay, CoreTraceState, DecoderState, ExecutionContextSystemInfo,
        ExternalNodeReplay, HasherReplay, MemoryReplay, NodeExecutionState, NodeFlags,
        StackOverflowReplay, StackState, SystemState,
    },
    stack::OverflowTable,
};

/// Execution state snapshot, used to record the state at the start of a trace fragment.
#[derive(Debug)]
struct StateSnapshot {
    system: SystemState,
    decoder_state: DecoderState,
    stack: StackState,
    continuation_stack: ContinuationStack,
    execution_state: NodeExecutionState,
    initial_mast_forest: Arc<MastForest>,
}

/// Builder for recording the core trace state of the processor during execution.
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
pub struct CoreTraceStateBuilder {
    // State stored at the start of a trace fragment
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
    core_trace_states: Vec<CoreTraceState>,
}

impl CoreTraceStateBuilder {
    /// Captures the internal state into a new [CoreTraceState] (stored internally), resets the
    /// internal replay state of the builder, and records a new state snapshot, marking the
    /// beginning of the next trace state.
    ///
    /// This must be called at the beginning of a new trace fragment, before executing the first
    /// operation. Internal replay fields are expected to be accessed during execution of this new
    /// fragment to record data to be replayed by the trace fragment generators.
    pub fn start_new_trace_state(
        &mut self,
        system_state: SystemState,
        decoder_state: DecoderState,
        stack_top: [Felt; MIN_STACK_DEPTH],
        continuation_stack: ContinuationStack,
        execution_state: NodeExecutionState,
        initial_mast_forest: Arc<MastForest>,
    ) {
        // If there is an ongoing snapshot, finish it
        self.finish_current_trace_state();

        // Calculate stack depth: 16 (min stack depth) + overflow elements
        let stack_depth = MIN_STACK_DEPTH + self.overflow_table.num_elements_in_current_ctx();
        let last_overflow_addr = self.overflow_table.last_update_clk_in_current_ctx();

        // Start a new snapshot
        self.state_snapshot = Some(StateSnapshot {
            system: system_state,
            decoder_state,
            stack: StackState::new(stack_top, stack_depth, last_overflow_addr),
            continuation_stack,
            execution_state,
            initial_mast_forest,
        });
    }

    /// Records the block address and flags for an END operation based on the block being popped.
    pub fn record_node_end(&mut self, block_info: &BlockInfo) {
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
    pub fn record_execution_context(&mut self, ctx_info: ExecutionContextSystemInfo) {
        self.block_stack_replay.record_execution_context(ctx_info);
    }

    /// Convert the `CoreTraceStateBuilder` into the list of `CoreTraceState` built during
    /// execution.
    pub fn into_core_trace_states(mut self) -> Vec<CoreTraceState> {
        // If there is an ongoing trace state being built, finish it
        self.finish_current_trace_state();

        self.core_trace_states
    }

    /// Records the current core trace state, if any.
    ///
    /// Specifically, extracts the stored [SnapshotStart] as well as all the replay data recorded
    /// from the various components (e.g. memory, advice, etc) since the last call to this method.
    /// Resets the internal state to default values to prepare for the next trace fragment.
    ///
    /// Note that the very first time that this is called (at clock cycle 0), the snapshot will not
    /// contain any replay data, and so no core trace state will be recorded.
    fn finish_current_trace_state(&mut self) {
        if let Some(snapshot) = self.state_snapshot.take() {
            // Extract the replays
            let hasher_replay = self.hasher.extract_replay();
            let memory_replay = core::mem::take(&mut self.memory);
            let advice_replay = core::mem::take(&mut self.advice);
            let external_replay = core::mem::take(&mut self.external);
            let stack_overflow_replay = core::mem::take(&mut self.overflow_replay);
            let block_stack_replay = core::mem::take(&mut self.block_stack_replay);

            let trace_state = CoreTraceState {
                system: snapshot.system,
                decoder: snapshot.decoder_state,
                stack: snapshot.stack,
                stack_overflow: stack_overflow_replay,
                block_stack_replay,
                traversal: snapshot.continuation_stack,
                hasher: hasher_replay,
                memory: memory_replay,
                advice: advice_replay,
                external_node_replay: external_replay,
                execution_state: snapshot.execution_state,
                initial_mast_forest: snapshot.initial_mast_forest,
            };

            self.core_trace_states.push(trace_state);
        }
    }
}

// HASHER CHIPLET SHIM
// =========================================================

/// The number of hasher rows per permutation operation. This is used to compute the address for the
/// next operation in the hasher chiplet.
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
