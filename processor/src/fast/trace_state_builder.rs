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
    fast::checkpoints::{
        AdviceReplay, BlockStackReplay, CoreTraceState, DecoderState, ExecutionContextSystemInfo,
        ExternalNodeReplay, HasherReplay, MemoryReplay, NodeExecutionPhase, NodeFlags,
        StackOverflowReplay, StackState, SystemState,
    },
    stack::OverflowTable,
};

/// All data stored at the start of a trace fragment
#[derive(Debug)]
struct SnapshotStart {
    system: SystemState,
    decoder_state: DecoderState,
    stack: StackState,
    continuation_stack: ContinuationStack,
    exec_phase: NodeExecutionPhase,
    initial_mast_forest: Arc<MastForest>,
}

/// Builder for recording the core trace state of the processor during execution.
#[derive(Debug, Default)]
pub struct CoreTraceStateBuilder {
    // State that gets snapshotted at the start of each trace fragment
    // TODO(plafer): Do we want to store this in a separate struct?
    pub overflow: OverflowTable,
    pub block_stack: BlockStack,

    // State that gets snapshotted at the end of each trace fragment
    pub hasher: HasherChipletShim,
    pub block_stack_replay: BlockStackReplay,
    pub memory: MemoryReplay,
    pub advice: AdviceReplay,
    pub external: ExternalNodeReplay,
    pub stack_overflow: StackOverflowReplay,

    // State stored at the start of a trace fragment
    snapshot_start: Option<SnapshotStart>,

    // Output
    core_trace_states: Vec<CoreTraceState>,
}

impl CoreTraceStateBuilder {
    /// Extracts the internal state out in order to create a `CoreTraceState`, and stores it
    /// internally.
    ///
    /// The replay data is cleared after extraction, since each trace state is expected to be empty
    /// at the beginning of a new trace fragment. The overflow table and block stack are not cleared
    /// however, since they track the state of the computation since the beginning.
    pub fn extract_new_state(
        &mut self,
        system_state: SystemState,
        decoder_state: DecoderState,
        stack_top: [Felt; MIN_STACK_DEPTH],
        continuation_stack: ContinuationStack,
        exec_phase: NodeExecutionPhase,
        initial_mast_forest: Arc<MastForest>,
    ) {
        // If there is an ongoing snapshot, finish it
        self.finish_current_snapshot();

        // Calculate stack depth: 16 (min stack depth) + overflow elements
        let stack_depth = MIN_STACK_DEPTH + self.overflow.num_elements_in_current_ctx();
        let last_overflow_addr = self.overflow.last_update_clk_in_current_ctx();

        // Start a new snapshot
        self.snapshot_start = Some(SnapshotStart {
            system: system_state,
            decoder_state,
            stack: StackState::new(stack_top, stack_depth, last_overflow_addr),
            continuation_stack,
            exec_phase,
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
        // If there is an ongoing snapshot, finish it
        self.finish_current_snapshot();

        self.core_trace_states
    }

    fn finish_current_snapshot(&mut self) {
        if let Some(snapshot) = self.snapshot_start.take() {
            // Extract the replays
            let hasher_replay = self.hasher.extract_replay();
            let memory_replay = core::mem::take(&mut self.memory);
            let advice_replay = core::mem::take(&mut self.advice);
            let external_replay = core::mem::take(&mut self.external);
            let stack_overflow_replay = core::mem::take(&mut self.stack_overflow);
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
                exec_phase: snapshot.exec_phase,
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

#[derive(Debug)]
pub struct HasherChipletShim {
    addr: u32,
    replay: HasherReplay,
}

impl HasherChipletShim {
    pub fn new() -> Self {
        Self { addr: 1, replay: HasherReplay::default() }
    }

    /// Records the address associated with a `Hasher::hash_control_block` operation.
    pub fn record_hash_control_block(&mut self) -> Felt {
        let block_addr = self.addr.into();

        self.replay.block_addresses.push_back(block_addr);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION;

        block_addr
    }

    /// Records the address associated with a `Hasher::hash_basic_block` operation.
    pub fn record_hash_basic_block(&mut self, basic_block_node: &BasicBlockNode) -> Felt {
        let block_addr = self.addr.into();

        self.replay.block_addresses.push_back(block_addr);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION * basic_block_node.num_op_batches() as u32;

        block_addr
    }

    pub fn record_permute(&mut self, hashed_state: [Felt; 12]) {
        self.replay.record_permute(self.addr.into(), hashed_state);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION;
    }

    pub fn record_build_merkle_root(&mut self, path: &MerklePath, computed_root: Word) {
        self.replay.record_build_merkle_root(self.addr.into(), computed_root);
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION * path.depth() as u32;
    }

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
