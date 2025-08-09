use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Felt, Word,
    crypto::merkle::MerklePath,
    mast::{BasicBlockNode, MastForest},
    stack::MIN_STACK_DEPTH,
};

use crate::{
    continuation_stack::ContinuationStack,
    decoder::block_stack::BlockStack,
    fast::checkpoints::{
        AdviceReplay, CoreTraceState, ExternalNodeReplay, HasherReplay, MemoryReplay,
        NodeExecutionPhase, StackState, SystemState,
    },
    stack::OverflowTable,
};

/// All data stored at the start of a trace fragment
#[derive(Debug)]
struct SnapshotStart {
    system: SystemState,
    stack: StackState,
    continuation_stack: ContinuationStack,
    exec_phase: NodeExecutionPhase,
    initial_mast_forest: Arc<MastForest>,
    block_stack: BlockStack,
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
    pub memory: MemoryReplay,
    pub advice: AdviceReplay,
    pub external: ExternalNodeReplay,

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
        stack_top: [Felt; MIN_STACK_DEPTH],
        continuation_stack: ContinuationStack,
        exec_phase: NodeExecutionPhase,
        initial_mast_forest: Arc<MastForest>,
    ) {
        // If there is an ongoing snapshot, finish it
        self.finish_current_snapshot();

        // Start a new snapshot
        self.snapshot_start = Some(SnapshotStart {
            system: system_state,
            stack: StackState::new(stack_top, self.overflow.clone()),
            continuation_stack,
            exec_phase,
            initial_mast_forest,
            block_stack: self.block_stack.clone(),
        });
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

            let trace_state = CoreTraceState {
                system: snapshot.system,
                stack: snapshot.stack,
                block_stack: snapshot.block_stack,
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
