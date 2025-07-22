use miden_core::{Felt, Word, crypto::merkle::MerklePath, mast::BasicBlockNode};

use crate::{
    fast::checkpoints::{AdviceReplay, ExternalNodeReplay, HasherReplay, MemoryReplay},
    stack::OverflowTable,
};

#[derive(Debug, Default)]
pub struct Shims {
    pub hasher: HasherChipletShim,
    pub memory: MemoryReplay,
    pub advice: AdviceReplay,
    pub external: ExternalNodeReplay,
    pub overflow: OverflowTable,
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
    pub fn record_hash_control_block(&mut self) {
        self.replay.block_addresses.push_back(self.addr.into());
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION;
    }

    /// Records the address associated with a `Hasher::hash_basic_block` operation.
    pub fn record_hash_basic_block(&mut self, basic_block_node: &BasicBlockNode) {
        self.replay.block_addresses.push_back(self.addr.into());
        self.addr += NUM_HASHER_ROWS_PER_PERMUTATION * basic_block_node.num_op_batches() as u32;
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
