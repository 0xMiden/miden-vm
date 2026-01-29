use alloc::vec::Vec;

// RE-EXPORTS
// ================================================================================================
pub use miden_core::crypto::{
    dsa::*,
    hash::Poseidon2,
    merkle::{
        EmptySubtreeRoots, LeafIndex, MerkleError, MerklePath, MerkleStore, MerkleTree, Mmr,
        MmrPeaks, NodeIndex, PartialMerkleTree, SimpleSmt, Smt,
    },
};

use super::{Felt, Word, ZERO};

// CRYPTO HELPER FUNCTIONS
// ================================================================================================

pub fn init_merkle_store(values: &[u64]) -> (Vec<Word>, MerkleStore) {
    let leaves = init_merkle_leaves(values);
    let merkle_tree = MerkleTree::new(leaves.clone()).unwrap();
    let store = MerkleStore::from(&merkle_tree);
    (leaves, store)
}

pub fn init_merkle_leaves(values: &[u64]) -> Vec<Word> {
    values.iter().map(|&v| init_merkle_leaf(v)).collect()
}

pub fn init_merkle_leaf(value: u64) -> Word {
    [Felt::new(value), ZERO, ZERO, ZERO].into()
}
