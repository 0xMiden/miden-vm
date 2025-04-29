use alloc::vec::Vec;

// RE-EXPORTS
// ================================================================================================
pub use vm_core::crypto::{
    dsa::*,
    hash::{Rpo256, RpoDigest},
    merkle::{
        EmptySubtreeRoots, LeafIndex, MerkleError, MerklePath, MerkleStore, MerkleTree, Mmr,
        MmrPeaks, NodeIndex, PartialMerkleTree, SimpleSmt, Smt,
    },
};
use vm_core::PrimeCharacteristicRing;
pub use winter_prover::crypto::{
    BatchMerkleProof, DefaultRandomCoin as WinterRandomCoin, ElementHasher, Hasher, RandomCoin,
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
    [Felt::from_u64(value), ZERO, ZERO, ZERO]
}
