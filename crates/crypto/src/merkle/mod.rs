//! Data structures related to Merkle trees based on Poseidon2 hash function.

use super::{EMPTY_WORD, Felt, Word, hash::poseidon2::Poseidon2};

// SUBMODULES
// ================================================================================================

mod empty_roots;
mod error;
mod index;
mod merkle_tree;
mod node;
mod partial_mt;
mod path;
mod sparse_path;

pub mod mmr;
pub mod smt;
pub mod store;

// REEXPORTS
// ================================================================================================

pub use empty_roots::EmptySubtreeRoots;
pub use error::MerkleError;
pub use index::NodeIndex;
pub use merkle_tree::{MerkleTree, path_to_text, tree_to_text};
pub use node::InnerNodeInfo;
pub use partial_mt::PartialMerkleTree;
pub use path::{MerklePath, MerkleProof, RootPath};
pub use sparse_path::SparseMerklePath;

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(test)]
const fn int_to_node(value: u64) -> Word {
    use super::ZERO;
    Word::new([Felt::new_unchecked(value), ZERO, ZERO, ZERO])
}

#[cfg(test)]
const fn int_to_leaf(value: u64) -> Word {
    use super::ZERO;
    Word::new([Felt::new_unchecked(value), ZERO, ZERO, ZERO])
}
