//! Large-scale Sparse Merkle Tree backed by pluggable storage.
//!
//! `LargeSmt` stores the top of the tree (depths 0–`IN_MEMORY_DEPTH`-1) in memory and persists
//! the lower depths in storage as fixed-size subtrees. This hybrid layout scales beyond RAM
//! while keeping common operations fast. With the `rocksdb` feature enabled, the lower
//! subtrees and leaves are stored in RocksDB. On reload, the in-memory top is reconstructed
//! from cached in-memory-depth subtree roots.
//!
//! Examples below require the `rocksdb` feature.
//!
//! Load an existing RocksDB-backed tree with root validation:
//! ```no_run
//! # #[cfg(feature = "rocksdb")]
//! # {
//! use miden_crypto::{
//!     Word,
//!     merkle::smt::{LargeSmt, RocksDbConfig, RocksDbStorage},
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let expected_root: Word = miden_crypto::EMPTY_WORD;
//! let storage = RocksDbStorage::open(RocksDbConfig::new("/path/to/db"))?;
//! let smt = LargeSmt::load_with_root(storage, expected_root)?;
//! assert_eq!(smt.root(), expected_root);
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! Load an existing tree without root validation (use with caution):
//! ```no_run
//! # #[cfg(feature = "rocksdb")]
//! # {
//! use miden_crypto::merkle::smt::{LargeSmt, RocksDbConfig, RocksDbStorage};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = RocksDbStorage::open(RocksDbConfig::new("/path/to/db"))?;
//! let smt = LargeSmt::load(storage)?;
//! let _root = smt.root();
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! Initialize an empty RocksDB-backed tree and bulk-load entries:
//! ```no_run
//! # #[cfg(feature = "rocksdb")]
//! # {
//! use miden_crypto::{
//!     Felt, Word,
//!     merkle::smt::{LargeSmt, RocksDbConfig, RocksDbStorage},
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let path = "/path/to/new-db";
//! if std::path::Path::new(path).exists() {
//!     std::fs::remove_dir_all(path)?;
//! }
//! std::fs::create_dir_all(path)?;
//!
//! let storage = RocksDbStorage::open(RocksDbConfig::new(path))?;
//! let mut smt = LargeSmt::new(storage)?; // empty tree
//!
//! // Prepare initial entries
//! let entries = vec![
//!     (
//!         Word::new([
//!             Felt::new_unchecked(1),
//!             Felt::new_unchecked(0),
//!             Felt::new_unchecked(0),
//!             Felt::new_unchecked(0),
//!         ]),
//!         Word::new([
//!             Felt::new_unchecked(10),
//!             Felt::new_unchecked(20),
//!             Felt::new_unchecked(30),
//!             Felt::new_unchecked(40),
//!         ]),
//!     ),
//!     (
//!         Word::new([
//!             Felt::new_unchecked(2),
//!             Felt::new_unchecked(0),
//!             Felt::new_unchecked(0),
//!             Felt::new_unchecked(0),
//!         ]),
//!         Word::new([
//!             Felt::new_unchecked(11),
//!             Felt::new_unchecked(22),
//!             Felt::new_unchecked(33),
//!             Felt::new_unchecked(44),
//!         ]),
//!     ),
//! ];
//!
//! // Bulk insert entries (faster than compute_mutations + apply_mutations)
//! smt.insert_batch(entries)?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! Apply batch updates (insertions and deletions):
//! ```no_run
//! # #[cfg(feature = "rocksdb")]
//! # {
//! use miden_crypto::{
//!     EMPTY_WORD, Felt, Word,
//!     merkle::smt::{LargeSmt, RocksDbConfig, RocksDbStorage},
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = RocksDbStorage::open(RocksDbConfig::new("/path/to/db"))?;
//! let mut smt = LargeSmt::load(storage)?;
//!
//! let k1 = Word::new([
//!     Felt::new_unchecked(101),
//!     Felt::new_unchecked(0),
//!     Felt::new_unchecked(0),
//!     Felt::new_unchecked(0),
//! ]);
//! let v1 = Word::new([
//!     Felt::new_unchecked(1),
//!     Felt::new_unchecked(2),
//!     Felt::new_unchecked(3),
//!     Felt::new_unchecked(4),
//! ]);
//! let k2 = Word::new([
//!     Felt::new_unchecked(202),
//!     Felt::new_unchecked(0),
//!     Felt::new_unchecked(0),
//!     Felt::new_unchecked(0),
//! ]);
//! let k3 = Word::new([
//!     Felt::new_unchecked(303),
//!     Felt::new_unchecked(0),
//!     Felt::new_unchecked(0),
//!     Felt::new_unchecked(0),
//! ]);
//! let v3 = Word::new([
//!     Felt::new_unchecked(7),
//!     Felt::new_unchecked(7),
//!     Felt::new_unchecked(7),
//!     Felt::new_unchecked(7),
//! ]);
//!
//! // EMPTY_WORD marks deletions
//! let updates = vec![(k1, v1), (k2, EMPTY_WORD), (k3, v3)];
//! smt.insert_batch(updates)?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! Quick initialization with `with_entries` (best for modest datasets/tests):
//! ```no_run
//! # #[cfg(feature = "rocksdb")]
//! # {
//! use miden_crypto::{
//!     Felt, Word,
//!     merkle::smt::{LargeSmt, RocksDbConfig, RocksDbStorage},
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Note: `with_entries` expects an EMPTY storage and performs an all-at-once build.
//! // Prefer `insert_batch` for large bulk loads.
//! let path = "/path/to/new-db";
//! if std::path::Path::new(path).exists() {
//!     std::fs::remove_dir_all(path)?;
//! }
//! std::fs::create_dir_all(path)?;
//!
//! let storage = RocksDbStorage::open(RocksDbConfig::new(path))?;
//! let entries = vec![
//!     (
//!         Word::new([
//!             Felt::new_unchecked(1),
//!             Felt::new_unchecked(0),
//!             Felt::new_unchecked(0),
//!             Felt::new_unchecked(0),
//!         ]),
//!         Word::new([
//!             Felt::new_unchecked(10),
//!             Felt::new_unchecked(20),
//!             Felt::new_unchecked(30),
//!             Felt::new_unchecked(40),
//!         ]),
//!     ),
//!     (
//!         Word::new([
//!             Felt::new_unchecked(2),
//!             Felt::new_unchecked(0),
//!             Felt::new_unchecked(0),
//!             Felt::new_unchecked(0),
//!         ]),
//!         Word::new([
//!             Felt::new_unchecked(11),
//!             Felt::new_unchecked(22),
//!             Felt::new_unchecked(33),
//!             Felt::new_unchecked(44),
//!         ]),
//!     ),
//! ];
//! let _smt = LargeSmt::with_entries(storage, entries)?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ## Performance and Memory Considerations
//!
//! The `apply_mutations()` and `apply_mutations_with_reversion()` methods use batched
//! operations: they preload all affected subtrees and leaves before applying changes
//! atomically. This approach reduces I/O at the cost of higher temporary memory usage.
//!
//! ### Memory Usage
//!
//! Peak memory is proportional to:
//! - The number of mutated leaves
//! - The number of distinct storage subtrees touched by those mutations
//!
//! This memory is temporary and released immediately after the batch commits.
//!
//! ### Locality Matters
//!
//! Memory usage scales with how dispersed updates are, not just their count:
//! - **Localized updates**: Keys with shared high-order bits fall into the same storage subtrees
//! - **Scattered updates**: Keys spread across many storage subtrees require loading more distinct
//!   subtrees
//!
//! ### Guidelines
//!
//! For typical batches (up to ~10,000 updates) with reasonable locality, the working set
//! is modest. Very large or highly scattered batches will use more
//! memory proportionally.
//!
//! To optimize memory and I/O: group updates by key locality so that keys sharing
//! high-order bits are processed together.

use alloc::{sync::Arc, vec::Vec};

use super::{
    EmptySubtreeRoots, InnerNode, InnerNodeInfo, LeafIndex, MerkleError, NodeIndex, NodeMutation,
    SMT_DEPTH, SmtLeaf, SmtProof, SparseMerkleTree, SparseMerkleTreeReader, Word,
};
use crate::{
    EMPTY_WORD,
    merkle::smt::{Map, full::concurrent::MutatedSubtreeLeaves},
};

mod error;
pub use error::LargeSmtError;

#[cfg(test)]
mod property_tests;
#[cfg(test)]
mod tests;

mod subtree;
pub use subtree::{Subtree, SubtreeError};

mod storage;
pub use storage::{
    MemoryStorage, MemoryStorageSnapshot, SmtStorage, SmtStorageReader, StorageError,
    StorageUpdateParts, StorageUpdates, SubtreeUpdate,
};
#[cfg(feature = "rocksdb")]
pub use storage::{RocksDbConfig, RocksDbSnapshotStorage, RocksDbStorage};

mod iter;
pub use iter::LargeSmtInnerNodeIterator;

mod batch_ops;
mod construction;
mod smt_trait;

// CONSTANTS
// ================================================================================================

/// Number of levels of the tree that are stored in memory.
pub(super) const IN_MEMORY_DEPTH: u8 = 16;

/// Number of nodes that are stored in memory (including the unused index 0).
const NUM_IN_MEMORY_NODES: usize = 1 << (IN_MEMORY_DEPTH + 1);

/// Index of the root node inside `in_memory_nodes`.
pub(super) const ROOT_MEMORY_INDEX: usize = 1;

/// Number of subtree levels below in-memory depth (16-64 in steps of 8).
const NUM_SUBTREE_LEVELS: usize = 6;

/// How many subtrees we buffer before flushing them to storage **during the
/// SMT construction phase**.
///
/// * This constant is **only** used while building a fresh tree; incremental updates use their own
///   per-batch sizing.
/// * Construction is all-or-nothing: if the write fails we abort and rebuild from scratch, so we
///   allow larger batches that maximise I/O throughput instead of fine-grained rollback safety.
const CONSTRUCTION_SUBTREE_BATCH_SIZE: usize = 10_000;

// TYPES
// ================================================================================================

/// Result of loading leaves from storage: (leaf indices, map of leaf index to leaf).
type LoadedLeaves = (Vec<u64>, Map<u64, Option<SmtLeaf>>);

/// Result of processing key-value pairs into mutated leaves for subtree building:
/// - `MutatedSubtreeLeaves`: Leaves organized for parallel subtree building
/// - `Map<u64, SmtLeaf>`: Map of leaf index to mutated leaf node (for storage updates)
/// - `Map<Word, Word>`: Changed key-value pairs
/// - `isize`: Leaf count delta
/// - `isize`: Entry count delta
type MutatedLeaves = (MutatedSubtreeLeaves, Map<u64, SmtLeaf>, Map<Word, Word>, isize, isize);

// LargeSmt
// ================================================================================================

/// A large-scale Sparse Merkle tree mapping 256-bit keys to 256-bit values, backed by pluggable
/// storage. Both keys and values are represented by 4 field elements.
///
/// Unlike the regular `Smt`, this implementation is designed for very large trees by using external
/// storage (such as RocksDB) for the bulk of the tree data, while keeping only the upper levels (up
/// to `IN_MEMORY_DEPTH`) in memory. This hybrid approach allows the tree to scale beyond memory
/// limitations while maintaining good performance for common operations.
///
/// All leaves sit at depth 64. The most significant element of the key is used to identify the leaf
/// to which the key maps.
///
/// A leaf is either empty, or holds one or more key-value pairs. An empty leaf hashes to the empty
/// word. Otherwise, a leaf hashes to the hash of its key-value pairs, ordered by key first, value
/// second.
///
/// The tree structure:
/// - Depths 0-23: Stored in memory as a flat array for fast access
/// - Depths 24-64: Stored in external storage organized as subtrees for efficient batch operations
///
/// `LargeSmt` implements [`Clone`] when its storage is cloneable. The in-memory top is shared and
/// detaches on mutation.
#[derive(Clone, Debug)]
pub struct LargeSmt<S: SmtStorageReader> {
    storage: S,
    /// Shared flat array representation of in-memory nodes.
    /// Index 0 is unused; index 1 is root.
    /// For node at index i: left child at 2*i, right child at 2*i+1.
    in_memory_nodes: Arc<[Word]>,
    /// Cached count of non-empty leaves. Initialized from storage on load,
    /// updated after each mutation.
    leaf_count: usize,
    /// Cached count of key-value entries across all leaves. Initialized from
    /// storage on load, updated after each mutation.
    entry_count: usize,
}

impl<S: SmtStorageReader> LargeSmt<S> {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// The default value used to compute the hash of empty leaves.
    pub const EMPTY_VALUE: Word = EMPTY_WORD;

    /// The root of an empty tree.
    pub const EMPTY_ROOT: Word = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    /// Subtree depths for the subtrees stored in storage.
    pub const SUBTREE_DEPTHS: [u8; 6] = [56, 48, 40, 32, 24, 16];

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the depth of the tree
    pub const fn depth(&self) -> u8 {
        SMT_DEPTH
    }

    /// Returns the root of the tree
    pub fn root(&self) -> Word {
        <Self as SparseMerkleTreeReader<SMT_DEPTH>>::root(self)
    }

    /// Returns the number of non-empty leaves in this tree.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_leaves(&self) -> usize {
        self.leaf_count
    }

    /// Returns the number of key-value pairs with non-default values in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_entries(&self) -> usize {
        self.entry_count
    }

    /// Returns the leaf to which `key` maps
    pub fn get_leaf(&self, key: &Word) -> SmtLeaf {
        <Self as SparseMerkleTreeReader<SMT_DEPTH>>::get_leaf(self, key)
    }

    /// Returns the value associated with `key`
    pub fn get_value(&self, key: &Word) -> Word {
        <Self as SparseMerkleTreeReader<SMT_DEPTH>>::get_value(self, key)
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    pub fn open(&self, key: &Word) -> SmtProof {
        <Self as SparseMerkleTreeReader<SMT_DEPTH>>::open(self, key)
    }

    /// Returns a boolean value indicating whether the SMT is empty.
    pub fn is_empty(&self) -> bool {
        let root = self.root();
        debug_assert_eq!(self.leaf_count == 0, root == Self::EMPTY_ROOT);
        root == Self::EMPTY_ROOT
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [`LargeSmt`].
    /// Note: This iterator returns owned SmtLeaf values.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to create the iterator.
    pub fn leaves(
        &self,
    ) -> Result<impl Iterator<Item = (LeafIndex<SMT_DEPTH>, SmtLeaf)>, LargeSmtError> {
        let iter = self.storage.iter_leaves()?;
        Ok(iter.map(|(idx, leaf)| (LeafIndex::new_max_depth(idx), leaf)))
    }

    /// Returns an iterator over the key-value pairs of this [`LargeSmt`].
    /// Note: This iterator returns owned (Word, Word) tuples.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to create the iterator.
    pub fn entries(&self) -> Result<impl Iterator<Item = (Word, Word)>, LargeSmtError> {
        let leaves_iter = self.leaves()?;
        Ok(leaves_iter.flat_map(|(_, leaf)| {
            // Collect the (Word, Word) tuples into an owned Vec
            // This ensures they outlive the 'leaf' from which they are derived.
            let owned_entries: Vec<(Word, Word)> = leaf.entries().to_vec();
            // Return an iterator over this owned Vec
            owned_entries.into_iter()
        }))
    }

    /// Returns an iterator over the inner nodes of this [`LargeSmt`].
    ///
    /// # Errors
    /// Returns an error if the storage backend fails during iteration setup.
    pub fn inner_nodes(&self) -> Result<impl Iterator<Item = InnerNodeInfo> + '_, LargeSmtError> {
        // Pre-validate that storage is accessible
        let _ = self.storage.iter_subtrees()?;
        Ok(LargeSmtInnerNodeIterator::new(self))
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the inner node at the given index.
    ///
    /// For in-memory depths (< 24), reads from the flat in-memory array.
    /// For deeper nodes, reads from storage.
    pub(crate) fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        <Self as SparseMerkleTreeReader<SMT_DEPTH>>::get_inner_node(self, index)
    }

    // Triggers copy-on-write: clones the shared node array only if other references exist.
    pub(crate) fn in_memory_nodes_mut(&mut self) -> &mut [Word] {
        Arc::make_mut(&mut self.in_memory_nodes)
    }

    /// Helper to get an in-memory node if not empty.
    ///
    /// # Panics
    /// With debug assertions on, panics if `index.depth() >= IN_MEMORY_DEPTH`.
    fn get_non_empty_inner_node(&self, index: NodeIndex) -> Option<InnerNode> {
        debug_assert!(index.depth() < IN_MEMORY_DEPTH, "Only for in-memory nodes");

        let memory_index = to_memory_index(&index);

        let left = self.in_memory_nodes[memory_index * 2];
        let right = self.in_memory_nodes[memory_index * 2 + 1];

        // Check if both children are empty
        let child_depth = index.depth() + 1;
        if is_empty_parent(left, right, child_depth) {
            None
        } else {
            Some(InnerNode { left, right })
        }
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    #[cfg(test)]
    pub(crate) fn in_memory_nodes(&self) -> &[Word] {
        &self.in_memory_nodes
    }
}

impl<S: SmtStorage> LargeSmt<S> {
    /// Returns a read-only `LargeSmt` backed by a reader view of this tree's storage.
    ///
    /// The new tree shares the same root, leaf count, and entry count as `self`, and its storage
    /// is a point-in-time snapshot produced by [`SmtStorage::reader`]. The returned tree's storage
    /// type is `S::Reader: SmtStorageReader`, so it cannot be used for mutations.
    pub fn reader(&self) -> Result<LargeSmt<S::Reader>, LargeSmtError> {
        Ok(LargeSmt {
            storage: self.storage.reader()?,
            in_memory_nodes: self.in_memory_nodes.clone(),
            leaf_count: self.leaf_count,
            entry_count: self.entry_count,
        })
    }

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Self::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    ///
    /// # Errors
    /// Returns an error if inserting the key-value pair would exceed
    /// [`MAX_LEAF_ENTRIES`](super::MAX_LEAF_ENTRIES) (1024 entries) in the leaf.
    pub fn insert(&mut self, key: Word, value: Word) -> Result<Word, MerkleError> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::insert(self, key, value)
    }
}

// HELPERS
// ================================================================================================

/// Checks if a node with the given children is empty.
/// A node is considered empty if both children equal the empty hash for that depth.
pub(super) fn is_empty_parent(left: Word, right: Word, child_depth: u8) -> bool {
    let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth);
    left == empty_hash && right == empty_hash
}

/// Converts a NodeIndex to a flat vector index using 1-indexed layout.
/// Index 0 is unused, index 1 is root.
/// For a node at index i: left child at 2*i, right child at 2*i+1.
pub(super) fn to_memory_index(index: &NodeIndex) -> usize {
    debug_assert!(index.depth() < IN_MEMORY_DEPTH);
    debug_assert!(index.position() < (1 << index.depth()));
    (1usize << index.depth()) + index.position() as usize
}

impl<S: SmtStorageReader> PartialEq for LargeSmt<S> {
    /// Compares two LargeSmt instances based on their root hash and metadata.
    ///
    /// Note: This comparison only checks the root hash and counts, not the underlying
    /// storage contents. Two SMTs with the same root should be cryptographically
    /// equivalent, but this doesn't verify the storage backends are identical.
    fn eq(&self, other: &Self) -> bool {
        self.root() == other.root()
            && self.leaf_count == other.leaf_count
            && self.entry_count == other.entry_count
    }
}

impl<S: SmtStorageReader> Eq for LargeSmt<S> {}
