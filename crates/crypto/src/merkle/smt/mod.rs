//! Sparse Merkle Tree (SMT) data structures.

use alloc::vec::Vec;
use core::{
    fmt::{self, Display},
    hash::Hash,
};

use super::{EmptySubtreeRoots, InnerNodeInfo, MerkleError, NodeIndex, SparseMerklePath};
use crate::{
    EMPTY_WORD, Map, Set, Word,
    hash::poseidon2::Poseidon2,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

mod full;
pub use full::{MAX_LEAF_ENTRIES, SMT_DEPTH, Smt, SmtLeaf, SmtLeafError, SmtProof, SmtProofError};

#[cfg(feature = "concurrent")]
mod large;
#[cfg(feature = "internal")]
pub use full::concurrent::{SubtreeLeaf, build_subtree_for_bench};
#[cfg(feature = "concurrent")]
pub use large::{
    LargeSmt, LargeSmtError, LargeSmtResult, MemoryStorage, MemoryStorageSnapshot, SmtStorage,
    SmtStorageReader, StorageError, StorageResult, StorageUpdateParts, StorageUpdates, Subtree,
    SubtreeError, SubtreeUpdate,
};
#[cfg(feature = "rocksdb")]
pub use large::{
    RocksDbBloomFilterBitsPerKey, RocksDbConfig, RocksDbDurabilityMode, RocksDbMemoryBudget,
    RocksDbSnapshotStorage, RocksDbStorage, RocksDbTuningOptions, RocksDbWriteBufferManagerBudget,
};

mod large_forest;
pub use large_forest::{
    AppliedLineageMutation, Backend, BackendError, BackendReader, Config as ForestConfig,
    DEFAULT_MAX_HISTORY_VERSIONS as FOREST_DEFAULT_MAX_HISTORY_VERSIONS,
    InMemoryBackend as ForestInMemoryBackend,
    InMemoryBackendSnapshot as ForestInMemoryBackendReader, LargeSmtForest, LargeSmtForestError,
    LineageId, LineageMutation, LineageMutationKind,
    MIN_HISTORY_VERSIONS as FOREST_MIN_HISTORY_VERSIONS, RootInfo, SmtForestMutationSet,
    SmtForestOperation, SmtForestUpdateBatch, SmtUpdateBatch, TreeEntry, TreeId, TreeWithRoot,
    VersionId,
};
#[cfg(feature = "persistent-forest")]
pub use large_forest::{
    PersistentBackend as ForestPersistentBackend, PersistentBackendConfig,
    PersistentBackendReader as ForestPersistentBackendReader,
};

mod simple;
pub use simple::{SimpleSmt, SimpleSmtProof};

mod partial;
pub use partial::{NodeValue, PartialSmt, UniqueNodes};

mod forest;
pub use forest::SmtForest;
use miden_field::Felt;
// CONSTANTS
// ================================================================================================

/// Minimum supported depth.
pub const SMT_MIN_DEPTH: u8 = 1;

/// Maximum supported depth.
pub const SMT_MAX_DEPTH: u8 = 64;

/// The felt used as a domain separator when hashing leaves in merkle trees.
pub const LEAF_DOMAIN: Felt = Felt::new_unchecked(0x13af);

// SPARSE MERKLE TREE
// ================================================================================================

type InnerNodes = Map<NodeIndex, InnerNode>;
type Leaves<T> = Map<u64, T>;
type NodeMutations = Map<NodeIndex, NodeMutation>;

/// The read-only view of a sparse Merkle tree.
///
/// This trait contains all methods that require only read access to the tree, including querying
/// values, generating proofs/openings, and computing prospective mutations. Splitting this from
/// [`SparseMerkleTree`] allows types like `LargeSmt` to implement read-only operations with
/// weaker generic bounds (e.g., `SmtStorageReader` instead of `SmtStorage`).
pub(crate) trait SparseMerkleTreeReader<const DEPTH: u8> {
    /// The type for a key
    type Key: Clone + Ord + Eq + Hash;
    /// The type for a value
    type Value: Clone + PartialEq;
    /// The type for a leaf
    type Leaf: Clone;
    /// The type for an opening (i.e. a "proof") of a leaf
    type Opening;

    /// The default value used to compute the hash of empty leaves
    const EMPTY_VALUE: Self::Value;

    /// The root of the empty tree with provided DEPTH
    const EMPTY_ROOT: Word;

    // PROVIDED METHODS
    // ---------------------------------------------------------------------------------------------

    /// Returns a [SparseMerklePath] to the specified key.
    ///
    /// Mostly this is an implementation detail of [`Self::open()`].
    fn get_path(&self, key: &Self::Key) -> SparseMerklePath {
        let index = NodeIndex::from(Self::key_to_leaf_index(key));

        // SAFETY: this is guaranteed to have depth <= SMT_MAX_DEPTH
        SparseMerklePath::from_sized_iter(
            index.proof_indices().map(|index| self.get_node_hash(index)),
        )
        .expect("failed to convert to SparseMerklePath")
    }

    /// Get the hash of a node at an arbitrary index, including the root or leaf hashes.
    ///
    /// The root index simply returns [`Self::root()`]. Other hashes are retrieved by calling
    /// [`Self::get_inner_node()`] on the parent, and returning the respective child hash.
    fn get_node_hash(&self, index: NodeIndex) -> Word {
        if index.is_root() {
            return self.root();
        }

        let InnerNode { left, right } = self.get_inner_node(index.parent());

        let index_is_right = index.is_position_odd();
        if index_is_right { right } else { left }
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a sparse
    /// Merkle path to the leaf, as well as the leaf itself.
    fn open(&self, key: &Self::Key) -> Self::Opening {
        let leaf = self.get_leaf(key);
        let merkle_path = self.get_path(key);

        Self::path_and_leaf_to_opening(merkle_path, leaf)
    }

    /// Computes what changes are necessary to insert the specified key-value pairs into this Merkle
    /// tree, allowing for validation before applying those changes.
    ///
    /// This method returns a [`MutationSet`], which contains all the information for inserting
    /// `kv_pairs` into this Merkle tree already calculated, including the new root hash, which can
    /// be queried with [`MutationSet::root()`]. Once a mutation set is returned,
    /// [`SparseMerkleTree::apply_mutations()`] can be called in order to commit these changes to
    /// the Merkle tree, or [`drop()`] to discard them.
    ///
    /// # Errors
    /// - Returns [`MerkleError::DuplicateValuesForIndex`] if `kv_pairs` contains duplicate keys.
    /// - If mutations would exceed [`crate::merkle::smt::MAX_LEAF_ENTRIES`] (1024 entries) in a
    ///   leaf, returns [`MerkleError::TooManyLeafEntries`].
    fn compute_mutations(
        &self,
        kv_pairs: impl IntoIterator<Item = (Self::Key, Self::Value)>,
    ) -> Result<MutationSet<DEPTH, Self::Key, Self::Value>, MerkleError> {
        self.compute_mutations_sequential(kv_pairs)
    }

    /// Sequential version of [`SparseMerkleTreeReader::compute_mutations()`].
    /// This is the default implementation.
    ///
    /// # Errors
    ///
    /// - [`MerkleError::DuplicateValuesForIndex`] if `kv_pairs` contains multiple pairs with the
    ///   same key.
    /// - [`MerkleError::TooManyLeafEntries`] if the mutations would cause the tree to exceed
    ///   [`crate::merkle::smt::MAX_LEAF_ENTRIES`] in a single leaf.
    fn compute_mutations_sequential(
        &self,
        kv_pairs: impl IntoIterator<Item = (Self::Key, Self::Value)>,
    ) -> Result<MutationSet<DEPTH, Self::Key, Self::Value>, MerkleError> {
        use NodeMutation::*;

        let mut new_root = self.root();
        let mut new_pairs: Map<Self::Key, Self::Value> = Default::default();
        let mut node_mutations: NodeMutations = NodeMutations::new();
        let mut seen_keys: Set<Self::Key> = Set::new();

        for (key, value) in kv_pairs {
            // Reject duplicate keys.
            if !seen_keys.insert(key.clone()) {
                return Err(MerkleError::DuplicateValuesForIndex(
                    Self::key_to_leaf_index(&key).position(),
                ));
            }

            // If the old value and the new value are the same, there is nothing to update.
            let old_value = new_pairs.get(&key).cloned().unwrap_or_else(|| self.get_value(&key));
            if value == old_value {
                continue;
            }

            let leaf_index = Self::key_to_leaf_index(&key);
            let mut node_index = NodeIndex::from(leaf_index);

            // We need the current leaf's hash to calculate the new leaf, but in the rare case that
            // `kv_pairs` has multiple pairs that go into the same leaf, then those pairs are also
            // part of the "current leaf".
            let old_leaf = {
                let pairs_at_index = new_pairs
                    .iter()
                    .filter(|&(new_key, _)| Self::key_to_leaf_index(new_key) == leaf_index);

                pairs_at_index.fold(self.get_leaf(&key), |acc, (k, v)| {
                    // Most of the time `pairs_at_index` should only contain a single entry (or
                    // none at all), as multi-leaves should be really rare.
                    let existing_leaf = acc;
                    self.construct_prospective_leaf(existing_leaf, k, v)
                        .expect("current leaf should be valid")
                })
            };

            let new_leaf =
                self.construct_prospective_leaf(old_leaf, &key, &value).map_err(|e| match e {
                    SmtLeafError::TooManyLeafEntries { actual } => {
                        MerkleError::TooManyLeafEntries { actual }
                    },
                    other => panic!("unexpected SmtLeaf::insert error: {other:?}"),
                })?;

            let mut new_child_hash = Self::hash_leaf(&new_leaf);

            for node_depth in (0..node_index.depth()).rev() {
                // Whether the node we're replacing is the right child or the left child.
                let is_right = node_index.is_position_odd();
                node_index.move_up();

                let old_node = node_mutations
                    .get(&node_index)
                    .map(|mutation| match mutation {
                        Addition(node) => node.clone(),
                        Removal => EmptySubtreeRoots::get_inner_node(DEPTH, node_depth),
                    })
                    .unwrap_or_else(|| self.get_inner_node(node_index));

                let new_node = if is_right {
                    InnerNode {
                        left: old_node.left,
                        right: new_child_hash,
                    }
                } else {
                    InnerNode {
                        left: new_child_hash,
                        right: old_node.right,
                    }
                };

                // The next iteration will operate on this new node's hash.
                new_child_hash = new_node.hash();

                let &equivalent_empty_hash = EmptySubtreeRoots::entry(DEPTH, node_depth);
                let is_removal = new_child_hash == equivalent_empty_hash;
                let new_entry = if is_removal { Removal } else { Addition(new_node) };
                node_mutations.insert(node_index, new_entry);
            }

            // Once we're at depth 0, the last node we made is the new root.
            new_root = new_child_hash;
            // And then we're done with this pair; on to the next one.
            new_pairs.insert(key, value);
        }

        Ok(MutationSet {
            old_root: self.root(),
            new_root,
            node_mutations,
            new_pairs,
        })
    }

    // REQUIRED METHODS
    // ---------------------------------------------------------------------------------------------

    /// The root of the tree
    fn root(&self) -> Word;

    /// Retrieves an inner node at the given index
    fn get_inner_node(&self, index: NodeIndex) -> InnerNode;

    /// Returns the value at the specified key. Recall that by definition, any key that hasn't been
    /// updated is associated with [`Self::EMPTY_VALUE`].
    fn get_value(&self, key: &Self::Key) -> Self::Value;

    /// Returns the leaf at the specified index.
    fn get_leaf(&self, key: &Self::Key) -> Self::Leaf;

    /// Returns the hash of a leaf
    fn hash_leaf(leaf: &Self::Leaf) -> Word;

    /// Returns what a leaf would look like if a key-value pair were inserted into the tree, without
    /// mutating the tree itself. The existing leaf can be empty.
    ///
    /// To get a prospective leaf based on the current state of the tree, use `self.get_leaf(key)`
    /// as the argument for `existing_leaf`. The return value from this function can be chained back
    /// into this function as the first argument to continue making prospective changes.
    ///
    /// # Invariants
    /// Because this method is for a prospective key-value insertion into a specific leaf,
    /// `existing_leaf` must have the same leaf index as `key` (as determined by
    /// [`SparseMerkleTreeReader::key_to_leaf_index()`]), or the result will be meaningless.
    ///
    /// # Errors
    /// If inserting the key-value pair would exceed
    /// [`crate::merkle::smt::MAX_LEAF_ENTRIES`] (1024 entries) in a leaf,
    /// returns [`SmtLeafError::TooManyLeafEntries`].
    fn construct_prospective_leaf(
        &self,
        existing_leaf: Self::Leaf,
        key: &Self::Key,
        value: &Self::Value,
    ) -> Result<Self::Leaf, SmtLeafError>;

    /// Checks a slice of key-value pairs (assumed sorted by key) for duplicate keys.
    ///
    /// The input `sorted_kv_pairs` must be sorted for this function to return correct results, as
    /// it only performs checks of adjacent elements.
    ///
    /// # Errors
    ///
    /// - [`MerkleError::DuplicateValuesForIndex`] at the first duplicate key found in
    ///   `sorted_kv_pairs`.
    #[cfg(feature = "concurrent")] // Currently only used in concurrent contexts
    fn check_for_duplicate_keys(
        sorted_kv_pairs: &[(Self::Key, Self::Value)],
    ) -> Result<(), MerkleError> {
        if let Some(window) = sorted_kv_pairs.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(MerkleError::DuplicateValuesForIndex(
                Self::key_to_leaf_index(&window[0].0).position(),
            ));
        }
        Ok(())
    }

    /// Maps a key to a leaf index
    fn key_to_leaf_index(key: &Self::Key) -> LeafIndex<DEPTH>;

    /// Maps a (SparseMerklePath, Self::Leaf) to an opening.
    ///
    /// The length `path` is guaranteed to be equal to `DEPTH`
    fn path_and_leaf_to_opening(path: SparseMerklePath, leaf: Self::Leaf) -> Self::Opening;
}

/// An abstract description of a sparse Merkle tree with write capabilities.
///
/// A sparse Merkle tree is a key-value map which also supports proving that a given value is indeed
/// stored at a given key in the tree. It is viewed as always being fully populated. If a leaf's
/// value was not explicitly set, then its value is the default value. Typically, the vast majority
/// of leaves will store the default value (hence it is "sparse"), and therefore the internal
/// representation of the tree will only keep track of the leaves that have a different value from
/// the default.
///
/// All leaves sit at the same depth. The deeper the tree, the more leaves it has; but also the
/// longer its proofs are - of exactly `log(depth)` size. A tree cannot have depth 0, since such a
/// tree is just a single value, and is probably a programming mistake.
///
/// Every key maps to one leaf. If there are as many keys as there are leaves, then
/// [Self::Leaf] should be the same type as [Self::Value], as is the case with
/// [`SimpleSmt`]. However, if there are more keys than leaves, then [`Self::Leaf`]
/// must accommodate all keys that map to the same leaf.
///
/// [SparseMerkleTree] currently doesn't support optimizations that compress Merkle proofs.
pub(crate) trait SparseMerkleTree<const DEPTH: u8>: SparseMerkleTreeReader<DEPTH> {
    // PROVIDED METHODS
    // ---------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Self::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    fn insert(&mut self, key: Self::Key, value: Self::Value) -> Result<Self::Value, MerkleError> {
        let old_value = self.insert_value(key.clone(), value.clone())?.unwrap_or(Self::EMPTY_VALUE);

        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return Ok(value);
        }

        let leaf = self.get_leaf(&key);
        let node_index = {
            let leaf_index: LeafIndex<DEPTH> = Self::key_to_leaf_index(&key);
            leaf_index.into()
        };

        self.recompute_nodes_from_index_to_root(node_index, Self::hash_leaf(&leaf));

        Ok(old_value)
    }

    /// Recomputes the branch nodes (including the root) from `index` all the way to the root.
    /// `node_hash_at_index` is the hash of the node stored at index.
    fn recompute_nodes_from_index_to_root(
        &mut self,
        mut index: NodeIndex,
        node_hash_at_index: Word,
    ) {
        let mut node_hash = node_hash_at_index;
        for node_depth in (0..index.depth()).rev() {
            let is_right = index.is_position_odd();
            index.move_up();
            let InnerNode { left, right } = self.get_inner_node(index);
            let (left, right) = if is_right {
                (left, node_hash)
            } else {
                (node_hash, right)
            };
            node_hash = Poseidon2::merge(&[left, right]);

            if node_hash == *EmptySubtreeRoots::entry(DEPTH, node_depth) {
                // If a subtree is empty, then can remove the inner node, since it's equal to the
                // default value
                self.remove_inner_node(index);
            } else {
                self.insert_inner_node(index, InnerNode { left, right });
            }
        }
        self.set_root(node_hash);
    }

    /// Applies the prospective mutations computed with [`SparseMerkleTree::compute_mutations()`] to
    /// this tree.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    /// If mutations would exceed [`crate::merkle::smt::MAX_LEAF_ENTRIES`] (1024 entries) in a leaf,
    /// returns
    /// [`MerkleError::TooManyLeafEntries`].
    fn apply_mutations(
        &mut self,
        mutations: MutationSet<DEPTH, Self::Key, Self::Value>,
    ) -> Result<(), MerkleError>
    where
        Self: Sized,
    {
        use NodeMutation::*;
        let MutationSet {
            old_root,
            node_mutations,
            new_pairs,
            new_root,
        } = mutations;

        // Guard against accidentally trying to apply mutations that were computed against a
        // different tree, including a stale version of this tree.
        if old_root != self.root() {
            return Err(MerkleError::ConflictingRoots {
                expected_root: self.root(),
                actual_root: old_root,
            });
        }

        for (index, mutation) in node_mutations {
            match mutation {
                Removal => {
                    self.remove_inner_node(index);
                },
                Addition(node) => {
                    self.insert_inner_node(index, node);
                },
            }
        }

        for (key, value) in new_pairs {
            self.insert_value(key, value)?;
        }

        self.set_root(new_root);

        Ok(())
    }

    /// Applies the prospective mutations computed with [`SparseMerkleTree::compute_mutations()`] to
    /// this tree and returns the reverse mutation set. Applying the reverse mutation sets to the
    /// updated tree will revert the changes.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    fn apply_mutations_with_reversion(
        &mut self,
        mutations: MutationSet<DEPTH, Self::Key, Self::Value>,
    ) -> Result<MutationSet<DEPTH, Self::Key, Self::Value>, MerkleError>
    where
        Self: Sized,
    {
        use NodeMutation::*;
        let MutationSet {
            old_root,
            node_mutations,
            new_pairs,
            new_root,
        } = mutations;

        // Guard against accidentally trying to apply mutations that were computed against a
        // different tree, including a stale version of this tree.
        if old_root != self.root() {
            return Err(MerkleError::ConflictingRoots {
                expected_root: self.root(),
                actual_root: old_root,
            });
        }

        let mut reverse_mutations = NodeMutations::new();
        for (index, mutation) in node_mutations {
            match mutation {
                Removal => {
                    if let Some(node) = self.remove_inner_node(index) {
                        reverse_mutations.insert(index, Addition(node));
                    }
                },
                Addition(node) => {
                    if let Some(old_node) = self.insert_inner_node(index, node) {
                        reverse_mutations.insert(index, Addition(old_node));
                    } else {
                        reverse_mutations.insert(index, Removal);
                    }
                },
            }
        }

        let mut reverse_pairs = Map::new();
        for (key, value) in new_pairs {
            match self.insert_value(key.clone(), value)? {
                Some(old_value) => {
                    reverse_pairs.insert(key, old_value);
                },
                None => {
                    reverse_pairs.insert(key, Self::EMPTY_VALUE);
                },
            }
        }

        self.set_root(new_root);

        Ok(MutationSet {
            old_root: new_root,
            node_mutations: reverse_mutations,
            new_pairs: reverse_pairs,
            new_root: old_root,
        })
    }

    // REQUIRED METHODS
    // ---------------------------------------------------------------------------------------------

    /// Sets the root of the tree
    fn set_root(&mut self, root: Word);

    /// Inserts an inner node at the given index
    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode>;

    /// Removes an inner node at the given index
    fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode>;

    /// Inserts a leaf node, and returns the value at the key if already exists
    fn insert_value(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Result<Option<Self::Value>, MerkleError>;
}

// INNER NODE
// ================================================================================================

/// This struct is public so functions returning it can be used in `benches/`, but is otherwise not
/// part of the public API.
#[doc(hidden)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct InnerNode {
    pub left: Word,
    pub right: Word,
}

impl InnerNode {
    pub fn hash(&self) -> Word {
        Poseidon2::merge(&[self.left, self.right])
    }
}

// LEAF INDEX
// ================================================================================================

/// The index of a leaf, at a depth known at compile-time.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct LeafIndex<const DEPTH: u8> {
    index: NodeIndex,
}

impl<const DEPTH: u8> LeafIndex<DEPTH> {
    /// Creates a new `LeafIndex` with the specified value.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided depth is less than the minimum supported depth.
    pub fn new(value: u64) -> Result<Self, MerkleError> {
        if DEPTH < SMT_MIN_DEPTH {
            return Err(MerkleError::DepthTooSmall(DEPTH));
        }

        Ok(LeafIndex { index: NodeIndex::new(DEPTH, value)? })
    }

    /// Returns the position of this leaf index within its depth layer.
    pub fn position(&self) -> u64 {
        self.index.position()
    }
}

impl LeafIndex<SMT_MAX_DEPTH> {
    /// Creates a new `LeafIndex` at the maximum supported depth without validation.
    pub const fn new_max_depth(value: u64) -> Self {
        LeafIndex {
            index: NodeIndex::new_unchecked(SMT_MAX_DEPTH, value),
        }
    }
}

impl<const DEPTH: u8> From<LeafIndex<DEPTH>> for NodeIndex {
    fn from(value: LeafIndex<DEPTH>) -> Self {
        value.index
    }
}

impl<const DEPTH: u8> TryFrom<NodeIndex> for LeafIndex<DEPTH> {
    type Error = MerkleError;

    fn try_from(node_index: NodeIndex) -> Result<Self, Self::Error> {
        if node_index.depth() != DEPTH {
            return Err(MerkleError::InvalidNodeIndexDepth {
                expected: DEPTH,
                provided: node_index.depth(),
            });
        }

        Self::new(node_index.position())
    }
}

impl<const DEPTH: u8> Serializable for LeafIndex<DEPTH> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.index.write_into(target);
    }
}

impl<const DEPTH: u8> Deserializable for LeafIndex<DEPTH> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self { index: source.read()? })
    }
}

impl<const DEPTH: u8> Display for LeafIndex<DEPTH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DEPTH={}, position={}", DEPTH, self.position())
    }
}

// MUTATIONS
// ================================================================================================

/// A change to an inner node of a sparse Merkle tree that hasn't yet been applied.
/// [`MutationSet`] stores this type in relation to a [`NodeIndex`] to keep track of what changes
/// need to occur at which node indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeMutation {
    /// Node needs to be removed.
    Removal,
    /// Node needs to be inserted.
    Addition(InnerNode),
}

/// Represents a group of prospective mutations to a `SparseMerkleTree`, created by
/// `SparseMerkleTree::compute_mutations()`, and that can be applied with
/// `SparseMerkleTree::apply_mutations()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MutationSet<const DEPTH: u8, K: Eq + Hash, V> {
    /// The root of the Merkle tree this MutationSet is for, recorded at the time
    /// [`SparseMerkleTree::compute_mutations()`] was called. Exists to guard against applying
    /// mutations to the wrong tree or applying stale mutations to a tree that has since changed.
    old_root: Word,
    /// The set of nodes that need to be removed or added. The "effective" node at an index is the
    /// Merkle tree's existing node at that index, with the [`NodeMutation`] in this map at that
    /// index overlaid, if any. Each [`NodeMutation::Addition`] corresponds to a
    /// [`SparseMerkleTree::insert_inner_node()`] call, and each [`NodeMutation::Removal`]
    /// corresponds to a [`SparseMerkleTree::remove_inner_node()`] call.
    node_mutations: NodeMutations,
    /// The set of top-level key-value pairs we're prospectively adding to the tree, including
    /// adding empty values. The "effective" value for a key is the value in this Map, falling
    /// back to the existing value in the Merkle tree. Each entry corresponds to a
    /// [`SparseMerkleTree::insert_value()`] call.
    new_pairs: Map<K, V>,
    /// The calculated root for the Merkle tree, given these mutations. Publicly retrievable with
    /// [`MutationSet::root()`]. Corresponds to a [`SparseMerkleTree::set_root()`]. call.
    new_root: Word,
}

impl<const DEPTH: u8, K: Eq + Hash, V> MutationSet<DEPTH, K, V> {
    /// Returns the SMT root that was calculated during `SparseMerkleTree::compute_mutations()`. See
    /// that method for more information.
    pub fn root(&self) -> Word {
        self.new_root
    }

    /// Returns the SMT root before the mutations were applied.
    pub fn old_root(&self) -> Word {
        self.old_root
    }

    /// Returns the set of inner nodes that need to be removed or added.
    pub fn node_mutations(&self) -> &NodeMutations {
        &self.node_mutations
    }

    /// Returns the set of top-level key-value pairs that need to be added, updated or deleted
    /// (i.e. set to `EMPTY_WORD`).
    pub fn new_pairs(&self) -> &Map<K, V> {
        &self.new_pairs
    }

    /// Returns `true` if the mutation set represents no changes to the tree, and `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.node_mutations.is_empty()
            && self.new_pairs.is_empty()
            && self.old_root == self.new_root
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for InnerNode {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.left);
        target.write(self.right);
    }
}

impl Deserializable for InnerNode {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let left = source.read()?;
        let right = source.read()?;

        Ok(Self { left, right })
    }
}

impl Serializable for NodeMutation {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            NodeMutation::Removal => target.write_bool(false),
            NodeMutation::Addition(inner_node) => {
                target.write_bool(true);
                inner_node.write_into(target);
            },
        }
    }
}

impl Deserializable for NodeMutation {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        if source.read_bool()? {
            let inner_node = source.read()?;
            return Ok(NodeMutation::Addition(inner_node));
        }

        Ok(NodeMutation::Removal)
    }
}

impl<const DEPTH: u8, K: Serializable + Eq + Hash, V: Serializable> Serializable
    for MutationSet<DEPTH, K, V>
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.old_root);
        target.write(self.new_root);

        let inner_removals: Vec<_> = self
            .node_mutations
            .iter()
            .filter(|(_, value)| matches!(value, NodeMutation::Removal))
            .map(|(key, _)| key)
            .collect();
        let inner_additions: Vec<_> = self
            .node_mutations
            .iter()
            .filter_map(|(key, value)| match value {
                NodeMutation::Addition(node) => Some((key, node)),
                _ => None,
            })
            .collect();

        target.write(inner_removals);
        target.write(inner_additions);

        target.write_usize(self.new_pairs.len());
        target.write_many(&self.new_pairs);
    }
}

impl<const DEPTH: u8, K: Deserializable + Ord + Eq + Hash, V: Deserializable> Deserializable
    for MutationSet<DEPTH, K, V>
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let old_root = source.read()?;
        let new_root = source.read()?;

        let inner_removals: Vec<NodeIndex> = source.read()?;
        let inner_additions: Vec<(NodeIndex, InnerNode)> = source.read()?;

        let node_mutations = NodeMutations::from_iter(
            inner_removals.into_iter().map(|index| (index, NodeMutation::Removal)).chain(
                inner_additions
                    .into_iter()
                    .map(|(index, node)| (index, NodeMutation::Addition(node))),
            ),
        );

        let num_new_pairs = source.read_usize()?;
        let new_pairs: Map<_, _> =
            source.read_many_iter(num_new_pairs)?.collect::<Result<_, _>>()?;

        Ok(Self {
            old_root,
            node_mutations,
            new_pairs,
            new_root,
        })
    }
}
