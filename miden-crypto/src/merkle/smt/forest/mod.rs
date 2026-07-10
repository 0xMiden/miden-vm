use alloc::{collections::BTreeSet, vec::Vec};

use super::{EmptySubtreeRoots, MerkleError, NodeIndex, SmtLeaf, SmtProof, Word};
use crate::{
    Map,
    merkle::smt::{LeafIndex, SMT_DEPTH, SmtLeafError, SmtProofError, forest::store::SmtStore},
};

mod store;

#[cfg(test)]
mod tests;

// SPARSE MERKLE TREE FOREST
// ================================================================================================

/// An in-memory data collection of sparse Merkle trees (SMTs).
///
/// Each SMT in the forest is identified by its root hash. The forest stores all leaves of all SMTs
/// in the forest, as well as all Merkle paths required to prove membership of any leaf in any SMT.
///
/// An empty tree root is always present in the forest.
///
/// Example usage:
///
/// ```rust
/// use miden_crypto::{
///     Felt, ONE, Word, ZERO,
///     merkle::{
///         EmptySubtreeRoots,
///         smt::{MAX_LEAF_ENTRIES, SMT_DEPTH, SmtForest},
///     },
/// };
///
/// // Create a new SMT forest
/// let mut forest = SmtForest::new();
///
/// // Insert a key-value pair into an SMT with an empty root
/// let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
/// let key = Word::new([ZERO; Word::NUM_ELEMENTS]);
/// let value = Word::new([ONE; Word::NUM_ELEMENTS]);
/// let new_root = forest.insert(empty_tree_root, key, value).unwrap();
///
/// // Insert multiple key-value pairs
/// let mut entries = Vec::new();
/// for i in 0..MAX_LEAF_ENTRIES {
///     let key = Word::new([Felt::new_unchecked(i as u64); Word::NUM_ELEMENTS]);
///     let value = Word::new([Felt::new_unchecked((i + 1) as u64); Word::NUM_ELEMENTS]);
///     entries.push((key, value));
/// }
/// let new_root = forest.batch_insert(new_root, entries.into_iter()).unwrap();
///
/// // Open a proof for the inserted key
/// let proof = forest.open(new_root, key).unwrap();
///
/// // Prune SMTs to release memory used by their nodes and leaves
/// forest.pop_smts(vec![new_root]);
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SmtForest {
    /// Roots of all SMTs in this forest. Any time an SMT in this forest is updated, we add a new
    /// root to this set.
    roots: BTreeSet<Word>,

    /// Stores Merkle paths for all SMTs in this forest.
    store: SmtStore,

    /// Leaves of all SMTs stored in this forest
    leaves: Map<Word, SmtLeaf>,
}

impl Default for SmtForest {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtForest {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an empty `SmtForest` instance.
    pub fn new() -> SmtForest {
        let roots = BTreeSet::new();
        let store = SmtStore::new();
        let leaves = Map::new();

        SmtForest { roots, store, leaves }
    }

    // DATA EXTRACTORS
    // --------------------------------------------------------------------------------------------

    /// Returns an opening for the specified key in the SMT with the specified root.
    ///
    /// Returns an error if an SMT with this root is not in the forest, or if the forest does
    /// not have sufficient data to provide an opening for the specified key.
    pub fn open(&self, root: Word, key: Word) -> Result<SmtProof, MerkleError> {
        if !self.contains_root(root) {
            return Err(MerkleError::RootNotInStore(root));
        }

        let leaf_index = NodeIndex::from(LeafIndex::from(key));

        let proof = self.store.get_path(root, leaf_index)?;
        let path = proof.path.try_into()?;
        let leaf_hash = proof.value;
        let leaf = if leaf_hash == crate::EMPTY_WORD {
            SmtLeaf::new_empty(LeafIndex::from(key))
        } else {
            let Some(leaf) = self.leaves.get(&leaf_hash).cloned() else {
                return Err(MerkleError::UntrackedKey(key));
            };
            leaf
        };

        SmtProof::new(path, leaf).map_err(|error| match error {
            SmtProofError::InvalidMerklePathLength(depth) => MerkleError::InvalidPathLength(depth),
            // These variants are only returned by verification methods, not by SmtProof::new()
            SmtProofError::InvalidKeyForProof
            | SmtProofError::ValueMismatch { .. }
            | SmtProofError::ConflictingRoots { .. }
            | SmtProofError::ValuePresent { .. } => unreachable!(),
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts the specified key-value pair into an SMT with the specified root. This will also
    /// add a new root to the forest. Returns the new root.
    ///
    /// Returns an error if an SMT with the specified root is not in the forest, there is not
    /// enough data in the forest to perform the insert, or if the insert would create a leaf
    /// with too many entries.
    pub fn insert(&mut self, root: Word, key: Word, value: Word) -> Result<Word, MerkleError> {
        self.batch_insert(root, vec![(key, value)])
    }

    /// Inserts the specified key-value pairs into an SMT with the specified root. This will also
    /// add a single new root to the forest for the entire batch of inserts. Returns the new root.
    ///
    /// Returns an error if an SMT with the specified root is not in the forest, there is not
    /// enough data in the forest to perform the insert, or if the insert would create a leaf
    /// with too many entries.
    pub fn batch_insert(
        &mut self,
        root: Word,
        entries: impl IntoIterator<Item = (Word, Word)> + Clone,
    ) -> Result<Word, MerkleError> {
        if !self.contains_root(root) {
            return Err(MerkleError::RootNotInStore(root));
        }

        // Find all affected leaf indices
        let indices = entries
            .clone()
            .into_iter()
            .map(|(key, _)| LeafIndex::from(key))
            .collect::<BTreeSet<_>>();

        // Create new SmtLeaf objects for updated key-value pairs
        let mut new_leaves = Map::new();
        for index in indices {
            let node_index = NodeIndex::from(index);
            let current_hash = self.store.get_node(root, node_index)?;

            let current_leaf = self
                .leaves
                .get(&current_hash)
                .cloned()
                .unwrap_or_else(|| SmtLeaf::new_empty(index));

            new_leaves.insert(index, (current_hash, current_leaf));
        }
        for (key, value) in entries {
            let index = LeafIndex::from(key);
            let (_old_hash, leaf) = new_leaves.get_mut(&index).unwrap();
            if value == crate::EMPTY_WORD {
                let _ = leaf.remove(key);
            } else {
                leaf.insert(key, value).map_err(|err| to_merkle_error(&err))?;
            }
        }

        // Calculate new leaf hashes, skip processing unchanged leaves
        new_leaves = new_leaves
            .into_iter()
            .filter_map(|(key, (old_hash, leaf))| {
                let new_hash = leaf.hash();
                if new_hash == old_hash {
                    None
                } else {
                    Some((key, (new_hash, leaf)))
                }
            })
            .collect();

        // Update SmtStore with new leaf hashes
        let new_leaf_entries =
            new_leaves.iter().map(|(index, leaf)| (NodeIndex::from(*index), leaf.0));
        let new_root = self.store.set_leaves(root, new_leaf_entries)?;

        // Update successful, insert new leaves into the forest
        for (leaf_hash, leaf) in new_leaves.into_values() {
            if leaf_hash != crate::EMPTY_WORD {
                self.leaves.insert(leaf_hash, leaf);
            }
        }
        // Never register the empty tree root in self.roots, as it is always implicitly valid
        // and the empty hash nodes are pre-populated infrastructure in the SmtStore.
        // Adding it here would let `pop_smts` walk and destroy those nodes,
        // corrupting the store for all future operations.
        if new_root != *EmptySubtreeRoots::entry(SMT_DEPTH, 0) {
            self.roots.insert(new_root);
        }

        Ok(new_root)
    }

    /// Removes the specified SMTs (identified by their roots) from the forest.
    /// Releases memory used by nodes and leaves that are no longer reachable.
    /// Roots not in the forest and empty trees are ignored.
    pub fn pop_smts(&mut self, roots: impl IntoIterator<Item = Word>) {
        let roots = roots
            .into_iter()
            .filter(|root| {
                // don't use self.contains_root here because we don't remove empty trees
                self.roots.contains(root)
            })
            .collect::<Vec<_>>();

        for root in &roots {
            self.roots.remove(root);
        }

        for leaf in self.store.remove_roots(roots) {
            self.leaves.remove(&leaf);
        }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Checks if the forest contains the specified root or if it is the empty tree root
    /// (always present in the forest).
    fn contains_root(&self, root: Word) -> bool {
        self.roots.contains(&root) || *EmptySubtreeRoots::entry(SMT_DEPTH, 0) == root
    }
}

fn to_merkle_error(err: &SmtLeafError) -> MerkleError {
    match err {
        SmtLeafError::TooManyLeafEntries { actual } => {
            MerkleError::TooManyLeafEntries { actual: *actual }
        },
        _ => unreachable!("other SmtLeafError variants should not be possible here"),
    }
}
