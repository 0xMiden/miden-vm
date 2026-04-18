use alloc::{boxed::Box, vec::Vec};

use super::{SmtStorage, StorageError, StorageUpdateParts, StorageUpdates, SubtreeUpdate};
use crate::{
    EMPTY_WORD, Map, MapEntry, Word,
    merkle::{
        NodeIndex,
        smt::{
            InnerNode, SmtLeaf,
            large::{IN_MEMORY_DEPTH, subtree::Subtree},
        },
    },
};

/// In-memory storage for a Sparse Merkle Tree (SMT), implementing the `SmtStorage` trait.
///
/// This structure stores the SMT's leaf nodes and subtrees directly in memory.
///
/// It is primarily intended for scenarios where data persistence to disk is not a
/// primary concern. Common use cases include:
/// - Testing environments.
/// - Managing SMT instances with a limited operational lifecycle.
/// - Situations where a higher-level application architecture handles its own data persistence
///   strategy.
#[derive(Debug, Clone)]
pub struct MemoryStorage {
    pub leaves: Map<u64, SmtLeaf>,
    pub subtrees: Map<NodeIndex, Subtree>,
}

impl MemoryStorage {
    /// Creates a new, empty in-memory storage for a Sparse Merkle Tree.
    ///
    /// Initializes empty maps for leaves and subtrees.
    pub fn new() -> Self {
        Self { leaves: Map::new(), subtrees: Map::new() }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtStorage for MemoryStorage {
    /// Gets the total number of non-empty leaves currently stored.
    fn leaf_count(&self) -> Result<usize, StorageError> {
        Ok(self.leaves.len())
    }

    /// Gets the total number of key-value entries currently stored.
    fn entry_count(&self) -> Result<usize, StorageError> {
        Ok(self.leaves.values().map(SmtLeaf::num_entries).sum())
    }

    /// Inserts a key-value pair into the leaf at the given index.
    ///
    /// - If the leaf at `index` does not exist, a new `SmtLeaf::Single` is created.
    /// - If the leaf exists, the key-value pair is inserted into it.
    /// - Returns the previous value associated with the key, if any.
    ///
    /// # Panics
    /// Panics in debug builds if `value` is `EMPTY_WORD`.
    fn insert_value(
        &mut self,
        index: u64,
        key: Word,
        value: Word,
    ) -> Result<Option<Word>, StorageError> {
        debug_assert_ne!(value, EMPTY_WORD);

        match self.leaves.get_mut(&index) {
            Some(leaf) => Ok(leaf.insert(key, value)?),
            None => {
                self.leaves.insert(index, SmtLeaf::Single((key, value)));
                Ok(None)
            },
        }
    }

    /// Removes a key-value pair from the leaf at the given `index`.
    ///
    /// - If the leaf at `index` exists and the `key` is found within that leaf, the key-value pair
    ///   is removed, and the old `Word` value is returned in `Ok(Some(Word))`.
    /// - If the leaf at `index` exists but the `key` is not found within that leaf, `Ok(None)` is
    ///   returned (as `leaf.get_value(&key)` would be `None`).
    /// - If the leaf at `index` does not exist, `Ok(None)` is returned, as no value could be
    ///   removed.
    fn remove_value(&mut self, index: u64, key: Word) -> Result<Option<Word>, StorageError> {
        let old_value = match self.leaves.entry(index) {
            MapEntry::Occupied(mut entry) => {
                let (old_value, is_empty) = entry.get_mut().remove(key);
                if is_empty {
                    entry.remove();
                }
                old_value
            },
            // Leaf at index does not exist, so no value could be removed.
            MapEntry::Vacant(_) => None,
        };
        Ok(old_value)
    }

    /// Retrieves a single leaf node.
    fn get_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        Ok(self.leaves.get(&index).cloned())
    }

    /// Sets multiple leaf nodes in storage.
    ///
    /// If a leaf at a given index already exists, it is overwritten.
    fn set_leaves(&mut self, leaves_map: Map<u64, SmtLeaf>) -> Result<(), StorageError> {
        self.leaves.extend(leaves_map);
        Ok(())
    }

    /// Removes a single leaf node.
    fn remove_leaf(&mut self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        Ok(self.leaves.remove(&index))
    }

    /// Retrieves multiple leaf nodes. Returns Ok(None) for indices not found.
    fn get_leaves(&self, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>, StorageError> {
        let leaves = indices.iter().map(|idx| self.leaves.get(idx).cloned()).collect();
        Ok(leaves)
    }

    /// Returns true if the storage has any leaves.
    fn has_leaves(&self) -> Result<bool, StorageError> {
        Ok(!self.leaves.is_empty())
    }

    /// Retrieves a single Subtree (representing deep nodes) by its root NodeIndex.
    /// Assumes index.depth() >= IN_MEMORY_DEPTH. Returns Ok(None) if not found.
    fn get_subtree(&self, index: NodeIndex) -> Result<Option<Subtree>, StorageError> {
        Ok(self.subtrees.get(&index).cloned())
    }

    /// Retrieves multiple Subtrees.
    /// Assumes index.depth() >= IN_MEMORY_DEPTH for all indices. Returns Ok(None) for indices not
    /// found.
    fn get_subtrees(&self, indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>, StorageError> {
        let subtrees: Vec<_> = indices.iter().map(|idx| self.subtrees.get(idx).cloned()).collect();
        Ok(subtrees)
    }

    /// Sets a single Subtree (representing deep nodes) by its root NodeIndex.
    ///
    /// If a subtree with the same root NodeIndex already exists, it is overwritten.
    /// Assumes `subtree.root_index().depth() >= IN_MEMORY_DEPTH`.
    fn set_subtree(&mut self, subtree: &Subtree) -> Result<(), StorageError> {
        self.subtrees.insert(subtree.root_index(), subtree.clone());
        Ok(())
    }

    /// Sets multiple Subtrees (representing deep nodes) by their root NodeIndex.
    ///
    /// If a subtree with a given root NodeIndex already exists, it is overwritten.
    /// Assumes `subtree.root_index().depth() >= IN_MEMORY_DEPTH` for all subtrees in the vector.
    fn set_subtrees(&mut self, subtrees_vec: Vec<Subtree>) -> Result<(), StorageError> {
        self.subtrees
            .extend(subtrees_vec.into_iter().map(|subtree| (subtree.root_index(), subtree)));
        Ok(())
    }

    /// Removes a single Subtree (representing deep nodes) by its root NodeIndex.
    fn remove_subtree(&mut self, index: NodeIndex) -> Result<(), StorageError> {
        self.subtrees.remove(&index);
        Ok(())
    }

    /// Retrieves a single inner node from a Subtree.
    ///
    /// This function is intended for accessing nodes within a Subtree, meaning
    /// `index.depth()` must be greater than or equal to `IN_MEMORY_DEPTH`.
    ///
    /// # Errors
    /// - `StorageError::Unsupported`: If `index.depth() < IN_MEMORY_DEPTH`.
    ///
    /// Returns `Ok(None)` if the subtree or the specific inner node within it is not found.
    fn get_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() < IN_MEMORY_DEPTH {
            return Err(StorageError::Unsupported(
                "Cannot get inner node from upper part of the tree".into(),
            ));
        }
        let subtree_root_index = Subtree::find_subtree_root(index);
        Ok(self
            .subtrees
            .get(&subtree_root_index)
            .and_then(|subtree| subtree.get_inner_node(index)))
    }

    /// Sets a single inner node within a Subtree.
    ///
    /// - `index.depth()` must be greater than or equal to `IN_MEMORY_DEPTH`.
    /// - If the target Subtree does not exist, it is created.
    /// - The `node` is then inserted into the Subtree.
    ///
    /// Returns the `InnerNode` that was previously at this `index`, if any.
    ///
    /// # Errors
    /// - `StorageError::Unsupported`: If `index.depth() < IN_MEMORY_DEPTH`.
    fn set_inner_node(
        &mut self,
        index: NodeIndex,
        node: InnerNode,
    ) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() < IN_MEMORY_DEPTH {
            return Err(StorageError::Unsupported(
                "Cannot set inner node in upper part of the tree".into(),
            ));
        }
        let subtree_root_index = Subtree::find_subtree_root(index);
        let mut subtree = self
            .subtrees
            .remove(&subtree_root_index)
            .unwrap_or_else(|| Subtree::new(subtree_root_index));
        let old_node = subtree.insert_inner_node(index, node);
        self.subtrees.insert(subtree_root_index, subtree);
        Ok(old_node)
    }

    /// Removes a single inner node from a Subtree.
    ///
    /// - `index.depth()` must be greater than or equal to `IN_MEMORY_DEPTH`.
    /// - If the Subtree becomes empty after removing the node, the Subtree itself is removed from
    ///   storage.
    ///
    /// Returns the `InnerNode` that was removed, if any.
    ///
    /// # Errors
    /// - `StorageError::Unsupported`: If `index.depth() < IN_MEMORY_DEPTH`.
    fn remove_inner_node(&mut self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() < IN_MEMORY_DEPTH {
            return Err(StorageError::Unsupported(
                "Cannot remove inner node from upper part of the tree".into(),
            ));
        }
        let subtree_root_index = Subtree::find_subtree_root(index);

        let inner_node: Option<InnerNode> =
            self.subtrees.remove(&subtree_root_index).and_then(|mut subtree| {
                let old_node = subtree.remove_inner_node(index);
                if !subtree.is_empty() {
                    self.subtrees.insert(subtree_root_index, subtree);
                }
                old_node
            });
        Ok(inner_node)
    }

    /// Applies a set of updates atomically to the storage.
    ///
    /// This method handles updates to:
    /// - Leaves: Inserts new or updated leaves, removes specified leaves.
    /// - Subtrees: Inserts new or updated subtrees, removes specified subtrees.
    fn apply(&mut self, updates: StorageUpdates) -> Result<(), StorageError> {
        let StorageUpdateParts {
            leaf_updates,
            subtree_updates,
            leaf_count_delta: _,
            entry_count_delta: _,
        } = updates.into_parts();

        for (index, leaf_opt) in leaf_updates {
            if let Some(leaf) = leaf_opt {
                self.leaves.insert(index, leaf);
            } else {
                self.leaves.remove(&index);
            }
        }
        for update in subtree_updates {
            match update {
                SubtreeUpdate::Store { index, subtree } => {
                    self.subtrees.insert(index, subtree);
                },
                SubtreeUpdate::Delete { index } => {
                    self.subtrees.remove(&index);
                },
            }
        }
        Ok(())
    }

    /// Returns an iterator over all (index, SmtLeaf) pairs in the storage.
    ///
    /// The iterator provides access to the current state of the leaves.
    fn iter_leaves(&self) -> Result<Box<dyn Iterator<Item = (u64, SmtLeaf)> + '_>, StorageError> {
        Ok(Box::new(self.leaves.iter().map(|(&k, v)| (k, v.clone()))))
    }

    /// Returns an iterator over all Subtrees in the storage.
    ///
    /// The iterator provides access to the current subtrees from storage.
    fn iter_subtrees(&self) -> Result<Box<dyn Iterator<Item = Subtree> + '_>, StorageError> {
        Ok(Box::new(self.subtrees.values().cloned()))
    }

    /// Retrieves all depth 24 roots for fast tree rebuilding.
    ///
    /// For MemoryStorage, this returns an empty vector since all data is already in memory
    /// and there's no startup performance benefit to caching depth 24 roots.
    fn get_depth24(&self) -> Result<Vec<(u64, Word)>, StorageError> {
        Ok(Vec::new())
    }
}
