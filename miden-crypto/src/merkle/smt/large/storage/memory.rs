use alloc::{boxed::Box, vec::Vec};

use super::{
    SmtStorage, SmtStorageReader, StorageError, StorageResult, StorageUpdateParts, StorageUpdates,
    SubtreeUpdate,
};
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

// MEMORY STORAGE
// ================================================================================================

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

    /// Converts this storage into a read-only snapshot.
    pub fn into_snapshot(self) -> MemoryStorageSnapshot {
        MemoryStorageSnapshot(self)
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtStorageReader for MemoryStorage {
    /// Gets the total number of non-empty leaves currently stored.
    fn leaf_count(&self) -> StorageResult<usize> {
        Ok(self.leaves.len())
    }

    /// Gets the total number of key-value entries currently stored.
    fn entry_count(&self) -> StorageResult<usize> {
        Ok(self.leaves.values().map(SmtLeaf::num_entries).sum())
    }

    /// Retrieves a single leaf node.
    fn get_leaf(&self, index: u64) -> StorageResult<Option<SmtLeaf>> {
        Ok(self.leaves.get(&index).cloned())
    }

    /// Retrieves multiple leaf nodes. Returns Ok(None) for indices not found.
    fn get_leaves(&self, indices: &[u64]) -> StorageResult<Vec<Option<SmtLeaf>>> {
        let leaves = indices.iter().map(|idx| self.leaves.get(idx).cloned()).collect();
        Ok(leaves)
    }

    /// Returns true if the storage has any leaves.
    fn has_leaves(&self) -> StorageResult<bool> {
        Ok(!self.leaves.is_empty())
    }

    /// Retrieves a single Subtree (representing deep nodes) by its root NodeIndex.
    /// Assumes index.depth() >= IN_MEMORY_DEPTH. Returns Ok(None) if not found.
    fn get_subtree(&self, index: NodeIndex) -> StorageResult<Option<Subtree>> {
        Ok(self.subtrees.get(&index).cloned())
    }

    /// Retrieves multiple Subtrees.
    /// Assumes index.depth() >= IN_MEMORY_DEPTH for all indices. Returns Ok(None) for indices not
    /// found.
    fn get_subtrees(&self, indices: &[NodeIndex]) -> StorageResult<Vec<Option<Subtree>>> {
        let subtrees: Vec<_> = indices.iter().map(|idx| self.subtrees.get(idx).cloned()).collect();
        Ok(subtrees)
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
    fn get_inner_node(&self, index: NodeIndex) -> StorageResult<Option<InnerNode>> {
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

    /// Returns an iterator over all (index, SmtLeaf) pairs in the storage.
    ///
    /// The iterator provides access to the current state of the leaves.
    fn iter_leaves(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(u64, SmtLeaf)>> + '_>> {
        Ok(Box::new(self.leaves.iter().map(|(&k, v)| Ok((k, v.clone())))))
    }

    /// Returns an iterator over all Subtrees in the storage.
    ///
    /// The iterator provides access to the current subtrees from storage.
    fn iter_subtrees(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<Subtree>> + '_>> {
        Ok(Box::new(self.subtrees.values().cloned().map(Ok)))
    }

    /// Retrieves roots of all subtrees at `IN_MEMORY_DEPTH` depth.
    ///
    /// Derived from the subtrees already in memory: for each subtree whose root sits at
    /// `IN_MEMORY_DEPTH`, the root node's hash is the entry that `initialize_from_storage`
    /// needs to reconstruct the in-memory top of the tree.
    fn get_top_subtree_roots(&self) -> StorageResult<Vec<(u64, Word)>> {
        let in_mem_roots = self
            .subtrees
            .values()
            .filter(|subtree| subtree.root_index().depth() == IN_MEMORY_DEPTH)
            .filter_map(|subtree| {
                subtree
                    .get_inner_node(subtree.root_index())
                    .map(|node| (subtree.root_index().position(), node.hash()))
            })
            .collect();
        Ok(in_mem_roots)
    }
}

impl SmtStorage for MemoryStorage {
    type Reader = MemoryStorageSnapshot;

    /// Returns a read-only snapshot of this in-memory storage by cloning it.
    fn reader(&self) -> StorageResult<Self::Reader> {
        Ok(self.clone().into_snapshot())
    }

    /// Inserts a key-value pair into the leaf at the given index.
    ///
    /// - If the leaf at `index` does not exist, a new `SmtLeaf::Single` is created.
    /// - If the leaf exists, the key-value pair is inserted into it.
    /// - Returns the previous value associated with the key, if any.
    ///
    /// # Panics
    /// Panics in debug builds if `value` is `EMPTY_WORD`.
    fn insert_value(&mut self, index: u64, key: Word, value: Word) -> StorageResult<Option<Word>> {
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
    fn remove_value(&mut self, index: u64, key: Word) -> StorageResult<Option<Word>> {
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

    /// Sets multiple leaf nodes in storage.
    ///
    /// If a leaf at a given index already exists, it is overwritten.
    fn set_leaves(&mut self, leaves_map: Map<u64, SmtLeaf>) -> StorageResult<()> {
        self.leaves.extend(leaves_map);
        Ok(())
    }

    /// Removes a single leaf node.
    fn remove_leaf(&mut self, index: u64) -> StorageResult<Option<SmtLeaf>> {
        Ok(self.leaves.remove(&index))
    }

    /// Sets a single Subtree (representing deep nodes) by its root NodeIndex.
    ///
    /// If a subtree with the same root NodeIndex already exists, it is overwritten.
    /// Assumes `subtree.root_index().depth() >= IN_MEMORY_DEPTH`.
    fn set_subtree(&mut self, subtree: &Subtree) -> StorageResult<()> {
        self.subtrees.insert(subtree.root_index(), subtree.clone());
        Ok(())
    }

    /// Sets multiple Subtrees (representing deep nodes) by their root NodeIndex.
    ///
    /// If a subtree with a given root NodeIndex already exists, it is overwritten.
    /// Assumes `subtree.root_index().depth() >= IN_MEMORY_DEPTH` for all subtrees in the vector.
    fn set_subtrees(&mut self, subtrees_vec: Vec<Subtree>) -> StorageResult<()> {
        self.subtrees
            .extend(subtrees_vec.into_iter().map(|subtree| (subtree.root_index(), subtree)));
        Ok(())
    }

    /// Removes a single Subtree (representing deep nodes) by its root NodeIndex.
    fn remove_subtree(&mut self, index: NodeIndex) -> StorageResult<()> {
        self.subtrees.remove(&index);
        Ok(())
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
    ) -> StorageResult<Option<InnerNode>> {
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
    fn remove_inner_node(&mut self, index: NodeIndex) -> StorageResult<Option<InnerNode>> {
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
    fn apply(&mut self, updates: StorageUpdates) -> StorageResult<()> {
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
}

// MEMORY STORAGE SNAPSHOT
// ================================================================================================

/// Read-only snapshot of SMT storage data.
///
/// This type intentionally implements [`SmtStorageReader`] only. It is used as the reader view for
/// storage backends that need to hand out a detached point-in-time copy without also exposing
/// mutation methods through [`SmtStorage`].
#[derive(Debug, Clone)]
pub struct MemoryStorageSnapshot(MemoryStorage);

impl SmtStorageReader for MemoryStorageSnapshot {
    fn leaf_count(&self) -> StorageResult<usize> {
        self.0.leaf_count()
    }

    fn entry_count(&self) -> StorageResult<usize> {
        self.0.entry_count()
    }

    fn get_leaf(&self, index: u64) -> StorageResult<Option<SmtLeaf>> {
        self.0.get_leaf(index)
    }

    fn get_leaves(&self, indices: &[u64]) -> StorageResult<Vec<Option<SmtLeaf>>> {
        self.0.get_leaves(indices)
    }

    fn has_leaves(&self) -> StorageResult<bool> {
        self.0.has_leaves()
    }

    fn get_subtree(&self, index: NodeIndex) -> StorageResult<Option<Subtree>> {
        self.0.get_subtree(index)
    }

    fn get_subtrees(&self, indices: &[NodeIndex]) -> StorageResult<Vec<Option<Subtree>>> {
        self.0.get_subtrees(indices)
    }

    fn get_leaf_and_subtrees(
        &self,
        leaf_index: u64,
        subtree_indices: &[NodeIndex],
    ) -> StorageResult<(Option<SmtLeaf>, Vec<Option<Subtree>>)> {
        self.0.get_leaf_and_subtrees(leaf_index, subtree_indices)
    }

    fn get_inner_node(&self, index: NodeIndex) -> StorageResult<Option<InnerNode>> {
        self.0.get_inner_node(index)
    }

    fn iter_leaves(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(u64, SmtLeaf)>> + '_>> {
        self.0.iter_leaves()
    }

    fn iter_subtrees(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<Subtree>> + '_>> {
        self.0.iter_subtrees()
    }

    fn get_top_subtree_roots(&self) -> StorageResult<Vec<(u64, Word)>> {
        self.0.get_top_subtree_roots()
    }
}
