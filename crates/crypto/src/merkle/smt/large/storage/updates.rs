use alloc::vec::Vec;

use crate::merkle::{
    NodeIndex,
    smt::{Map, SmtLeaf, large::subtree::Subtree},
};

/// Represents a storage update operation for a subtree.
///
/// Each variant explicitly indicates whether to store or delete a subtree at a given index.
#[derive(Debug, Clone)]
pub enum SubtreeUpdate {
    /// Store or update a subtree at the specified index.
    Store {
        /// The index where the subtree should be stored.
        index: NodeIndex,
        /// The subtree data to store.
        subtree: Subtree,
    },
    /// Delete the subtree at the specified index.
    Delete {
        /// The index of the subtree to delete.
        index: NodeIndex,
    },
}

/// Owned decomposition of a [`StorageUpdates`] batch into its constituent parts.
///
/// This struct provides direct access to the individual components of a storage update
/// batch after transferring ownership from [`StorageUpdates::into_parts`].
#[derive(Debug)]
pub struct StorageUpdateParts {
    /// Leaf updates indexed by their position in the tree.
    ///
    /// `Some(leaf)` indicates an insertion or update, while `None` indicates deletion.
    pub leaf_updates: Map<u64, Option<SmtLeaf>>,

    /// Vector of subtree storage operations (Store or Delete) to be applied atomically.
    pub subtree_updates: Vec<SubtreeUpdate>,

    /// Net change in the count of non-empty leaves.
    ///
    /// Positive values indicate more leaves were added than removed,
    /// negative values indicate more leaves were removed than added.
    pub leaf_count_delta: isize,

    /// Net change in the total number of key-value entries across all leaves.
    ///
    /// Positive values indicate more entries were added than removed,
    /// negative values indicate more entries were removed than added.
    pub entry_count_delta: isize,
}

/// Represents a collection of changes to be applied atomically to an SMT storage backend.
///
/// This struct is used to batch multiple updates (to leaves and subtrees)
/// ensuring that they are persisted together as a single, consistent transaction.
/// It also tracks deltas for leaf and entry counts, allowing storage implementations
/// to maintain these counts accurately.
#[derive(Default, Debug, Clone)]
pub struct StorageUpdates {
    /// A map of updates to individual SMT leaves.
    /// The key is the logical leaf index (u64).
    /// - `Some(SmtLeaf)` indicates an insertion or update of the leaf at that index.
    /// - `None` indicates a deletion of the leaf at that index.
    leaf_updates: Map<u64, Option<SmtLeaf>>,

    /// Vector of subtree storage operations (Store or Delete) to be applied atomically.
    subtree_updates: Vec<SubtreeUpdate>,

    /// The net change in the total count of non-empty leaves resulting from this batch of updates.
    /// For example, if one leaf is added and one is removed, this would be 0.
    /// If two new leaves are added, this would be +2.
    leaf_count_delta: isize,

    /// The net change in the total count of key-value entries across all leaves
    /// resulting from this batch of updates.
    entry_count_delta: isize,
}

impl StorageUpdates {
    /// Creates a new `StorageUpdates` with default empty updates.
    ///
    /// This constructor is ideal for incremental building where you'll add updates
    /// one by one using the convenience methods like `insert_leaf()` and `insert_subtree()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new `StorageUpdates` from pre-computed components.
    ///
    /// This constructor is ideal for bulk operations where you already have
    /// the complete maps of updates and calculated deltas, such as when applying
    /// a batch of mutations.
    pub fn from_parts(
        leaf_updates: Map<u64, Option<SmtLeaf>>,
        subtree_updates: impl IntoIterator<Item = SubtreeUpdate>,
        leaf_count_delta: isize,
        entry_count_delta: isize,
    ) -> Self {
        Self {
            leaf_updates,
            subtree_updates: subtree_updates.into_iter().collect(),
            leaf_count_delta,
            entry_count_delta,
        }
    }

    /// Adds a leaf insertion/update to the batch.
    ///
    /// If a leaf at the same index was previously added to this batch, it will be replaced.
    pub fn insert_leaf(&mut self, index: u64, leaf: SmtLeaf) {
        self.leaf_updates.insert(index, Some(leaf));
    }

    /// Adds a leaf removal to the batch.
    ///
    /// If a leaf at the same index was previously added to this batch, it will be replaced.
    pub fn remove_leaf(&mut self, index: u64) {
        self.leaf_updates.insert(index, None);
    }

    /// Adds a subtree insertion/update to the batch.
    ///
    /// **Note:** This method does not deduplicate. If you call this multiple times with the
    /// same subtree index, multiple update operations will be added to the batch. The storage
    /// implementation will apply them in order, with the last one taking effect.
    pub fn insert_subtree(&mut self, subtree: Subtree) {
        let index = subtree.root_index();
        self.subtree_updates.push(SubtreeUpdate::Store { index, subtree });
    }

    /// Adds a subtree removal to the batch.
    ///
    /// **Note:** This method does not deduplicate. If you call this multiple times with the
    /// same subtree index, multiple delete operations will be added to the batch. The storage
    /// implementation will apply them in order, with the last one taking effect.
    pub fn remove_subtree(&mut self, index: NodeIndex) {
        self.subtree_updates.push(SubtreeUpdate::Delete { index });
    }

    /// Returns true if this update batch contains no changes.
    pub fn is_empty(&self) -> bool {
        self.leaf_updates.is_empty() && self.subtree_updates.is_empty()
    }

    /// Returns the number of leaf updates in this batch.
    pub fn leaf_update_count(&self) -> usize {
        self.leaf_updates.len()
    }

    /// Returns the number of subtree updates in this batch.
    pub fn subtree_update_count(&self) -> usize {
        self.subtree_updates.len()
    }

    /// Returns a reference to the leaf updates map.
    pub fn leaf_updates(&self) -> &Map<u64, Option<SmtLeaf>> {
        &self.leaf_updates
    }

    /// Returns a reference to the subtree updates vector.
    pub fn subtree_updates(&self) -> &[SubtreeUpdate] {
        &self.subtree_updates
    }

    /// Returns the leaf count delta.
    pub fn leaf_count_delta(&self) -> isize {
        self.leaf_count_delta
    }

    /// Returns the entry count delta.
    pub fn entry_count_delta(&self) -> isize {
        self.entry_count_delta
    }

    /// Sets the leaf count delta.
    pub fn set_leaf_count_delta(&mut self, delta: isize) {
        self.leaf_count_delta = delta;
    }

    /// Sets the entry count delta.
    pub fn set_entry_count_delta(&mut self, delta: isize) {
        self.entry_count_delta = delta;
    }

    /// Adjusts the leaf count delta by the specified amount.
    pub fn adjust_leaf_count_delta(&mut self, adjustment: isize) {
        self.leaf_count_delta += adjustment;
    }

    /// Adjusts the entry count delta by the specified amount.
    pub fn adjust_entry_count_delta(&mut self, adjustment: isize) {
        self.entry_count_delta += adjustment;
    }

    /// Consumes this StorageUpdates and returns the leaf updates map.
    pub fn into_leaf_updates(self) -> Map<u64, Option<SmtLeaf>> {
        self.leaf_updates
    }

    /// Consumes this StorageUpdates and returns the subtree updates vector.
    pub fn into_subtree_updates(self) -> Vec<SubtreeUpdate> {
        self.subtree_updates
    }

    /// Consumes this `StorageUpdates` and returns its owned parts as a [`StorageUpdateParts`].
    pub fn into_parts(self) -> StorageUpdateParts {
        StorageUpdateParts {
            leaf_updates: self.leaf_updates,
            subtree_updates: self.subtree_updates,
            leaf_count_delta: self.leaf_count_delta,
            entry_count_delta: self.entry_count_delta,
        }
    }
}
