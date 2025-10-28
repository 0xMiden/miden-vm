use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{DecoratorId, MastNodeId};
use crate::{Idx, IndexVec};

/// A CSR (Compressed Sparse Row) representation for storing node-level decorators (before_enter and
/// after_exit).
///
/// This structure provides efficient storage for before_enter and after_exit decorators across all
/// nodes in a MastForest, using a similar CSR pattern to DecoratorIndexMapping but for node-level
/// decorators.
///
/// The data layout follows CSR format:
/// - `before_enter_decorators`: Flat storage of all before_enter DecoratorId values
/// - `after_exit_decorators`: Flat storage of all after_exit DecoratorId values
/// - `node_indptr_for_before`: Pointer indices for nodes within before_enter_decorators
/// - `node_indptr_for_after`: Pointer indices for nodes within after_exit_decorators
///
/// For node i, its before_enter decorators are at:
/// before_enter_decorators[node_indptr_for_before[i]..node_indptr_for_before[i+1]]
/// And its after_exit decorators are at:
/// after_exit_decorators[node_indptr_for_after[i]..node_indptr_for_after[i+1]]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NodeDecoratorStorage {
    /// All `before_enter` decorators, concatenated across all nodes.
    pub before_enter_decorators: Vec<DecoratorId>,
    /// All `after_exit` decorators, concatenated across all nodes.
    pub after_exit_decorators: Vec<DecoratorId>,
    /// Index pointers for before_enter decorators: the range for node i is
    /// node_indptr_for_before[i]..node_indptr_for_before[i+1]
    pub node_indptr_for_before: IndexVec<MastNodeId, usize>,
    /// Index pointers for after_exit decorators: the range for node i is
    /// node_indptr_for_after[i]..node_indptr_for_after[i+1]
    pub node_indptr_for_after: IndexVec<MastNodeId, usize>,
}

impl NodeDecoratorStorage {
    /// Creates a new empty `NodeDecoratorStorage`.
    pub fn new() -> Self {
        Self {
            before_enter_decorators: Vec::new(),
            after_exit_decorators: Vec::new(),
            node_indptr_for_before: IndexVec::new(),
            node_indptr_for_after: IndexVec::new(),
        }
    }

    /// Creates a new empty `NodeDecoratorStorage` with specified capacity.
    pub fn with_capacity(
        nodes_capacity: usize,
        before_decorators_capacity: usize,
        after_decorators_capacity: usize,
    ) -> Self {
        Self {
            before_enter_decorators: Vec::with_capacity(before_decorators_capacity),
            after_exit_decorators: Vec::with_capacity(after_decorators_capacity),
            node_indptr_for_before: IndexVec::with_capacity(nodes_capacity + 1),
            node_indptr_for_after: IndexVec::with_capacity(nodes_capacity + 1),
        }
    }

    /// Adds decorators for a node to the centralized storage using CSR pattern.
    ///
    /// # Arguments
    /// * `node_id` - The ID of the node to add decorators for
    /// * `before` - Slice of before_enter decorators for this node
    /// * `after` - Slice of after_exit decorators for this node
    pub fn add_node_decorators(
        &mut self,
        node_id: MastNodeId,
        before: &[DecoratorId],
        after: &[DecoratorId],
    ) {
        // Ensure the IndexVec can accommodate this node_id + 1 for the sentinel pointer
        while self.node_indptr_for_before.len() <= node_id.to_usize() {
            let current_len = self.before_enter_decorators.len();
            let _ = self.node_indptr_for_before.push(current_len);

            let current_len = self.after_exit_decorators.len();
            let _ = self.node_indptr_for_after.push(current_len);
        }

        // Handle before_enter decorators using CSR pattern
        if self.node_indptr_for_before.is_empty() {
            // First node: just set the start pointer
            self.node_indptr_for_before[MastNodeId::new_unchecked(0)] = 0;
        } else if node_id.to_usize() > 0 {
            // Overwrite the previous end pointer to become this node's start pointer
            let prev_node = MastNodeId::new_unchecked((node_id.to_usize() - 1) as u32);
            self.node_indptr_for_before[prev_node] = self.before_enter_decorators.len();
        }

        // Add before_enter decorators
        let _before_start = self.before_enter_decorators.len();
        self.before_enter_decorators.extend_from_slice(before);
        let before_end = self.before_enter_decorators.len();

        // Push new end pointer for this node
        if self.node_indptr_for_before.len() > node_id.to_usize() {
            self.node_indptr_for_before[node_id] = before_end;
        } else {
            let _ = self.node_indptr_for_before.push(before_end);
        }

        // Handle after_exit decorators using CSR pattern
        if self.node_indptr_for_after.is_empty() {
            // First node: just set the start pointer
            self.node_indptr_for_after[MastNodeId::new_unchecked(0)] = 0;
        } else if node_id.to_usize() > 0 {
            // Overwrite the previous end pointer to become this node's start pointer
            let prev_node = MastNodeId::new_unchecked((node_id.to_usize() - 1) as u32);
            self.node_indptr_for_after[prev_node] = self.after_exit_decorators.len();
        }

        // Add after_exit decorators
        let _after_start = self.after_exit_decorators.len();
        self.after_exit_decorators.extend_from_slice(after);
        let after_end = self.after_exit_decorators.len();

        // Push new end pointer for this node
        if self.node_indptr_for_after.len() > node_id.to_usize() {
            self.node_indptr_for_after[node_id] = after_end;
        } else {
            let _ = self.node_indptr_for_after.push(after_end);
        }
    }

    /// Gets the before_enter decorators for a given node.
    pub fn get_before_decorators(&self, node_id: MastNodeId) -> &[DecoratorId] {
        let node_idx = node_id.to_usize();

        // Check if we have pointers for this node
        if node_idx + 1 >= self.node_indptr_for_before.len() {
            return &[];
        }

        let start = self.node_indptr_for_before[node_id];
        let end = self.node_indptr_for_before[MastNodeId::new_unchecked((node_idx + 1) as u32)];

        if start > end || end > self.before_enter_decorators.len() {
            return &[];
        }

        &self.before_enter_decorators[start..end]
    }

    /// Gets the after_exit decorators for a given node.
    pub fn get_after_decorators(&self, node_id: MastNodeId) -> &[DecoratorId] {
        let node_idx = node_id.to_usize();

        // Check if we have pointers for this node
        if node_idx + 1 >= self.node_indptr_for_after.len() {
            return &[];
        }

        let start = self.node_indptr_for_after[node_id];
        let end = self.node_indptr_for_after[MastNodeId::new_unchecked((node_idx + 1) as u32)];

        if start > end || end > self.after_exit_decorators.len() {
            return &[];
        }

        &self.after_exit_decorators[start..end]
    }

    /// Finalizes the storage by ensuring sentinel pointers are properly set.
    /// This should be called after all nodes have been added.
    pub fn finalize(&mut self) {
        // Ensure sentinel pointers exist for all nodes
        let max_len = self.node_indptr_for_before.len().max(self.node_indptr_for_after.len());

        // Add final sentinel pointers if needed
        if self.node_indptr_for_before.len() == max_len {
            let _ = self.node_indptr_for_before.push(self.before_enter_decorators.len());
        }
        if self.node_indptr_for_after.len() == max_len {
            let _ = self.node_indptr_for_after.push(self.after_exit_decorators.len());
        }
    }

    /// Removes all decorators for a given node.
    ///
    /// # Arguments
    /// * `_node_id` - The ID of the node to remove decorators for
    ///
    /// Note: This operation is not supported in the CSR structure as it would require
    /// shifting all subsequent data. This method is a no-op.
    pub fn remove_decorators(&mut self, _node_id: MastNodeId) {
        // For CSR structure, removing individual node decorators is not supported
        // as it would require shifting all subsequent data. This is a no-op.
    }

    /// Clears all decorators and mappings.
    pub fn clear(&mut self) {
        self.before_enter_decorators.clear();
        self.after_exit_decorators.clear();
        self.node_indptr_for_before = IndexVec::new();
        self.node_indptr_for_after = IndexVec::new();
    }

    /// Returns the number of nodes in this storage.
    pub fn len(&self) -> usize {
        self.node_indptr_for_before.len().saturating_sub(1)
    }

    /// Returns true if this storage is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for NodeDecoratorStorage {
    fn default() -> Self {
        Self::new()
    }
}
