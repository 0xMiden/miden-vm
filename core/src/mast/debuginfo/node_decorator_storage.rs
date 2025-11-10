use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    Idx, IndexVec,
    mast::{DecoratorId, MastNodeId},
};

/// A CSR (Compressed Sparse Row) representation for storing node-level decorators (before_enter and
/// after_exit).
///
/// This structure provides efficient storage for before_enter and after_exit decorators across all
/// nodes in a MastForest, using a similar CSR pattern to OpToDecoratorIds but for node-level
/// decorators.
///
/// The data layout follows CSR format:
/// - `before_enter_decorators`: Flat storage of all before_enter DecoratorId values
/// - `after_exit_decorators`: Flat storage of all after_exit DecoratorId values
/// - `node_indptr_for_before`: Pointer indices for nodes within before_enter_decorators
/// - `node_indptr_for_after`: Pointer indices for nodes within after_exit_decorators
///
/// For node `i`, its before_enter decorators are at:
/// ```text
/// before_enter_decorators[node_indptr_for_before[i]..node_indptr_for_before[i+1]]
/// ```
/// And its after_exit decorators are at:
/// ```text
/// after_exit_decorators[node_indptr_for_after[i]..node_indptr_for_after[i+1]]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NodeToDecoratorIds {
    /// All `before_enter` decorators, concatenated across all nodes.
    pub before_enter_decorators: Vec<DecoratorId>,
    /// All `after_exit` decorators, concatenated across all nodes.
    pub after_exit_decorators: Vec<DecoratorId>,
    /// Index pointers for before_enter decorators: the range for node `i` is
    /// ```text
    /// node_indptr_for_before[i]..node_indptr_for_before[i+1]
    /// ```
    pub node_indptr_for_before: IndexVec<MastNodeId, usize>,
    /// Index pointers for after_exit decorators: the range for node `i` is
    /// ```text
    /// node_indptr_for_after[i]..node_indptr_for_after[i+1]
    /// ```
    pub node_indptr_for_after: IndexVec<MastNodeId, usize>,
}

impl NodeToDecoratorIds {
    /// Creates a new empty `NodeToDecoratorIds`.
    pub fn new() -> Self {
        Self {
            before_enter_decorators: Vec::new(),
            after_exit_decorators: Vec::new(),
            node_indptr_for_before: IndexVec::new(),
            node_indptr_for_after: IndexVec::new(),
        }
    }

    /// Creates a new empty `NodeToDecoratorIds` with specified capacity.
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
        // For CSR, we need to ensure there's always a sentinel pointer at node_id + 1
        let required_len = node_id.to_usize() + 2; // +1 for the node itself, +1 for sentinel
        while self.node_indptr_for_before.len() < required_len {
            self.node_indptr_for_before
                .push(self.before_enter_decorators.len())
                .expect("node_indptr_for_before capacity exceeded: MAST forest has too many nodes");
            self.node_indptr_for_after
                .push(self.after_exit_decorators.len())
                .expect("node_indptr_for_after capacity exceeded: MAST forest has too many nodes");
        }

        // Get the start position for this node's decorators
        let start_pos = self.before_enter_decorators.len();

        // Add before_enter decorators
        self.before_enter_decorators.extend_from_slice(before);
        let before_end = self.before_enter_decorators.len();

        // Update the start pointer for this node (overwrite existing)
        self.node_indptr_for_before[node_id] = start_pos;

        // Update the end pointer (which is the start for the next node)
        self.node_indptr_for_before[MastNodeId::new_unchecked((node_id.to_usize() + 1) as u32)] =
            before_end;

        // Get the start position for this node's after_exit decorators
        let after_start_pos = self.after_exit_decorators.len();

        // Add after_exit decorators
        self.after_exit_decorators.extend_from_slice(after);
        let after_end = self.after_exit_decorators.len();

        // Update the start pointer for this node (overwrite existing)
        self.node_indptr_for_after[node_id] = after_start_pos;

        // Update the end pointer (which is the start for the next node)
        self.node_indptr_for_after[MastNodeId::new_unchecked((node_id.to_usize() + 1) as u32)] =
            after_end;
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
            self.node_indptr_for_before
                .push(self.before_enter_decorators.len())
                .expect("node_indptr_for_before capacity exceeded: MAST forest has too many nodes");
        }
        if self.node_indptr_for_after.len() == max_len {
            self.node_indptr_for_after
                .push(self.after_exit_decorators.len())
                .expect("node_indptr_for_after capacity exceeded: MAST forest has too many nodes");
        }
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

impl Default for NodeToDecoratorIds {
    fn default() -> Self {
        Self::new()
    }
}
