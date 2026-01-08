use alloc::{
    string::{String, ToString},
    vec::Vec,
};

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
    before_enter_decorators: Vec<DecoratorId>,
    /// All `after_exit` decorators, concatenated across all nodes.
    after_exit_decorators: Vec<DecoratorId>,
    /// Index pointers for before_enter decorators: the range for node `i` is
    /// ```text
    /// node_indptr_for_before[i]..node_indptr_for_before[i+1]
    /// ```
    node_indptr_for_before: IndexVec<MastNodeId, usize>,
    /// Index pointers for after_exit decorators: the range for node `i` is
    /// ```text
    /// node_indptr_for_after[i]..node_indptr_for_after[i+1]
    /// ```
    node_indptr_for_after: IndexVec<MastNodeId, usize>,
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

    /// Create a NodeToDecoratorIds from raw components.
    ///
    /// Used during deserialization. Validation happens separately via `validate_csr()`.
    pub fn from_components(
        before_enter_decorators: Vec<DecoratorId>,
        after_exit_decorators: Vec<DecoratorId>,
        node_indptr_for_before: IndexVec<MastNodeId, usize>,
        node_indptr_for_after: IndexVec<MastNodeId, usize>,
    ) -> Result<Self, String> {
        let storage = Self {
            before_enter_decorators,
            after_exit_decorators,
            node_indptr_for_before,
            node_indptr_for_after,
        };

        // Basic structural validation (full validation happens via validate_csr)
        let before_slice = storage.node_indptr_for_before.as_slice();
        let after_slice = storage.node_indptr_for_after.as_slice();

        if !before_slice.is_empty() && before_slice[0] != 0 {
            return Err("node_indptr_for_before must start at 0".to_string());
        }

        if !after_slice.is_empty() && after_slice[0] != 0 {
            return Err("node_indptr_for_after must start at 0".to_string());
        }

        Ok(storage)
    }

    /// Validate CSR structure integrity.
    ///
    /// Checks:
    /// - All decorator IDs are valid (< decorator_count)
    /// - Both indptr arrays are monotonic, start at 0, end at respective decorator vector lengths
    pub(super) fn validate_csr(&self, decorator_count: usize) -> Result<(), String> {
        // Completely empty structures are valid (no nodes, no decorators)
        if self.before_enter_decorators.is_empty()
            && self.after_exit_decorators.is_empty()
            && self.node_indptr_for_before.is_empty()
            && self.node_indptr_for_after.is_empty()
        {
            return Ok(());
        }

        // Validate all decorator IDs
        for &dec_id in self.before_enter_decorators.iter().chain(self.after_exit_decorators.iter())
        {
            if dec_id.to_usize() >= decorator_count {
                return Err(format!(
                    "Invalid decorator ID {}: exceeds decorator count {}",
                    dec_id.to_usize(),
                    decorator_count
                ));
            }
        }

        // Validate before_enter CSR
        let before_slice = self.node_indptr_for_before.as_slice();
        if !before_slice.is_empty() {
            if before_slice[0] != 0 {
                return Err("node_indptr_for_before must start at 0".to_string());
            }

            for window in before_slice.windows(2) {
                if window[0] > window[1] {
                    return Err(format!(
                        "node_indptr_for_before not monotonic: {} > {}",
                        window[0], window[1]
                    ));
                }
            }

            if *before_slice.last().unwrap() != self.before_enter_decorators.len() {
                return Err(format!(
                    "node_indptr_for_before end {} doesn't match before_enter_decorators length {}",
                    before_slice.last().unwrap(),
                    self.before_enter_decorators.len()
                ));
            }
        }

        // Validate after_exit CSR
        let after_slice = self.node_indptr_for_after.as_slice();
        if !after_slice.is_empty() {
            if after_slice[0] != 0 {
                return Err("node_indptr_for_after must start at 0".to_string());
            }

            for window in after_slice.windows(2) {
                if window[0] > window[1] {
                    return Err(format!(
                        "node_indptr_for_after not monotonic: {} > {}",
                        window[0], window[1]
                    ));
                }
            }

            if *after_slice.last().unwrap() != self.after_exit_decorators.len() {
                return Err(format!(
                    "node_indptr_for_after end {} doesn't match after_exit_decorators length {}",
                    after_slice.last().unwrap(),
                    self.after_exit_decorators.len()
                ));
            }
        }

        Ok(())
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

    // SERIALIZATION HELPERS
    // --------------------------------------------------------------------------------------------

    /// Write this CSR structure to a target using dense representation.
    pub(super) fn write_into<W: crate::utils::ByteWriter>(&self, target: &mut W) {
        use crate::utils::Serializable;

        self.before_enter_decorators.write_into(target);
        self.after_exit_decorators.write_into(target);
        self.node_indptr_for_before.write_into(target);
        self.node_indptr_for_after.write_into(target);
    }

    /// Read this CSR structure from a source, validating decorator IDs against decorator_count.
    pub(super) fn read_from<R: crate::utils::ByteReader>(
        source: &mut R,
        decorator_count: usize,
    ) -> Result<Self, crate::utils::DeserializationError> {
        use crate::utils::Deserializable;

        let before_enter_decorators: Vec<DecoratorId> = Deserializable::read_from(source)?;
        let after_exit_decorators: Vec<DecoratorId> = Deserializable::read_from(source)?;

        let node_indptr_for_before: IndexVec<MastNodeId, usize> =
            Deserializable::read_from(source)?;
        let node_indptr_for_after: IndexVec<MastNodeId, usize> = Deserializable::read_from(source)?;

        let result = Self::from_components(
            before_enter_decorators,
            after_exit_decorators,
            node_indptr_for_before,
            node_indptr_for_after,
        )
        .map_err(|e| crate::utils::DeserializationError::InvalidValue(e.to_string()))?;

        result.validate_csr(decorator_count).map_err(|e| {
            crate::utils::DeserializationError::InvalidValue(format!(
                "NodeToDecoratorIds validation failed: {e}"
            ))
        })?;

        Ok(result)
    }
}

impl Default for NodeToDecoratorIds {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_decorator_id(value: u32) -> DecoratorId {
        DecoratorId(value)
    }

    #[test]
    fn test_from_components_valid() {
        let before = vec![test_decorator_id(0), test_decorator_id(1)];
        let after = vec![test_decorator_id(2)];

        let mut before_indptr = IndexVec::new();
        before_indptr.push(0).unwrap();
        before_indptr.push(2).unwrap();

        let mut after_indptr = IndexVec::new();
        after_indptr.push(0).unwrap();
        after_indptr.push(1).unwrap();

        let storage =
            NodeToDecoratorIds::from_components(before, after, before_indptr, after_indptr);

        assert!(storage.is_ok());
    }

    #[test]
    fn test_validate_csr_valid() {
        let mut before_indptr = IndexVec::new();
        before_indptr.push(0).unwrap();
        before_indptr.push(1).unwrap();

        let mut after_indptr = IndexVec::new();
        after_indptr.push(0).unwrap();
        after_indptr.push(1).unwrap();

        let storage = NodeToDecoratorIds::from_components(
            vec![test_decorator_id(0)],
            vec![test_decorator_id(1)],
            before_indptr,
            after_indptr,
        )
        .unwrap();

        assert!(storage.validate_csr(3).is_ok());
    }

    #[test]
    fn test_validate_csr_invalid_decorator_id() {
        let mut before_indptr = IndexVec::new();
        before_indptr.push(0).unwrap();
        before_indptr.push(1).unwrap();

        let mut after_indptr = IndexVec::new();
        after_indptr.push(0).unwrap();
        after_indptr.push(0).unwrap();

        let storage = NodeToDecoratorIds::from_components(
            vec![test_decorator_id(5)], // ID too high
            vec![],
            before_indptr,
            after_indptr,
        )
        .unwrap();

        let result = storage.validate_csr(3);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid decorator ID"));
    }
}
