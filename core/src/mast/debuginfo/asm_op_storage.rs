//! CSR storage for mapping (NodeId, OpIdx) -> Option<AsmOpId>.
//!
//! Unlike decorators where each operation can have multiple decorator IDs, each operation
//! has at most one AssemblyOp. This simplifies the storage: we store a flat array of
//! Option<AsmOpId> indexed by operation, with CSR pointers to map nodes to their operations.
//!
//! # Data Layout
//!
//! - `asm_op_ids`: flat array of `Option<AsmOpId>`, one per operation across all nodes
//! - `node_indptr`: CSR row pointers mapping node N to indices `[node_indptr[N]..node_indptr[N+1])`
//!   in `asm_op_ids`
//!
//! # Example
//!
//! ```text
//! Node 0: Op 0 -> None, Op 1 -> None, Op 2 -> Some(asm_op_0)
//! Node 1: Op 0 -> Some(asm_op_1), Op 1 -> Some(asm_op_2)
//! ```
//!
//! This would be stored as:
//! ```text
//! asm_op_ids: [None, None, Some(0), Some(1), Some(2)]
//! node_indptr: [0, 3, 5]  // Node 0: [0,3), Node 1: [3,5)
//! ```

use alloc::vec::Vec;

use miden_utils_indexing::IndexVec;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::mast::{AsmOpId, MastNodeId};

/// Error type for AsmOp index mapping operations.
// TODO: Remove this allow when Task 3 integrates OpToAsmOpId into DebugInfo
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AsmOpIndexError {
    /// Node index is invalid (either out of sequence or already added).
    #[error("Invalid node index {0:?}")]
    NodeIndex(MastNodeId),
    /// Operation indices must be strictly increasing within the input.
    #[error("Operation indices must be strictly increasing")]
    NonIncreasingOpIndices,
    /// Internal CSR structure is corrupted.
    #[error("Internal CSR structure error")]
    InternalStructure,
}

/// CSR storage mapping (NodeId, OpIdx) -> Option<AsmOpId>.
///
/// Unlike [`OpToDecoratorIds`](super::OpToDecoratorIds), each operation has at most one
/// AssemblyOp, so we store `Option<AsmOpId>` per operation slot rather than a list.
///
/// This structure provides efficient lookup of AssemblyOps by node and operation index,
/// which is needed for error context reporting and debugging tools.
// TODO: Remove this allow when Task 3 integrates OpToAsmOpId into DebugInfo
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OpToAsmOpId {
    /// AsmOpId for each operation slot (None if no AssemblyOp for that op).
    asm_op_ids: Vec<Option<AsmOpId>>,
    /// CSR row pointers: node N's operations are at `asm_op_ids[node_indptr[N]..node_indptr[N+1]]`.
    node_indptr: IndexVec<MastNodeId, usize>,
}

// TODO: Remove this allow when Task 3 integrates OpToAsmOpId into DebugInfo
#[allow(dead_code)]
impl OpToAsmOpId {
    /// Creates a new empty [`OpToAsmOpId`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an [`OpToAsmOpId`] with the specified capacity.
    pub fn with_capacity(nodes_capacity: usize, operations_capacity: usize) -> Self {
        Self {
            asm_op_ids: Vec::with_capacity(operations_capacity),
            node_indptr: IndexVec::with_capacity(nodes_capacity + 1),
        }
    }

    /// Returns `true` if this storage contains no nodes.
    pub fn is_empty(&self) -> bool {
        self.node_indptr.is_empty()
    }

    /// Returns the number of nodes in this storage.
    pub fn num_nodes(&self) -> usize {
        if self.node_indptr.is_empty() {
            0
        } else {
            self.node_indptr.len() - 1
        }
    }

    /// Returns the total number of operation slots across all nodes.
    pub fn num_operations(&self) -> usize {
        self.asm_op_ids.len()
    }

    /// Registers AssemblyOps for a node's operations.
    ///
    /// `asm_ops` is a list of `(op_idx, asm_op_id)` pairs. The `op_idx` values must be
    /// strictly increasing. Operations not listed will have `None` for their AsmOpId.
    ///
    /// Nodes must be added in sequential order starting from 0. If a node is skipped,
    /// empty placeholder nodes are automatically created.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node to register operations for. Must be >= current node count.
    /// * `asm_ops` - List of (operation_index, AsmOpId) pairs, sorted by operation_index.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `node_id` is less than the current node count (already added)
    /// - Operation indices are not strictly increasing
    pub fn add_asm_op_for_node(
        &mut self,
        node_id: MastNodeId,
        asm_ops: Vec<(usize, AsmOpId)>,
    ) -> Result<(), AsmOpIndexError> {
        let expected_node = self.num_nodes() as u32;
        let node_idx = u32::from(node_id);

        // Check if trying to add a node that was already added
        if node_idx < expected_node {
            return Err(AsmOpIndexError::NodeIndex(node_id));
        }

        // Create empty nodes for any gaps
        for gap_idx in expected_node..node_idx {
            self.add_empty_node(MastNodeId::new_unchecked(gap_idx))?;
        }

        // Initialize node_indptr if this is the first node
        if self.node_indptr.is_empty() {
            self.node_indptr.push(0).map_err(|_| AsmOpIndexError::InternalStructure)?;
        }

        if asm_ops.is_empty() {
            // Empty node: just add pointer to current position
            self.node_indptr
                .push(self.asm_op_ids.len())
                .map_err(|_| AsmOpIndexError::InternalStructure)?;
            return Ok(());
        }

        // Verify strictly increasing operation indices
        for window in asm_ops.windows(2) {
            if window[0].0 >= window[1].0 {
                return Err(AsmOpIndexError::NonIncreasingOpIndices);
            }
        }

        // Find max operation index to determine how many slots we need
        let max_op_idx = asm_ops.last().map(|(idx, _)| *idx).unwrap_or(0);
        let num_ops = max_op_idx + 1;

        // Add operation slots for this node, initialized to None
        let start = self.asm_op_ids.len();
        self.asm_op_ids.resize(start + num_ops, None);

        // Fill in the AsmOpIds at their respective positions
        for (op_idx, asm_op_id) in asm_ops {
            self.asm_op_ids[start + op_idx] = Some(asm_op_id);
        }

        // Update node_indptr to point past this node's operations
        self.node_indptr
            .push(self.asm_op_ids.len())
            .map_err(|_| AsmOpIndexError::InternalStructure)?;

        Ok(())
    }

    /// Adds an empty node (node with no operations).
    fn add_empty_node(&mut self, _node_id: MastNodeId) -> Result<(), AsmOpIndexError> {
        if self.node_indptr.is_empty() {
            self.node_indptr.push(0).map_err(|_| AsmOpIndexError::InternalStructure)?;
        }
        self.node_indptr
            .push(self.asm_op_ids.len())
            .map_err(|_| AsmOpIndexError::InternalStructure)?;
        Ok(())
    }

    /// Returns the AsmOpId for a specific operation within a node, if any.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node to query.
    /// * `op_idx` - The operation index within the node.
    ///
    /// # Returns
    ///
    /// - `Some(asm_op_id)` if the operation has an associated AssemblyOp
    /// - `None` if the node doesn't exist, the operation is out of range,
    ///   or the operation has no AssemblyOp
    pub fn asm_op_id_for_operation(&self, node_id: MastNodeId, op_idx: usize) -> Option<AsmOpId> {
        let (start, end) = self.operation_range_for_node(node_id)?;

        let global_idx = start + op_idx;
        if global_idx >= end {
            return None;
        }

        self.asm_op_ids.get(global_idx).copied().flatten()
    }

    /// Returns the first AsmOpId for a node, if any operations have one.
    ///
    /// This is useful for getting context about a node when no specific operation
    /// index is available.
    pub fn first_asm_op_for_node(&self, node_id: MastNodeId) -> Option<AsmOpId> {
        let (start, end) = self.operation_range_for_node(node_id)?;

        for idx in start..end {
            if let Some(Some(asm_op_id)) = self.asm_op_ids.get(idx) {
                return Some(*asm_op_id);
            }
        }

        None
    }

    /// Returns the range of indices into `asm_op_ids` for the given node.
    ///
    /// Returns `None` if the node doesn't exist.
    fn operation_range_for_node(&self, node_id: MastNodeId) -> Option<(usize, usize)> {
        let node_idx = u32::from(node_id) as usize;

        // Need at least node_idx + 2 entries in node_indptr (start and end)
        if node_idx + 1 >= self.node_indptr.len() {
            return None;
        }

        let start = self.node_indptr[node_id];
        let end = self.node_indptr[MastNodeId::new_unchecked((node_idx + 1) as u32)];

        Some((start, end))
    }

    /// Validates the CSR structure integrity.
    ///
    /// # Arguments
    ///
    /// * `asm_op_count` - The total number of AssemblyOps that should be valid.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the structure is valid, otherwise an error message.
    pub(super) fn validate_csr(&self, asm_op_count: usize) -> Result<(), alloc::string::String> {
        use alloc::string::ToString;

        // Empty storage is always valid
        if self.asm_op_ids.is_empty() && self.node_indptr.is_empty() {
            return Ok(());
        }

        // Nodes with no operations: all pointers should be 0
        if self.asm_op_ids.is_empty() {
            if !self.node_indptr.iter().all(|&ptr| ptr == 0) {
                return Err("node pointers must all be 0 when there are no operations".to_string());
            }
            return Ok(());
        }

        // Validate node_indptr
        let node_slice = self.node_indptr.as_slice();
        if node_slice.is_empty() {
            return Err("node_indptr cannot be empty when asm_op_ids is non-empty".to_string());
        }

        if node_slice[0] != 0 {
            return Err("node_indptr must start at 0".to_string());
        }

        // Check monotonicity
        for window in node_slice.windows(2) {
            if window[0] > window[1] {
                return Err(alloc::format!(
                    "node_indptr not monotonic: {} > {}",
                    window[0],
                    window[1]
                ));
            }
        }

        // Last pointer should equal asm_op_ids length
        if *node_slice.last().unwrap() != self.asm_op_ids.len() {
            return Err(alloc::format!(
                "node_indptr end {} doesn't match asm_op_ids length {}",
                node_slice.last().unwrap(),
                self.asm_op_ids.len()
            ));
        }

        // Validate all AsmOpIds
        for id in self.asm_op_ids.iter().flatten() {
            let id_val = u32::from(*id) as usize;
            if id_val >= asm_op_count {
                return Err(alloc::format!(
                    "Invalid AsmOpId {}: exceeds asm_op count {}",
                    id_val,
                    asm_op_count
                ));
            }
        }

        Ok(())
    }

    /// Serializes this [`OpToAsmOpId`] into the target writer.
    pub(super) fn write_into<W: crate::utils::ByteWriter>(&self, target: &mut W) {
        use crate::utils::Serializable;

        self.asm_op_ids.write_into(target);
        self.node_indptr.write_into(target);
    }

    /// Deserializes an [`OpToAsmOpId`] from the source reader.
    pub(super) fn read_from<R: crate::utils::ByteReader>(
        source: &mut R,
        asm_op_count: usize,
    ) -> Result<Self, crate::utils::DeserializationError> {
        use crate::utils::{Deserializable, DeserializationError};

        let asm_op_ids: Vec<Option<AsmOpId>> = Deserializable::read_from(source)?;
        let node_indptr: IndexVec<MastNodeId, usize> = Deserializable::read_from(source)?;

        let result = Self { asm_op_ids, node_indptr };

        result.validate_csr(asm_op_count).map_err(|e| {
            DeserializationError::InvalidValue(alloc::format!(
                "OpToAsmOpId validation failed: {}",
                e
            ))
        })?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test AsmOpId.
    fn test_asm_op_id(value: u32) -> AsmOpId {
        AsmOpId::new(value)
    }

    /// Helper to create a test MastNodeId.
    fn test_node_id(value: u32) -> MastNodeId {
        MastNodeId::new_unchecked(value)
    }

    // =============================================================================================
    // Basic Construction Tests
    // =============================================================================================

    #[test]
    fn test_op_to_asm_op_id_empty() {
        let storage = OpToAsmOpId::new();
        assert!(storage.is_empty());
        assert_eq!(storage.num_nodes(), 0);
        assert_eq!(storage.num_operations(), 0);
    }

    #[test]
    fn test_op_to_asm_op_id_default() {
        let storage = OpToAsmOpId::default();
        assert!(storage.is_empty());
    }

    #[test]
    fn test_op_to_asm_op_id_with_capacity() {
        let storage = OpToAsmOpId::with_capacity(10, 100);
        assert!(storage.is_empty());
        assert_eq!(storage.num_nodes(), 0);
    }

    // =============================================================================================
    // Single Node Tests
    // =============================================================================================

    #[test]
    fn test_op_to_asm_op_id_single_node() {
        let mut storage = OpToAsmOpId::new();
        let node_id = test_node_id(0);
        let asm_op_id = test_asm_op_id(0);

        // Register: op 2 has asm_op_id 0
        storage.add_asm_op_for_node(node_id, vec![(2, asm_op_id)]).unwrap();

        assert!(!storage.is_empty());
        assert_eq!(storage.num_nodes(), 1);
        assert_eq!(storage.num_operations(), 3); // ops 0, 1, 2

        // Query
        assert_eq!(storage.asm_op_id_for_operation(node_id, 0), None);
        assert_eq!(storage.asm_op_id_for_operation(node_id, 1), None);
        assert_eq!(storage.asm_op_id_for_operation(node_id, 2), Some(asm_op_id));
        assert_eq!(storage.asm_op_id_for_operation(node_id, 3), None); // out of range
    }

    #[test]
    fn test_op_to_asm_op_id_single_node_multiple_ops() {
        let mut storage = OpToAsmOpId::new();
        let node_id = test_node_id(0);

        // Multiple operations with asm_ops
        storage
            .add_asm_op_for_node(
                node_id,
                vec![(0, test_asm_op_id(10)), (2, test_asm_op_id(20)), (5, test_asm_op_id(30))],
            )
            .unwrap();

        assert_eq!(storage.num_operations(), 6); // ops 0-5

        assert_eq!(storage.asm_op_id_for_operation(node_id, 0), Some(test_asm_op_id(10)));
        assert_eq!(storage.asm_op_id_for_operation(node_id, 1), None);
        assert_eq!(storage.asm_op_id_for_operation(node_id, 2), Some(test_asm_op_id(20)));
        assert_eq!(storage.asm_op_id_for_operation(node_id, 3), None);
        assert_eq!(storage.asm_op_id_for_operation(node_id, 4), None);
        assert_eq!(storage.asm_op_id_for_operation(node_id, 5), Some(test_asm_op_id(30)));
    }

    #[test]
    fn test_op_to_asm_op_id_empty_node() {
        let mut storage = OpToAsmOpId::new();
        let node_id = test_node_id(0);

        // Empty node
        storage.add_asm_op_for_node(node_id, vec![]).unwrap();

        assert!(!storage.is_empty());
        assert_eq!(storage.num_nodes(), 1);
        assert_eq!(storage.num_operations(), 0);

        // All operations should return None
        assert_eq!(storage.asm_op_id_for_operation(node_id, 0), None);
    }

    // =============================================================================================
    // Multi-Node Tests
    // =============================================================================================

    #[test]
    fn test_op_to_asm_op_id_multiple_nodes() {
        let mut storage = OpToAsmOpId::new();

        // Node 0: op 1 has asm_op 0
        storage
            .add_asm_op_for_node(test_node_id(0), vec![(1, test_asm_op_id(0))])
            .unwrap();

        // Node 1: op 0 has asm_op 1, op 2 has asm_op 2
        storage
            .add_asm_op_for_node(
                test_node_id(1),
                vec![(0, test_asm_op_id(1)), (2, test_asm_op_id(2))],
            )
            .unwrap();

        assert_eq!(storage.num_nodes(), 2);

        // Node 0 queries
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(0), 0), None);
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(0), 1), Some(test_asm_op_id(0)));

        // Node 1 queries
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(1), 0), Some(test_asm_op_id(1)));
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(1), 1), None);
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(1), 2), Some(test_asm_op_id(2)));
    }

    #[test]
    fn test_op_to_asm_op_id_mixed_empty_and_populated_nodes() {
        let mut storage = OpToAsmOpId::new();

        // Node 0: has ops
        storage
            .add_asm_op_for_node(test_node_id(0), vec![(0, test_asm_op_id(0))])
            .unwrap();

        // Node 1: empty
        storage.add_asm_op_for_node(test_node_id(1), vec![]).unwrap();

        // Node 2: has ops
        storage
            .add_asm_op_for_node(test_node_id(2), vec![(1, test_asm_op_id(1))])
            .unwrap();

        assert_eq!(storage.num_nodes(), 3);

        assert_eq!(storage.asm_op_id_for_operation(test_node_id(0), 0), Some(test_asm_op_id(0)));
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(1), 0), None);
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(2), 0), None);
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(2), 1), Some(test_asm_op_id(1)));
    }

    #[test]
    fn test_op_to_asm_op_id_gap_in_nodes() {
        let mut storage = OpToAsmOpId::new();

        // Add node 0
        storage
            .add_asm_op_for_node(test_node_id(0), vec![(0, test_asm_op_id(0))])
            .unwrap();

        // Skip node 1, add node 2 directly (should auto-create empty node 1)
        storage
            .add_asm_op_for_node(test_node_id(2), vec![(0, test_asm_op_id(1))])
            .unwrap();

        assert_eq!(storage.num_nodes(), 3);

        // Node 1 should be empty
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(1), 0), None);

        // Nodes 0 and 2 should have their ops
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(0), 0), Some(test_asm_op_id(0)));
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(2), 0), Some(test_asm_op_id(1)));
    }

    // =============================================================================================
    // first_asm_op_for_node Tests
    // =============================================================================================

    #[test]
    fn test_first_asm_op_for_node() {
        let mut storage = OpToAsmOpId::new();

        // Node with asm_op at op 2 (not op 0)
        storage
            .add_asm_op_for_node(test_node_id(0), vec![(2, test_asm_op_id(42))])
            .unwrap();

        assert_eq!(storage.first_asm_op_for_node(test_node_id(0)), Some(test_asm_op_id(42)));
    }

    #[test]
    fn test_first_asm_op_for_node_empty() {
        let mut storage = OpToAsmOpId::new();

        storage.add_asm_op_for_node(test_node_id(0), vec![]).unwrap();

        assert_eq!(storage.first_asm_op_for_node(test_node_id(0)), None);
    }

    #[test]
    fn test_first_asm_op_for_node_nonexistent() {
        let storage = OpToAsmOpId::new();

        assert_eq!(storage.first_asm_op_for_node(test_node_id(0)), None);
    }

    #[test]
    fn test_first_asm_op_for_node_multiple_ops() {
        let mut storage = OpToAsmOpId::new();

        // Multiple ops, first one at index 1
        storage
            .add_asm_op_for_node(
                test_node_id(0),
                vec![(1, test_asm_op_id(10)), (3, test_asm_op_id(30))],
            )
            .unwrap();

        // Should return the first one found (at op 1)
        assert_eq!(storage.first_asm_op_for_node(test_node_id(0)), Some(test_asm_op_id(10)));
    }

    // =============================================================================================
    // Error Cases
    // =============================================================================================

    #[test]
    fn test_op_to_asm_op_id_non_increasing_ops() {
        let mut storage = OpToAsmOpId::new();

        // Non-increasing operation indices should fail
        let result = storage.add_asm_op_for_node(
            test_node_id(0),
            vec![(2, test_asm_op_id(0)), (1, test_asm_op_id(1))],
        );

        assert_eq!(result, Err(AsmOpIndexError::NonIncreasingOpIndices));
    }

    #[test]
    fn test_op_to_asm_op_id_duplicate_ops() {
        let mut storage = OpToAsmOpId::new();

        // Duplicate operation indices should fail
        let result = storage.add_asm_op_for_node(
            test_node_id(0),
            vec![(1, test_asm_op_id(0)), (1, test_asm_op_id(1))],
        );

        assert_eq!(result, Err(AsmOpIndexError::NonIncreasingOpIndices));
    }

    #[test]
    fn test_op_to_asm_op_id_node_already_added() {
        let mut storage = OpToAsmOpId::new();

        storage.add_asm_op_for_node(test_node_id(0), vec![]).unwrap();
        storage.add_asm_op_for_node(test_node_id(1), vec![]).unwrap();

        // Try to add node 0 again
        let result = storage.add_asm_op_for_node(test_node_id(0), vec![]);

        assert_eq!(result, Err(AsmOpIndexError::NodeIndex(test_node_id(0))));
    }

    // =============================================================================================
    // Query Edge Cases
    // =============================================================================================

    #[test]
    fn test_op_to_asm_op_id_query_nonexistent_node() {
        let storage = OpToAsmOpId::new();

        assert_eq!(storage.asm_op_id_for_operation(test_node_id(0), 0), None);
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(999), 0), None);
    }

    #[test]
    fn test_op_to_asm_op_id_query_out_of_bounds_op() {
        let mut storage = OpToAsmOpId::new();

        storage
            .add_asm_op_for_node(test_node_id(0), vec![(1, test_asm_op_id(0))])
            .unwrap();

        // Op 2 is out of bounds (only ops 0, 1 exist)
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(0), 2), None);
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(0), 100), None);
    }

    // =============================================================================================
    // CSR Validation Tests
    // =============================================================================================

    #[test]
    fn test_validate_csr_empty() {
        let storage = OpToAsmOpId::new();
        assert!(storage.validate_csr(0).is_ok());
    }

    #[test]
    fn test_validate_csr_valid() {
        let mut storage = OpToAsmOpId::new();
        storage
            .add_asm_op_for_node(
                test_node_id(0),
                vec![(0, test_asm_op_id(0)), (1, test_asm_op_id(1))],
            )
            .unwrap();

        assert!(storage.validate_csr(2).is_ok());
    }

    #[test]
    fn test_validate_csr_invalid_asm_op_id() {
        let mut storage = OpToAsmOpId::new();
        storage
            .add_asm_op_for_node(
                test_node_id(0),
                vec![(0, test_asm_op_id(0)), (1, test_asm_op_id(5))],
            )
            .unwrap();

        // asm_op_count=2 but we have id 5
        let result = storage.validate_csr(2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid AsmOpId"));
    }

    // =============================================================================================
    // Serialization Round-Trip Tests
    // =============================================================================================

    #[test]
    fn test_serialization_roundtrip_empty() {
        use crate::utils::SliceReader;

        let storage = OpToAsmOpId::new();

        let mut bytes = Vec::new();
        storage.write_into(&mut bytes);

        let mut reader = SliceReader::new(&bytes);
        let deserialized = OpToAsmOpId::read_from(&mut reader, 0).unwrap();

        assert_eq!(storage, deserialized);
    }

    #[test]
    fn test_serialization_roundtrip_with_data() {
        use crate::utils::SliceReader;

        let mut storage = OpToAsmOpId::new();
        storage
            .add_asm_op_for_node(
                test_node_id(0),
                vec![(0, test_asm_op_id(0)), (2, test_asm_op_id(1))],
            )
            .unwrap();
        storage.add_asm_op_for_node(test_node_id(1), vec![]).unwrap();
        storage
            .add_asm_op_for_node(test_node_id(2), vec![(1, test_asm_op_id(2))])
            .unwrap();

        let mut bytes = Vec::new();
        storage.write_into(&mut bytes);

        let mut reader = SliceReader::new(&bytes);
        let deserialized = OpToAsmOpId::read_from(&mut reader, 3).unwrap();

        assert_eq!(storage, deserialized);
    }

    // =============================================================================================
    // Clone and Debug Tests
    // =============================================================================================

    #[test]
    fn test_clone_and_equality() {
        let mut storage1 = OpToAsmOpId::new();
        storage1
            .add_asm_op_for_node(test_node_id(0), vec![(0, test_asm_op_id(42))])
            .unwrap();

        let storage2 = storage1.clone();
        assert_eq!(storage1, storage2);

        let mut storage3 = OpToAsmOpId::new();
        storage3
            .add_asm_op_for_node(test_node_id(0), vec![(0, test_asm_op_id(99))])
            .unwrap();

        assert_ne!(storage1, storage3);
    }

    #[test]
    fn test_debug_impl() {
        let storage = OpToAsmOpId::new();
        let debug_str = alloc::format!("{:?}", storage);
        assert!(debug_str.contains("OpToAsmOpId"));
    }
}
