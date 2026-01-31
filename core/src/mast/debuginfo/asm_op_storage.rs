//! CSR storage for mapping (NodeId, OpIdx) -> AsmOpId.
//!
//! This module stores AssemblyOp mappings using a sparse CSR format. Unlike the previous
//! design that stored `Option<AsmOpId>` per operation slot, this stores only the operations
//! that actually have an AssemblyOp, along with their operation index.
//!
//! # Data Layout
//!
//! For each node, we store a list of `(op_idx, asm_op_id)` pairs representing which
//! operations have an AssemblyOp. The pairs are sorted by `op_idx` within each node.
//!
//! # Example
//!
//! ```text
//! Node 0: Op 2 -> asm_op_0
//! Node 1: Op 0 -> asm_op_1, Op 2 -> asm_op_2
//! ```
//!
//! This would be stored as:
//! ```text
//! data: [(2, asm_op_0), (0, asm_op_1), (2, asm_op_2)]
//! indptr: [0, 1, 3]  // Node 0: [0,1), Node 1: [1,3)
//! ```

use alloc::{string::String, vec::Vec};

use miden_utils_indexing::{CsrMatrix, CsrValidationError};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::mast::{AsmOpId, MastNodeId};

/// Error type for AsmOp index mapping operations.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AsmOpIndexError {
    /// Node index is invalid (either out of sequence or already added).
    #[error("Invalid node index {0:?}")]
    NodeIndex(MastNodeId),
    /// Operation indices must be strictly increasing within the input.
    #[error("Operation indices must be strictly increasing")]
    NonIncreasingOpIndices,
    /// Operation index is out of bounds for the node's operation count.
    #[error("Operation index {0} exceeds node's operation count {1}")]
    OpIndexOutOfBounds(usize, usize),
    /// Internal CSR structure is corrupted.
    #[error("Internal CSR structure error")]
    InternalStructure,
}

/// CSR storage mapping (NodeId, OpIdx) -> AsmOpId.
///
/// Unlike [`OpToDecoratorIds`](super::OpToDecoratorIds), each operation has at most one
/// AssemblyOp. We store only the operations that have an AssemblyOp, using sparse storage.
///
/// This structure provides efficient lookup of AssemblyOps by node and operation index,
/// which is needed for error context reporting and debugging tools.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OpToAsmOpId {
    /// CSR storage: each row (node) contains `(op_idx, asm_op_id)` pairs.
    /// Only operations with an AssemblyOp are stored (sparse representation).
    inner: CsrMatrix<MastNodeId, (usize, AsmOpId)>,
}

impl Default for OpToAsmOpId {
    fn default() -> Self {
        Self::new()
    }
}

impl OpToAsmOpId {
    /// Creates a new empty [`OpToAsmOpId`].
    pub fn new() -> Self {
        Self { inner: CsrMatrix::new() }
    }

    /// Creates an [`OpToAsmOpId`] with the specified capacity.
    pub fn with_capacity(nodes_capacity: usize, operations_capacity: usize) -> Self {
        Self {
            inner: CsrMatrix::with_capacity(nodes_capacity, operations_capacity),
        }
    }

    /// Returns `true` if this storage contains no nodes.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the number of nodes in this storage.
    pub fn num_nodes(&self) -> usize {
        self.inner.num_rows()
    }

    /// Returns the total number of (op_idx, asm_op_id) entries across all nodes.
    ///
    /// Note: This is the number of operations that have an AssemblyOp, not the total
    /// number of operations.
    pub fn num_operations(&self) -> usize {
        self.inner.num_elements()
    }

    /// Registers AssemblyOps for a node's operations.
    ///
    /// `asm_ops` is a list of `(op_idx, asm_op_id)` pairs. The `op_idx` values must be
    /// strictly increasing. Operations not listed will have no AsmOpId (sparse storage).
    ///
    /// Nodes must be added in sequential order starting from 0. If a node is skipped,
    /// empty placeholder nodes are automatically created.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node to register operations for. Must be >= current node count.
    /// * `num_operations` - Total number of operations in this node (used for bounds checking).
    /// * `asm_ops` - List of (operation_index, AsmOpId) pairs, sorted by operation_index.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `node_id` is less than the current node count (already added)
    /// - Operation indices are not strictly increasing
    /// - An operation index exceeds `num_operations`
    pub fn add_asm_op_for_node(
        &mut self,
        node_id: MastNodeId,
        num_operations: usize,
        asm_ops: Vec<(usize, AsmOpId)>,
    ) -> Result<(), AsmOpIndexError> {
        let expected_node = self.num_nodes() as u32;
        let node_idx = u32::from(node_id);

        // Check if trying to add a node that was already added
        if node_idx < expected_node {
            return Err(AsmOpIndexError::NodeIndex(node_id));
        }

        // Create empty nodes for any gaps
        for _ in expected_node..node_idx {
            self.inner.push_empty_row().map_err(|_| AsmOpIndexError::InternalStructure)?;
        }

        // Verify strictly increasing operation indices
        for window in asm_ops.windows(2) {
            if window[0].0 >= window[1].0 {
                return Err(AsmOpIndexError::NonIncreasingOpIndices);
            }
        }

        // Verify all indices are within bounds
        if let Some((max_idx, _)) = asm_ops.last()
            && *max_idx >= num_operations
        {
            return Err(AsmOpIndexError::OpIndexOutOfBounds(*max_idx, num_operations));
        }

        self.inner.push_row(asm_ops).map_err(|_| AsmOpIndexError::InternalStructure)?;

        Ok(())
    }

    /// Returns the AsmOpId for a specific operation within a node, if any.
    ///
    /// If the operation doesn't have a direct AssemblyOp, this performs a backward search
    /// to find the most recent AssemblyOp (needed for multi-cycle instructions like `assertz`
    /// where only the first operation has an AssemblyOp).
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node to query.
    /// * `op_idx` - The operation index within the node.
    ///
    /// # Returns
    ///
    /// - `Some(asm_op_id)` if the operation has an associated AssemblyOp (direct or via backward
    ///   search)
    /// - `None` if the node doesn't exist or no AssemblyOp is found
    pub fn asm_op_id_for_operation(&self, node_id: MastNodeId, op_idx: usize) -> Option<AsmOpId> {
        let entries = self.inner.row(node_id)?;

        // Binary search for the largest op_idx <= target
        // We're looking for the entry whose op_idx is closest to (but not greater than) op_idx
        match entries.binary_search_by_key(&op_idx, |(idx, _)| *idx) {
            Ok(i) => Some(entries[i].1),
            Err(i) if i > 0 => Some(entries[i - 1].1),
            Err(_) => None,
        }
    }

    /// Returns the first AsmOpId for a node, if any operations have one.
    ///
    /// This is useful for getting context about a node when no specific operation
    /// index is available.
    pub fn first_asm_op_for_node(&self, node_id: MastNodeId) -> Option<AsmOpId> {
        let entries = self.inner.row(node_id)?;
        entries.first().map(|(_, id)| *id)
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
    pub(super) fn validate_csr(&self, asm_op_count: usize) -> Result<(), String> {
        self.inner
            .validate_with(|(_op_idx, asm_op_id)| (u32::from(*asm_op_id) as usize) < asm_op_count)
            .map_err(|e| format_validation_error(e, asm_op_count))
    }

    /// Creates a new [`OpToAsmOpId`] with remapped node IDs.
    ///
    /// This is used when nodes are removed from a MastForest and the remaining nodes
    /// are renumbered. The remapping maps old node IDs to new node IDs.
    ///
    /// Nodes that are not in the remapping are considered removed and their asm_op data
    /// is discarded.
    pub fn remap_nodes(
        &self,
        remapping: &alloc::collections::BTreeMap<MastNodeId, MastNodeId>,
    ) -> Self {
        use alloc::{collections::BTreeMap, vec::Vec};

        if self.is_empty() {
            return Self::new();
        }
        if remapping.is_empty() {
            // No remapping means no nodes were removed/reordered, keep current storage
            return self.clone();
        }

        // Find the max new node ID to determine the size of the new structure
        let max_new_id = remapping.values().map(|id| u32::from(*id)).max().unwrap_or(0) as usize;
        let num_new_nodes = max_new_id + 1;

        // Collect the data for each new node ID
        let mut new_node_data: BTreeMap<usize, Vec<(usize, AsmOpId)>> = BTreeMap::new();

        for (old_id, new_id) in remapping {
            let new_idx = u32::from(*new_id) as usize;

            if let Some(entries) = self.inner.row(*old_id)
                && !entries.is_empty()
            {
                new_node_data.insert(new_idx, entries.to_vec());
            }
        }

        // Build the new CSR structure
        let mut new_inner = CsrMatrix::with_capacity(num_new_nodes, self.inner.num_elements());

        for new_idx in 0..num_new_nodes {
            if let Some(data) = new_node_data.get(&new_idx) {
                new_inner.push_row(data.iter().copied()).expect("node count should fit in u32");
            } else {
                new_inner.push_empty_row().expect("node count should fit in u32");
            }
        }

        Self { inner: new_inner }
    }

    /// Serializes this [`OpToAsmOpId`] into the target writer.
    pub(super) fn write_into<W: crate::utils::ByteWriter>(&self, target: &mut W) {
        use crate::utils::Serializable;

        self.inner.write_into(target);
    }

    /// Deserializes an [`OpToAsmOpId`] from the source reader.
    pub(super) fn read_from<R: crate::utils::ByteReader>(
        source: &mut R,
        asm_op_count: usize,
    ) -> Result<Self, crate::utils::DeserializationError> {
        use crate::utils::{Deserializable, DeserializationError};

        let inner: CsrMatrix<MastNodeId, (usize, AsmOpId)> = Deserializable::read_from(source)?;

        let result = Self { inner };

        result.validate_csr(asm_op_count).map_err(|e| {
            DeserializationError::InvalidValue(alloc::format!(
                "OpToAsmOpId validation failed: {}",
                e
            ))
        })?;

        Ok(result)
    }
}

/// Format a CsrValidationError into a human-readable string.
fn format_validation_error(error: CsrValidationError, asm_op_count: usize) -> String {
    use alloc::format;
    match error {
        CsrValidationError::IndptrStartNotZero(val) => format!("indptr must start at 0, got {val}"),
        CsrValidationError::IndptrNotMonotonic { index, prev, curr } => {
            format!("indptr not monotonic at index {index}: {prev} > {curr}")
        },
        CsrValidationError::IndptrDataMismatch { indptr_end, data_len } => {
            format!("indptr ends at {indptr_end}, but data.len() is {data_len}")
        },
        CsrValidationError::InvalidData { row, position } => format!(
            "Invalid AsmOpId at row {row}, position {position}: exceeds asm_op count {asm_op_count}"
        ),
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

        // Register: op 2 has asm_op_id 0 (3 ops total: 0, 1, 2)
        storage.add_asm_op_for_node(node_id, 3, vec![(2, asm_op_id)]).unwrap();

        assert!(!storage.is_empty());
        assert_eq!(storage.num_nodes(), 1);
        assert_eq!(storage.num_operations(), 1); // Only 1 entry stored (sparse)

        // Query
        assert_eq!(storage.asm_op_id_for_operation(node_id, 0), None);
        assert_eq!(storage.asm_op_id_for_operation(node_id, 1), None);
        assert_eq!(storage.asm_op_id_for_operation(node_id, 2), Some(asm_op_id));
        assert_eq!(storage.asm_op_id_for_operation(node_id, 3), Some(asm_op_id)); // Backward search
    }

    #[test]
    fn test_op_to_asm_op_id_single_node_multiple_ops() {
        let mut storage = OpToAsmOpId::new();
        let node_id = test_node_id(0);

        // Multiple operations with asm_ops (6 ops total: 0-5)
        storage
            .add_asm_op_for_node(
                node_id,
                6,
                vec![(0, test_asm_op_id(10)), (2, test_asm_op_id(20)), (5, test_asm_op_id(30))],
            )
            .unwrap();

        assert_eq!(storage.num_operations(), 3); // Only 3 entries stored (sparse)

        // Backward search returns previous asm_op for ops without direct asm_op
        assert_eq!(storage.asm_op_id_for_operation(node_id, 0), Some(test_asm_op_id(10)));
        assert_eq!(storage.asm_op_id_for_operation(node_id, 1), Some(test_asm_op_id(10)));
        assert_eq!(storage.asm_op_id_for_operation(node_id, 2), Some(test_asm_op_id(20)));
        assert_eq!(storage.asm_op_id_for_operation(node_id, 3), Some(test_asm_op_id(20)));
        assert_eq!(storage.asm_op_id_for_operation(node_id, 4), Some(test_asm_op_id(20)));
        assert_eq!(storage.asm_op_id_for_operation(node_id, 5), Some(test_asm_op_id(30)));
    }

    #[test]
    fn test_op_to_asm_op_id_empty_node() {
        let mut storage = OpToAsmOpId::new();
        let node_id = test_node_id(0);

        // Empty node (0 operations)
        storage.add_asm_op_for_node(node_id, 0, vec![]).unwrap();

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

        // Node 0: op 1 has asm_op 0 (2 ops total)
        storage
            .add_asm_op_for_node(test_node_id(0), 2, vec![(1, test_asm_op_id(0))])
            .unwrap();

        // Node 1: op 0 has asm_op 1, op 2 has asm_op 2 (3 ops total)
        storage
            .add_asm_op_for_node(
                test_node_id(1),
                3,
                vec![(0, test_asm_op_id(1)), (2, test_asm_op_id(2))],
            )
            .unwrap();

        assert_eq!(storage.num_nodes(), 2);

        // Node 0 queries
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(0), 0), None);
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(0), 1), Some(test_asm_op_id(0)));

        // Node 1 queries
        // Backward search finds op 0's asm_op for op 1 (no direct asm_op)
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(1), 0), Some(test_asm_op_id(1)));
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(1), 1), Some(test_asm_op_id(1)));
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(1), 2), Some(test_asm_op_id(2)));
    }

    #[test]
    fn test_op_to_asm_op_id_mixed_empty_and_populated_nodes() {
        let mut storage = OpToAsmOpId::new();

        // Node 0: has ops (1 op)
        storage
            .add_asm_op_for_node(test_node_id(0), 1, vec![(0, test_asm_op_id(0))])
            .unwrap();

        // Node 1: empty (0 ops)
        storage.add_asm_op_for_node(test_node_id(1), 0, vec![]).unwrap();

        // Node 2: has ops (2 ops)
        storage
            .add_asm_op_for_node(test_node_id(2), 2, vec![(1, test_asm_op_id(1))])
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

        // Add node 0 (1 op)
        storage
            .add_asm_op_for_node(test_node_id(0), 1, vec![(0, test_asm_op_id(0))])
            .unwrap();

        // Skip node 1, add node 2 directly (should auto-create empty node 1) (1 op)
        storage
            .add_asm_op_for_node(test_node_id(2), 1, vec![(0, test_asm_op_id(1))])
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

        // Node with asm_op at op 2 (not op 0), 3 ops total
        storage
            .add_asm_op_for_node(test_node_id(0), 3, vec![(2, test_asm_op_id(42))])
            .unwrap();

        assert_eq!(storage.first_asm_op_for_node(test_node_id(0)), Some(test_asm_op_id(42)));
    }

    #[test]
    fn test_first_asm_op_for_node_empty() {
        let mut storage = OpToAsmOpId::new();

        storage.add_asm_op_for_node(test_node_id(0), 0, vec![]).unwrap();

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

        // Multiple ops, first one at index 1 (4 ops total)
        storage
            .add_asm_op_for_node(
                test_node_id(0),
                4,
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

        // Non-increasing operation indices should fail (3 ops)
        let result = storage.add_asm_op_for_node(
            test_node_id(0),
            3,
            vec![(2, test_asm_op_id(0)), (1, test_asm_op_id(1))],
        );

        assert_eq!(result, Err(AsmOpIndexError::NonIncreasingOpIndices));
    }

    #[test]
    fn test_op_to_asm_op_id_duplicate_ops() {
        let mut storage = OpToAsmOpId::new();

        // Duplicate operation indices should fail (2 ops)
        let result = storage.add_asm_op_for_node(
            test_node_id(0),
            2,
            vec![(1, test_asm_op_id(0)), (1, test_asm_op_id(1))],
        );

        assert_eq!(result, Err(AsmOpIndexError::NonIncreasingOpIndices));
    }

    #[test]
    fn test_op_to_asm_op_id_node_already_added() {
        let mut storage = OpToAsmOpId::new();

        storage.add_asm_op_for_node(test_node_id(0), 0, vec![]).unwrap();
        storage.add_asm_op_for_node(test_node_id(1), 0, vec![]).unwrap();

        // Try to add node 0 again
        let result = storage.add_asm_op_for_node(test_node_id(0), 0, vec![]);

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

        // 2 ops total (ops 0, 1)
        storage
            .add_asm_op_for_node(test_node_id(0), 2, vec![(1, test_asm_op_id(0))])
            .unwrap();

        // Op 2 is out of bounds but backward search still finds op 1's asm_op
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(0), 2), Some(test_asm_op_id(0)));
        assert_eq!(storage.asm_op_id_for_operation(test_node_id(0), 100), Some(test_asm_op_id(0)));
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
        // 2 ops with asm_ops at indices 0 and 1
        storage
            .add_asm_op_for_node(
                test_node_id(0),
                2,
                vec![(0, test_asm_op_id(0)), (1, test_asm_op_id(1))],
            )
            .unwrap();

        assert!(storage.validate_csr(2).is_ok());
    }

    #[test]
    fn test_validate_csr_invalid_asm_op_id() {
        let mut storage = OpToAsmOpId::new();
        // 2 ops with asm_ops at indices 0 and 1
        storage
            .add_asm_op_for_node(
                test_node_id(0),
                2,
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

        let mut bytes = alloc::vec::Vec::new();
        storage.write_into(&mut bytes);

        let mut reader = SliceReader::new(&bytes);
        let deserialized = OpToAsmOpId::read_from(&mut reader, 0).unwrap();

        assert_eq!(storage, deserialized);
    }

    #[test]
    fn test_serialization_roundtrip_with_data() {
        use crate::utils::SliceReader;

        let mut storage = OpToAsmOpId::new();
        // Node 0: 3 ops, asm_ops at indices 0 and 2
        storage
            .add_asm_op_for_node(
                test_node_id(0),
                3,
                vec![(0, test_asm_op_id(0)), (2, test_asm_op_id(1))],
            )
            .unwrap();
        // Node 1: 0 ops
        storage.add_asm_op_for_node(test_node_id(1), 0, vec![]).unwrap();
        // Node 2: 2 ops, asm_op at index 1
        storage
            .add_asm_op_for_node(test_node_id(2), 2, vec![(1, test_asm_op_id(2))])
            .unwrap();

        let mut bytes = alloc::vec::Vec::new();
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
            .add_asm_op_for_node(test_node_id(0), 1, vec![(0, test_asm_op_id(42))])
            .unwrap();

        let storage2 = storage1.clone();
        assert_eq!(storage1, storage2);

        let mut storage3 = OpToAsmOpId::new();
        storage3
            .add_asm_op_for_node(test_node_id(0), 1, vec![(0, test_asm_op_id(99))])
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
