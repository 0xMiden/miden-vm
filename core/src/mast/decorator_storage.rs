use alloc::vec::Vec;

use miden_utils_indexing::{Idx, IndexVec};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::mast::{DecoratorId, MastNodeId};

/// A two-level compressed sparse row (CSR) representation for storing decorators per operation per
/// node.
///
/// This structure provides efficient access to decorators in a hierarchical manner:
/// 1. First level: Node -> Operations (operations belong to nodes)
/// 2. Second level: Operation -> Decorators (decorators belong to operations)
///
/// The data layout follows CSR format at both levels:
/// - `decorator_indices`: Flat storage of all DecoratorId values
/// - `op_indptr_for_dec_idx`: Pointer indices for operations within decorator_indices
/// - `node_indptr_for_op_idx`: Pointer indices for nodes within op_indptr_for_dec_idx
///
/// # Example
///
/// Consider this COO (Coordinate format) representation:
/// ```text
/// Node 0, Op 0: [decorator_0, decorator_1]
/// Node 0, Op 1: [decorator_2]
/// Node 1, Op 0: [decorator_3, decorator_4, decorator_5]
/// ```
///
/// This would be stored as:
/// ```text
/// decorator_indices:    [0, 1, 2, 3, 4, 5]
/// op_indptr_for_dec_idx: [0, 2, 3, 6]  // Node 0: ops [0,2], [2,3]; Node 1: ops [3,6]
/// node_indptr_for_op_idx: [0, 2, 3]   // Node 0: [0,2], Node 1: [2,3]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OpIndexedDecoratorStorage {
    /// All the decorator indices per operation per node, in a CSR relationship with
    /// node_indptr_for_op_indptr and op_indptr_for_dec_idx
    decorator_indices: Vec<DecoratorId>,
    /// For the node which operation indices are in op_indptr_for_dec_idx[node_start, node_end],
    /// the indices of its i-th operation are at decorator_indices[op_indptr_for_dec_idx[node_start
    /// + i]..op_indptr_for_dec_idx[node_start + i + 1]]
    op_indptr_for_dec_idx: Vec<usize>,
    /// The decorated operation indices for the n-th node are at op_indptr_for_dec_idx[n, n+1]
    node_indptr_for_op_idx: IndexVec<MastNodeId, usize>,
}

/// Error type for DecoratorStorage operations
#[derive(Debug, PartialEq, Eq)]
pub enum DecoratorStorageError {
    /// Node index out of bounds
    NodeIndex(MastNodeId),
    /// Operation index out of bounds for the given node
    OperationIndex { node: MastNodeId, operation: usize },
    /// Invalid internal data structure (corrupted pointers)
    InternalStructure,
}

impl core::fmt::Display for DecoratorStorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NodeIndex(node) => write!(f, "Invalid node index: {:?}", node),
            Self::OperationIndex { node, operation } => {
                write!(f, "Invalid operation index {} for node {:?}", operation, node)
            },
            Self::InternalStructure => {
                write!(f, "Invalid internal data structure in DecoratorStorage")
            },
        }
    }
}

impl OpIndexedDecoratorStorage {
    /// Create a new empty DecoratorStorage with the specified capacity.
    ///
    /// # Arguments
    /// * `nodes_capacity` - Expected number of nodes
    /// * `operations_capacity` - Expected total number of operations across all nodes
    /// * `decorators_capacity` - Expected total number of decorators across all operations
    pub fn with_capacity(
        nodes_capacity: usize,
        operations_capacity: usize,
        decorators_capacity: usize,
    ) -> Self {
        Self {
            decorator_indices: Vec::with_capacity(decorators_capacity),
            op_indptr_for_dec_idx: Vec::with_capacity(operations_capacity + 1),
            node_indptr_for_op_idx: IndexVec::with_capacity(nodes_capacity + 1),
        }
    }

    /// Create a new empty DecoratorStorage.
    pub fn new() -> Self {
        Self::with_capacity(0, 0, 0)
    }

    /// Create a DecoratorStorage from raw CSR components.
    ///
    /// This is useful for deserialization or testing purposes.
    ///
    /// # Arguments
    /// * `decorator_indices` - Flat storage of all decorator IDs
    /// * `op_indptr_for_dec_idx` - Pointer indices for operations within decorator_indices
    /// * `node_indptr_for_op_idx` - Pointer indices for nodes within op_indptr_for_dec_idx
    ///
    /// # Returns
    /// An error if the internal structure is inconsistent.
    pub fn from_components(
        decorator_indices: Vec<DecoratorId>,
        op_indptr_for_dec_idx: Vec<usize>,
        node_indptr_for_op_idx: IndexVec<MastNodeId, usize>,
    ) -> Result<Self, DecoratorStorageError> {
        // Validate the structure
        if op_indptr_for_dec_idx.is_empty() {
            return Err(DecoratorStorageError::InternalStructure);
        }

        // Check that the last operation pointer doesn't exceed decorator indices length
        if *op_indptr_for_dec_idx.last().unwrap() > decorator_indices.len() {
            return Err(DecoratorStorageError::InternalStructure);
        }

        // Check that node pointers are within bounds of operation pointers
        if node_indptr_for_op_idx.is_empty() {
            return Err(DecoratorStorageError::InternalStructure);
        }

        let node_slice = node_indptr_for_op_idx.as_slice();
        if *node_slice.last().unwrap() > op_indptr_for_dec_idx.len() - 1 {
            return Err(DecoratorStorageError::InternalStructure);
        }

        // Ensure monotonicity of pointers
        for window in op_indptr_for_dec_idx.windows(2) {
            if window[0] > window[1] {
                return Err(DecoratorStorageError::InternalStructure);
            }
        }

        for window in node_slice.windows(2) {
            if window[0] > window[1] {
                return Err(DecoratorStorageError::InternalStructure);
            }
        }

        Ok(Self {
            decorator_indices,
            op_indptr_for_dec_idx,
            node_indptr_for_op_idx,
        })
    }

    /// Get the number of nodes in this storage.
    pub fn num_nodes(&self) -> usize {
        if self.node_indptr_for_op_idx.is_empty() {
            0
        } else {
            self.node_indptr_for_op_idx.len() - 1
        }
    }

    /// Get the total number of decorators across all operations.
    pub fn num_decorators(&self) -> usize {
        self.decorator_indices.len()
    }

    /// Add decorator information for a node incrementally.
    ///
    /// This method allows building up the DecoratorStorage structure by adding
    /// decorators for nodes in sequential order only.
    ///
    /// # Arguments
    /// * `node` - The node ID to add decorators for. Must be the next sequential node.
    /// * `decorators_info` - Vector of (operation_index, decorator_id) tuples. The operation
    ///   indices should be sorted (as guaranteed by validate_decorators). Operations not present in
    ///   this vector will have no decorators.
    ///
    /// # Returns
    /// Ok(()) if successful, Err(DecoratorStorageError) if the node is not the next sequential
    /// node.
    ///
    /// # Behavior
    /// - Can only add decorators for the next sequential node ID
    /// - Automatically creates empty operations for gaps in operation indices
    /// - Maintains the two-level CSR structure invariant
    pub fn add_decorator_info_for_node(
        &mut self,
        node: MastNodeId,
        decorators_info: Vec<(usize, DecoratorId)>,
    ) -> Result<(), DecoratorStorageError> {
        // Enforce sequential node ids
        let expected = MastNodeId::new_unchecked(self.num_nodes() as u32);
        if node != expected {
            return Err(DecoratorStorageError::NodeIndex(node));
        }

        // Start of this node's operations is the current length (do NOT reuse previous sentinel)
        let op_start = self.op_indptr_for_dec_idx.len();

        // Maintain node CSR: node_indptr[i] = start index for node i
        if self.node_indptr_for_op_idx.is_empty() {
            let _ = self.node_indptr_for_op_idx.push(op_start);
        } else {
            // Overwrite the previous "end" slot to become this node's start
            let last = MastNodeId::new_unchecked((self.node_indptr_for_op_idx.len() - 1) as u32);
            self.node_indptr_for_op_idx[last] = op_start;
        }

        if decorators_info.is_empty() {
            // Empty node: no operations at all, just set the end pointer equal to start
            // This creates a node with an empty operations range
            let _ = self.node_indptr_for_op_idx.push(op_start);
        } else {
            // Build op->decorator CSR for this node
            let max_op_idx = decorators_info.last().unwrap().0; // input is sorted by op index
            let mut it = decorators_info.into_iter().peekable();

            for op in 0..=max_op_idx {
                // pointer to start of decorators for op
                self.op_indptr_for_dec_idx.push(self.decorator_indices.len());
                while it.peek().is_some_and(|(i, _)| *i == op) {
                    self.decorator_indices.push(it.next().unwrap().1);
                }
            }
            // final sentinel for this node
            self.op_indptr_for_dec_idx.push(self.decorator_indices.len());

            // Push end pointer for this node (index of last op pointer)
            let end_ops = self.op_indptr_for_dec_idx.len() - 1;
            let _ = self.node_indptr_for_op_idx.push(end_ops);
        }

        Ok(())
    }

    /// Get the number of decorators for a specific operation within a node.
    ///
    /// # Arguments
    /// * `node` - The node ID
    /// * `operation` - The operation index within the node
    ///
    /// # Returns
    /// The number of decorators for the operation, or an error if indices are invalid.
    pub fn num_decorators_for_operation(
        &self,
        node: MastNodeId,
        operation: usize,
    ) -> Result<usize, DecoratorStorageError> {
        self.decorators_for_operation(node, operation).map(|slice| slice.len())
    }

    /// Get all decorators for a specific operation within a node.
    ///
    /// # Arguments
    /// * `node` - The node ID
    /// * `operation` - The operation index within the node
    ///
    /// # Returns
    /// A slice of decorator IDs for the operation, or an error if indices are invalid.
    pub fn decorators_for_operation(
        &self,
        node: MastNodeId,
        operation: usize,
    ) -> Result<&[DecoratorId], DecoratorStorageError> {
        let op_range = self.operation_range_for_node(node)?;
        // that operation does not have listed decorator indices
        if operation >= op_range.len() {
            return Ok(&[]);
        }

        let op_start_idx = op_range.start + operation;
        if op_start_idx + 1 >= self.op_indptr_for_dec_idx.len() {
            return Err(DecoratorStorageError::InternalStructure);
        }

        let dec_start = self.op_indptr_for_dec_idx[op_start_idx];
        let dec_end = self.op_indptr_for_dec_idx[op_start_idx + 1];

        if dec_start > dec_end || dec_end > self.decorator_indices.len() {
            return Err(DecoratorStorageError::InternalStructure);
        }

        Ok(&self.decorator_indices[dec_start..dec_end])
    }

    /// Get an iterator over all operations and their decorators for a given node.
    ///
    /// # Arguments
    /// * `node` - The node ID
    ///
    /// # Returns
    /// An iterator yielding (operation_index, decorator_slice) tuples, or an error if the node is
    /// invalid.
    pub fn decorators_for_node(
        &self,
        node: MastNodeId,
    ) -> Result<impl Iterator<Item = (usize, &[DecoratorId])>, DecoratorStorageError> {
        let op_range = self.operation_range_for_node(node)?;
        let num_ops = op_range.len();

        Ok((0..num_ops).map(move |op_idx| {
            let op_start_idx = op_range.start + op_idx;
            let dec_start = self.op_indptr_for_dec_idx[op_start_idx];
            let dec_end = self.op_indptr_for_dec_idx[op_start_idx + 1];
            (op_idx, &self.decorator_indices[dec_start..dec_end])
        }))
    }

    /// Check if a specific operation within a node has any decorators.
    ///
    /// # Arguments
    /// * `node` - The node ID
    /// * `operation` - The operation index within the node
    ///
    /// # Returns
    /// True if the operation has at least one decorator, false otherwise, or an error if indices
    /// are invalid.
    pub fn operation_has_decorators(
        &self,
        node: MastNodeId,
        operation: usize,
    ) -> Result<bool, DecoratorStorageError> {
        self.num_decorators_for_operation(node, operation).map(|count| count > 0)
    }

    /// Get the range of operation indices for a given node.
    ///
    /// # Arguments
    /// * `node` - The node ID
    ///
    /// # Returns
    /// A range representing the start and end (exclusive) operation indices for the node.
    fn operation_range_for_node(
        &self,
        node: MastNodeId,
    ) -> Result<core::ops::Range<usize>, DecoratorStorageError> {
        let node_slice = self.node_indptr_for_op_idx.as_slice();
        let node_idx = node.to_usize();

        if node_idx + 1 >= node_slice.len() {
            return Err(DecoratorStorageError::NodeIndex(node));
        }

        let start = node_slice[node_idx];
        let end = node_slice[node_idx + 1];

        if start > end || end > self.op_indptr_for_dec_idx.len() {
            return Err(DecoratorStorageError::InternalStructure);
        }

        Ok(start..end)
    }
}

impl Default for OpIndexedDecoratorStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use miden_utils_indexing::IndexVec;

    use super::*;

    /// Helper function to create a test DecoratorId
    fn test_decorator_id(value: u32) -> DecoratorId {
        DecoratorId(value)
    }

    /// Helper function to create a test MastNodeId
    fn test_node_id(value: u32) -> MastNodeId {
        MastNodeId::new_unchecked(value)
    }

    /// Helper to create standard test storage with 2 nodes, 3 operations, 6 decorators
    /// Structure: Node 0: Op 0 -> [0, 1], Op 1 -> [2]; Node 1: Op 0 -> [3, 4, 5]
    fn create_standard_test_storage() -> OpIndexedDecoratorStorage {
        let decorator_indices = vec![
            test_decorator_id(0),
            test_decorator_id(1),
            test_decorator_id(2),
            test_decorator_id(3),
            test_decorator_id(4),
            test_decorator_id(5),
        ];
        let op_indptr_for_dec_idx = vec![0, 2, 3, 6];
        let mut node_indptr_for_op_idx = IndexVec::new();
        let _ = node_indptr_for_op_idx.push(0);
        let _ = node_indptr_for_op_idx.push(2);
        let _ = node_indptr_for_op_idx.push(3);

        OpIndexedDecoratorStorage::from_components(
            decorator_indices,
            op_indptr_for_dec_idx,
            node_indptr_for_op_idx,
        )
        .unwrap()
    }

    #[test]
    fn test_constructors() {
        // Test new()
        let storage = OpIndexedDecoratorStorage::new();
        assert_eq!(storage.num_nodes(), 0);
        assert_eq!(storage.num_decorators(), 0);

        // Test with_capacity()
        let storage = OpIndexedDecoratorStorage::with_capacity(10, 20, 30);
        assert_eq!(storage.num_nodes(), 0);
        assert_eq!(storage.num_decorators(), 0);

        // Test default()
        let storage = OpIndexedDecoratorStorage::default();
        assert_eq!(storage.num_nodes(), 0);
        assert_eq!(storage.num_decorators(), 0);
    }

    #[test]
    fn test_from_components_simple() {
        // Create a simple structure:
        // Node 0: Op 0 -> [0, 1], Op 1 -> [2]
        // Node 1: Op 0 -> [3, 4, 5]
        let storage = create_standard_test_storage();

        assert_eq!(storage.num_nodes(), 2);
        assert_eq!(storage.num_decorators(), 6);
    }

    #[test]
    fn test_from_components_invalid_structure() {
        // Test with empty operation pointers
        let result = OpIndexedDecoratorStorage::from_components(vec![], vec![], IndexVec::new());
        assert_eq!(result, Err(DecoratorStorageError::InternalStructure));

        // Test with operation pointer exceeding decorator indices
        let result = OpIndexedDecoratorStorage::from_components(
            vec![test_decorator_id(0)],
            vec![0, 2], // Points to index 2 but we only have 1 decorator
            IndexVec::new(),
        );
        assert_eq!(result, Err(DecoratorStorageError::InternalStructure));

        // Test with non-monotonic operation pointers
        let result = OpIndexedDecoratorStorage::from_components(
            vec![test_decorator_id(0), test_decorator_id(1)],
            vec![0, 2, 1], // 2 > 1, should be monotonic
            IndexVec::new(),
        );
        assert_eq!(result, Err(DecoratorStorageError::InternalStructure));
    }

    #[test]
    fn test_data_access_methods() {
        let storage = create_standard_test_storage();

        // Test decorators_for_operation
        let decorators = storage.decorators_for_operation(test_node_id(0), 0).unwrap();
        assert_eq!(decorators, &[test_decorator_id(0), test_decorator_id(1)]);

        let decorators = storage.decorators_for_operation(test_node_id(0), 1).unwrap();
        assert_eq!(decorators, &[test_decorator_id(2)]);

        let decorators = storage.decorators_for_operation(test_node_id(1), 0).unwrap();
        assert_eq!(decorators, &[test_decorator_id(3), test_decorator_id(4), test_decorator_id(5)]);

        // Test decorators_for_node
        let decorators: Vec<_> = storage.decorators_for_node(test_node_id(0)).unwrap().collect();
        assert_eq!(decorators.len(), 2);
        assert_eq!(decorators[0], (0, &[test_decorator_id(0), test_decorator_id(1)][..]));
        assert_eq!(decorators[1], (1, &[test_decorator_id(2)][..]));

        let decorators: Vec<_> = storage.decorators_for_node(test_node_id(1)).unwrap().collect();
        assert_eq!(decorators.len(), 1);
        assert_eq!(
            decorators[0],
            (0, &[test_decorator_id(3), test_decorator_id(4), test_decorator_id(5)][..])
        );

        // Test operation_has_decorators
        assert!(storage.operation_has_decorators(test_node_id(0), 0).unwrap());
        assert!(storage.operation_has_decorators(test_node_id(0), 1).unwrap());
        assert!(storage.operation_has_decorators(test_node_id(1), 0).unwrap());
        assert!(!storage.operation_has_decorators(test_node_id(0), 2).unwrap());

        // Test num_decorators_for_operation
        assert_eq!(storage.num_decorators_for_operation(test_node_id(0), 0).unwrap(), 2);
        assert_eq!(storage.num_decorators_for_operation(test_node_id(0), 1).unwrap(), 1);
        assert_eq!(storage.num_decorators_for_operation(test_node_id(1), 0).unwrap(), 3);
        assert_eq!(storage.num_decorators_for_operation(test_node_id(0), 2).unwrap(), 0);

        // Test invalid operation returns empty slice
        let decorators = storage.decorators_for_operation(test_node_id(0), 2).unwrap();
        assert_eq!(decorators, &[]);
    }

    #[test]
    fn test_empty_nodes_and_operations() {
        // Create a structure with empty nodes/operations
        let decorator_indices = vec![];
        let op_indptr_for_dec_idx = vec![0, 0, 0]; // 2 operations, both empty
        let mut node_indptr_for_op_idx = IndexVec::new();
        let _ = node_indptr_for_op_idx.push(0);
        let _ = node_indptr_for_op_idx.push(2);

        let storage = OpIndexedDecoratorStorage::from_components(
            decorator_indices,
            op_indptr_for_dec_idx,
            node_indptr_for_op_idx,
        )
        .unwrap();

        assert_eq!(storage.num_nodes(), 1);
        assert_eq!(storage.num_decorators(), 0);

        // Empty decorators
        let decorators = storage.decorators_for_operation(test_node_id(0), 0).unwrap();
        assert_eq!(decorators, &[]);

        // Operation has no decorators
        assert!(!storage.operation_has_decorators(test_node_id(0), 0).unwrap());
    }

    #[test]
    fn test_debug_impl() {
        let storage = OpIndexedDecoratorStorage::new();
        let debug_str = format!("{:?}", storage);
        assert!(debug_str.contains("DecoratorStorage"));
    }

    #[test]
    fn test_clone_and_equality() {
        let decorator_indices = vec![
            test_decorator_id(0),
            test_decorator_id(1),
            test_decorator_id(2),
            test_decorator_id(3),
            test_decorator_id(4),
            test_decorator_id(5),
        ];
        let op_indptr_for_dec_idx = vec![0, 2, 3, 6];
        let mut node_indptr_for_op_idx = IndexVec::new();
        let _ = node_indptr_for_op_idx.push(0);
        let _ = node_indptr_for_op_idx.push(2);
        let _ = node_indptr_for_op_idx.push(3);

        let storage1 = OpIndexedDecoratorStorage::from_components(
            decorator_indices.clone(),
            op_indptr_for_dec_idx.clone(),
            node_indptr_for_op_idx.clone(),
        )
        .unwrap();

        let storage2 = storage1.clone();
        assert_eq!(storage1, storage2);

        // Modify one and ensure they're no longer equal
        let different_decorators = vec![test_decorator_id(10)];
        let mut different_node_indptr = IndexVec::new();
        let _ = different_node_indptr.push(0);
        let _ = different_node_indptr.push(1);

        let storage3 = OpIndexedDecoratorStorage::from_components(
            different_decorators,
            vec![0, 1],
            different_node_indptr,
        )
        .unwrap();

        assert_ne!(storage1, storage3);
    }

    #[test]
    fn test_add_decorator_info_functionality() {
        // Test 1: Basic multi-node functionality
        let mut storage = OpIndexedDecoratorStorage::new();

        // Add decorators for node 0
        let decorators_info = vec![
            (0, test_decorator_id(10)),
            (0, test_decorator_id(11)),
            (2, test_decorator_id(12)),
        ];
        storage.add_decorator_info_for_node(test_node_id(0), decorators_info).unwrap();

        assert_eq!(storage.num_nodes(), 1);
        assert_eq!(storage.num_decorators_for_operation(test_node_id(0), 0).unwrap(), 2);
        assert_eq!(storage.num_decorators_for_operation(test_node_id(0), 2).unwrap(), 1);

        // Add node 1 with simple decorators
        storage
            .add_decorator_info_for_node(test_node_id(1), vec![(0, test_decorator_id(20))])
            .unwrap();
        assert_eq!(storage.num_nodes(), 2);

        let node1_op0 = storage.decorators_for_operation(test_node_id(1), 0).unwrap();
        assert_eq!(node1_op0, &[test_decorator_id(20)]);

        // Test 2: Sequential constraint validation
        let mut storage2 = OpIndexedDecoratorStorage::new();
        storage2
            .add_decorator_info_for_node(test_node_id(0), vec![(0, test_decorator_id(10))])
            .unwrap();

        // Adding node 1 should succeed
        storage2
            .add_decorator_info_for_node(test_node_id(1), vec![(0, test_decorator_id(30))])
            .unwrap();
        assert_eq!(storage2.num_nodes(), 2);

        // Try to add node 0 again - should fail
        let result =
            storage2.add_decorator_info_for_node(test_node_id(0), vec![(0, test_decorator_id(40))]);
        assert_eq!(result, Err(DecoratorStorageError::NodeIndex(test_node_id(0))));

        // Test 3: Empty input handling (creates empty nodes with no operations)
        let mut storage3 = OpIndexedDecoratorStorage::new();
        let result = storage3.add_decorator_info_for_node(test_node_id(0), vec![]);
        assert_eq!(result, Ok(()));
        assert_eq!(storage3.num_nodes(), 1); // Should create empty node

        // Empty node should have no operations (accessing any operation should return empty)
        let decorators = storage3.decorators_for_operation(test_node_id(0), 0).unwrap();
        assert_eq!(decorators, &[]);

        // Should be able to add next node after empty node
        storage3
            .add_decorator_info_for_node(test_node_id(1), vec![(0, test_decorator_id(100))])
            .unwrap();
        assert_eq!(storage3.num_nodes(), 2);

        // Test 4: Operations with gaps
        let mut storage4 = OpIndexedDecoratorStorage::new();
        let gap_decorators = vec![
            (0, test_decorator_id(10)),
            (0, test_decorator_id(11)), // operation 0 has 2 decorators
            (3, test_decorator_id(12)), // operation 3 has 1 decorator
            (4, test_decorator_id(13)), // operation 4 has 1 decorator
        ];
        storage4.add_decorator_info_for_node(test_node_id(0), gap_decorators).unwrap();

        assert_eq!(storage4.num_decorators_for_operation(test_node_id(0), 0).unwrap(), 2);
        assert_eq!(storage4.num_decorators_for_operation(test_node_id(0), 1).unwrap(), 0);
        assert_eq!(storage4.num_decorators_for_operation(test_node_id(0), 2).unwrap(), 0);
        assert_eq!(storage4.num_decorators_for_operation(test_node_id(0), 3).unwrap(), 1);
        assert_eq!(storage4.num_decorators_for_operation(test_node_id(0), 4).unwrap(), 1);

        // Test accessing operations without decorators returns empty slice
        let op1_decorators = storage4.decorators_for_operation(test_node_id(0), 1).unwrap();
        assert_eq!(op1_decorators, &[]);

        // Test 5: Your specific use case - mixed empty and non-empty nodes
        let mut storage5 = OpIndexedDecoratorStorage::new();

        // node 0 with decorators
        storage5
            .add_decorator_info_for_node(
                test_node_id(0),
                vec![(0, test_decorator_id(1)), (1, test_decorator_id(0))],
            )
            .unwrap();

        // node 1 with no decorators (empty)
        storage5.add_decorator_info_for_node(test_node_id(1), vec![]).unwrap();

        // node 2 with decorators
        storage5
            .add_decorator_info_for_node(
                test_node_id(2),
                vec![(1, test_decorator_id(1)), (2, test_decorator_id(2))],
            )
            .unwrap();

        assert_eq!(storage5.num_nodes(), 3);

        // Verify node 0: op 0 has [1], op 1 has [0]
        assert_eq!(
            storage5.decorators_for_operation(test_node_id(0), 0).unwrap(),
            &[test_decorator_id(1)]
        );
        assert_eq!(
            storage5.decorators_for_operation(test_node_id(0), 1).unwrap(),
            &[test_decorator_id(0)]
        );

        // Verify node 1: has no operations at all, any operation access returns empty
        assert_eq!(storage5.decorators_for_operation(test_node_id(1), 0).unwrap(), &[]);

        // Verify node 2: op 0 has [], op 1 has [1], op 2 has [2]
        assert_eq!(storage5.decorators_for_operation(test_node_id(2), 0).unwrap(), &[]);
        assert_eq!(
            storage5.decorators_for_operation(test_node_id(2), 1).unwrap(),
            &[test_decorator_id(1)]
        );
        assert_eq!(
            storage5.decorators_for_operation(test_node_id(2), 2).unwrap(),
            &[test_decorator_id(2)]
        );
    }
}
