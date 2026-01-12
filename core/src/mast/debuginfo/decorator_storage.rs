use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use miden_utils_indexing::{Idx, IndexVec};
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::mast::{DecoratedOpLink, DecoratorId, MastNodeId};

/// A two-level compressed sparse row (CSR) representation for indexing decorator IDs per
/// operation per node.
///
/// This structure provides efficient access to decorator IDs in a hierarchical manner:
/// 1. First level: Node -> Operations (operations belong to nodes)
/// 2. Second level: Operation -> Decorator IDs (decorator IDs belong to operations)
///
/// The data layout follows CSR format at both levels:
///
/// - `decorator_ids` contains all the DecoratorId values in a single flat array. These are the
///   actual decorator identifiers that need to be accessed. We store them contiguously to minimize
///   memory overhead and improve cache locality when iterating.
///
/// - `op_indptr_for_dec_ids` stores pointer indices that map operations to their position within
///   the `decorator_ids` array. For each operation, it contains the start index where that
///   operation's decorator IDs begin in the flat storage.
///
/// - `node_indptr_for_op_idx` stores pointer indices that map nodes to their position within the
///   `op_indptr_for_dec_ids` array. For each node, it contains the start index where that node's
///   operation pointers begin.
///
/// Together, these three arrays form a two-level index structure that allows efficient
/// lookup of decorator IDs for any operation in any node, while minimizing memory usage
/// for sparse decorator data.
///
/// # Example
///
/// Consider this COO (Coordinate format) representation:
/// ```text
/// Node 0, Op 0: [decorator_id_0, decorator_id_1]
/// Node 0, Op 1: [decorator_id_2]
/// Node 1, Op 0: [decorator_id_3, decorator_id_4, decorator_id_5]
/// ```
///
/// This would be stored as:
/// ```text
/// decorator_ids:         [0, 1, 2, 3, 4, 5]
/// op_indptr_for_dec_ids: [0, 2, 3, 6]  // Node 0: ops [0,2], [2,3]; Node 1: ops [3,6]
/// node_indptr_for_op_idx: [0, 2, 3]   // Node 0: [0,2], Node 1: [2,3]
/// ```
///
/// See the unit test `test_csr_and_coo_produce_same_elements` for a comprehensive example
/// demonstrating how this encoding works and verifying round-trip conversion from COO to CSR.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct OpToDecoratorIds {
    /// All the decorator IDs per operation per node, in a CSR relationship with
    /// node_indptr_for_op_idx and op_indptr_for_dec_ids
    decorator_ids: Vec<DecoratorId>,
    /// For the node whose operation indices are in
    /// `op_indptr_for_dec_ids[node_start..node_end]`,
    /// the indices of its i-th operation are at:
    /// ```text
    /// decorator_ids[op_indptr_for_dec_ids[node_start + i]..
    ///               op_indptr_for_dec_ids[node_start + i + 1]]
    /// ```
    op_indptr_for_dec_ids: Vec<usize>,
    /// The decorated operation indices for the n-th node are at
    /// `op_indptr_for_dec_ids[node_indptr_for_op_idx[n]..node_indptr_for_op_idx[n+1]]`
    node_indptr_for_op_idx: IndexVec<MastNodeId, usize>,
}

/// Error type for decorator index mapping operations
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecoratorIndexError {
    /// Node index out of bounds
    #[error("Invalid node index {0:?}")]
    NodeIndex(MastNodeId),
    /// Operation index out of bounds for the given node
    #[error("Invalid operation index {operation} for node {node:?}")]
    OperationIndex { node: MastNodeId, operation: usize },
    /// Invalid internal data structure (corrupted pointers)
    #[error("Invalid internal data structure in OpToDecoratorIds")]
    InternalStructure,
}

impl OpToDecoratorIds {
    /// Create a new empty OpToDecoratorIds with the specified capacity.
    ///
    /// # Arguments
    /// * `nodes_capacity` - Expected number of nodes
    /// * `operations_capacity` - Expected total number of operations across all nodes
    /// * `decorator_ids_capacity` - Expected total number of decorator IDs across all operations
    pub fn with_capacity(
        nodes_capacity: usize,
        operations_capacity: usize,
        decorator_ids_capacity: usize,
    ) -> Self {
        Self {
            decorator_ids: Vec::with_capacity(decorator_ids_capacity),
            op_indptr_for_dec_ids: Vec::with_capacity(operations_capacity + 1),
            node_indptr_for_op_idx: IndexVec::with_capacity(nodes_capacity + 1),
        }
    }

    /// Create a new empty OpToDecoratorIds.
    pub fn new() -> Self {
        Self::with_capacity(0, 0, 0)
    }

    /// Create a OpToDecoratorIds from raw CSR components.
    ///
    /// This is useful for deserialization or testing purposes where you need to reconstruct
    /// the data structure from its raw components.
    ///
    /// # Arguments
    /// * `decorator_ids` - Flat storage of all decorator IDs. These are the actual decorator
    ///   identifiers that will be accessed through the index structure.
    /// * `op_indptr_for_dec_ids` - Pointer indices for operations within decorator_ids. These must
    ///   be monotonically increasing and within bounds of `decorator_ids`. The slice must not be
    ///   empty, and the first element must be 0.
    /// * `node_indptr_for_op_idx` - Pointer indices for nodes within op_indptr_for_dec_ids. These
    ///   must be monotonically increasing and within bounds of `op_indptr_for_dec_ids`. The slice
    ///   must not be empty, and the first element must be 0.
    ///
    /// # Valid Edge Cases
    /// - All three vectors empty (no nodes, no decorators)
    /// - Empty decorator vectors with node pointers all zero (nodes exist but have no decorators)
    ///
    /// # Validation Rules
    /// For non-empty structures:
    /// - Pointer arrays must start at zero
    /// - Pointers must be monotonically non-decreasing
    /// - Last value in `op_indptr_for_dec_ids` must be <= `decorator_ids.len()`
    /// - Last value in `node_indptr_for_op_idx` must be < `op_indptr_for_dec_ids.len()`
    pub(super) fn from_components(
        decorator_ids: Vec<DecoratorId>,
        op_indptr_for_dec_ids: Vec<usize>,
        node_indptr_for_op_idx: IndexVec<MastNodeId, usize>,
    ) -> Result<Self, DecoratorIndexError> {
        // Completely empty structures are valid (no nodes, no decorators)
        if decorator_ids.is_empty()
            && op_indptr_for_dec_ids.is_empty()
            && node_indptr_for_op_idx.is_empty()
        {
            return Ok(Self {
                decorator_ids,
                op_indptr_for_dec_ids,
                node_indptr_for_op_idx,
            });
        }

        // Nodes with no decorators are valid
        if decorator_ids.is_empty() && op_indptr_for_dec_ids.is_empty() {
            // All node pointers must be 0
            if node_indptr_for_op_idx.iter().all(|&ptr| ptr == 0) {
                return Ok(Self {
                    decorator_ids,
                    op_indptr_for_dec_ids,
                    node_indptr_for_op_idx,
                });
            } else {
                return Err(DecoratorIndexError::InternalStructure);
            }
        }

        // Validate the structure
        if op_indptr_for_dec_ids.is_empty() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        // Check that op_indptr_for_dec_ids starts at 0
        if op_indptr_for_dec_ids[0] != 0 {
            return Err(DecoratorIndexError::InternalStructure);
        }

        // Check that the last operation pointer doesn't exceed decorator IDs length
        let Some(&last_op_ptr) = op_indptr_for_dec_ids.last() else {
            return Err(DecoratorIndexError::InternalStructure);
        };
        if last_op_ptr > decorator_ids.len() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        // Check that node pointers are within bounds of operation pointers
        if node_indptr_for_op_idx.is_empty() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        let node_slice = node_indptr_for_op_idx.as_slice();

        // Check that node_indptr_for_op_idx starts at 0
        if node_slice[0] != 0 {
            return Err(DecoratorIndexError::InternalStructure);
        }

        let Some(&last_node_ptr) = node_slice.last() else {
            return Err(DecoratorIndexError::InternalStructure);
        };
        // Node pointers must be valid indices into op_indptr
        if last_node_ptr > op_indptr_for_dec_ids.len() - 1 {
            return Err(DecoratorIndexError::InternalStructure);
        }

        // Ensure monotonicity of pointers
        for window in op_indptr_for_dec_ids.windows(2) {
            if window[0] > window[1] {
                return Err(DecoratorIndexError::InternalStructure);
            }
        }

        for window in node_slice.windows(2) {
            if window[0] > window[1] {
                return Err(DecoratorIndexError::InternalStructure);
            }
        }

        Ok(Self {
            decorator_ids,
            op_indptr_for_dec_ids,
            node_indptr_for_op_idx,
        })
    }

    /// Validate CSR structure integrity.
    ///
    /// Checks:
    /// - All decorator IDs are valid (< decorator_count)
    /// - op_indptr_for_dec_ids is monotonic, starts at 0, ends at decorator_ids.len()
    /// - node_indptr_for_op_idx is monotonic, starts at 0, ends <= op_indptr_for_dec_ids.len()-1
    pub(super) fn validate_csr(&self, decorator_count: usize) -> Result<(), String> {
        // Completely empty structures are valid (no nodes, no decorators)
        if self.decorator_ids.is_empty()
            && self.op_indptr_for_dec_ids.is_empty()
            && self.node_indptr_for_op_idx.is_empty()
        {
            return Ok(());
        }

        // Nodes with no decorators are valid
        if self.decorator_ids.is_empty() && self.op_indptr_for_dec_ids.is_empty() {
            // All node pointers must be 0
            if !self.node_indptr_for_op_idx.iter().all(|&ptr| ptr == 0) {
                return Err("node pointers must all be 0 when there are no decorators".to_string());
            }
            return Ok(());
        }

        // Validate all decorator IDs
        for &dec_id in &self.decorator_ids {
            if dec_id.to_usize() >= decorator_count {
                return Err(format!(
                    "Invalid decorator ID {}: exceeds decorator count {}",
                    dec_id.to_usize(),
                    decorator_count
                ));
            }
        }

        // Validate op_indptr_for_dec_ids
        if self.op_indptr_for_dec_ids.is_empty() {
            return Err("op_indptr_for_dec_ids cannot be empty".to_string());
        }

        if self.op_indptr_for_dec_ids[0] != 0 {
            return Err("op_indptr_for_dec_ids must start at 0".to_string());
        }

        for window in self.op_indptr_for_dec_ids.windows(2) {
            if window[0] > window[1] {
                return Err(format!(
                    "op_indptr_for_dec_ids not monotonic: {} > {}",
                    window[0], window[1]
                ));
            }
        }

        if *self.op_indptr_for_dec_ids.last().unwrap() != self.decorator_ids.len() {
            return Err(format!(
                "op_indptr_for_dec_ids end {} doesn't match decorator_ids length {}",
                self.op_indptr_for_dec_ids.last().unwrap(),
                self.decorator_ids.len()
            ));
        }

        // Validate node_indptr_for_op_idx
        let node_slice = self.node_indptr_for_op_idx.as_slice();
        if node_slice.is_empty() {
            return Err("node_indptr_for_op_idx cannot be empty".to_string());
        }

        if node_slice[0] != 0 {
            return Err("node_indptr_for_op_idx must start at 0".to_string());
        }

        for window in node_slice.windows(2) {
            if window[0] > window[1] {
                return Err(format!(
                    "node_indptr_for_op_idx not monotonic: {} > {}",
                    window[0], window[1]
                ));
            }
        }

        // Node pointers must be valid indices into op_indptr
        let max_node_ptr = self.op_indptr_for_dec_ids.len() - 1;
        if *node_slice.last().unwrap() > max_node_ptr {
            return Err(format!(
                "node_indptr_for_op_idx end {} exceeds op_indptr bounds {}",
                node_slice.last().unwrap(),
                max_node_ptr
            ));
        }

        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.node_indptr_for_op_idx.is_empty()
    }

    /// Serialize this OpToDecoratorIds into the target writer.
    pub(super) fn write_into<W: crate::utils::ByteWriter>(&self, target: &mut W) {
        use crate::utils::Serializable;

        self.decorator_ids.write_into(target);
        self.op_indptr_for_dec_ids.write_into(target);
        self.node_indptr_for_op_idx.write_into(target);
    }

    /// Deserialize OpToDecoratorIds from the source reader.
    pub(super) fn read_from<R: crate::utils::ByteReader>(
        source: &mut R,
        decorator_count: usize,
    ) -> Result<Self, crate::utils::DeserializationError> {
        use crate::utils::{Deserializable, DeserializationError};

        let decorator_ids: Vec<DecoratorId> = Deserializable::read_from(source)?;
        let op_indptr_for_dec_ids: Vec<usize> = Deserializable::read_from(source)?;
        let node_indptr_for_op_idx: IndexVec<MastNodeId, usize> =
            Deserializable::read_from(source)?;

        let result =
            Self::from_components(decorator_ids, op_indptr_for_dec_ids, node_indptr_for_op_idx)
                .map_err(|e| DeserializationError::InvalidValue(e.to_string()))?;

        result.validate_csr(decorator_count).map_err(|e| {
            DeserializationError::InvalidValue(format!("OpToDecoratorIds validation failed: {e}"))
        })?;

        Ok(result)
    }

    /// Get the number of nodes in this storage.
    pub fn num_nodes(&self) -> usize {
        if self.node_indptr_for_op_idx.is_empty() {
            0
        } else {
            self.node_indptr_for_op_idx.len() - 1
        }
    }

    /// Get the total number of decorator IDs across all operations.
    pub fn num_decorator_ids(&self) -> usize {
        self.decorator_ids.len()
    }

    /// Add decorator information for a node incrementally.
    ///
    /// This method allows building up the OpToDecoratorIds structure by adding
    /// decorator IDs for nodes in sequential order only.
    ///
    /// # Arguments
    /// * `node` - The node ID to add decorator IDs for. Must be the next sequential node.
    /// * `decorators_info` - Vector of (operation_index, decorator_id) tuples. The operation
    ///   indices should be sorted (as guaranteed by validate_decorators). Operations not present in
    ///   this vector will have no decorator IDs.
    ///
    /// # Returns
    /// Ok(()) if successful, Err(DecoratorIndexError) if the node is not the next sequential
    /// node.
    ///
    /// # Behavior
    /// - Can only add decorator IDs for the next sequential node ID
    /// - Automatically creates empty operations for gaps in operation indices
    /// - Maintains the two-level CSR structure invariant
    pub fn add_decorator_info_for_node(
        &mut self,
        node: MastNodeId,
        decorators_info: Vec<(usize, DecoratorId)>,
    ) -> Result<(), DecoratorIndexError> {
        // Enforce sequential node ids
        let expected = MastNodeId::new_unchecked(self.num_nodes() as u32);
        if node < expected {
            return Err(DecoratorIndexError::NodeIndex(node));
        }
        // Create empty nodes for gaps in node indices
        for idx in expected.0..node.0 {
            self.add_decorator_info_for_node(MastNodeId::new_unchecked(idx), vec![])
                .unwrap();
        }

        // Start of this node's operations is the current length (do NOT reuse previous sentinel)
        let op_start = self.op_indptr_for_dec_ids.len();

        // Maintain node CSR: node_indptr[i] = start index for node i
        if self.node_indptr_for_op_idx.is_empty() {
            self.node_indptr_for_op_idx
                .push(op_start)
                .map_err(|_| DecoratorIndexError::OperationIndex { node, operation: op_start })?;
        } else {
            // Overwrite the previous "end" slot to become this node's start
            let last = MastNodeId::new_unchecked((self.node_indptr_for_op_idx.len() - 1) as u32);
            self.node_indptr_for_op_idx[last] = op_start;
        }

        if decorators_info.is_empty() {
            // Empty node needs sentinel if it follows decorated nodes
            // CSR requires all node_indptr values to be valid op_indptr indices.
            // If op_start == op_indptr.len(), add a sentinel so the pointer stays in bounds.
            if op_start == self.op_indptr_for_dec_ids.len()
                && !self.op_indptr_for_dec_ids.is_empty()
            {
                self.op_indptr_for_dec_ids.push(self.decorator_ids.len());
            }

            self.node_indptr_for_op_idx
                .push(op_start)
                .map_err(|_| DecoratorIndexError::OperationIndex { node, operation: op_start })?;
        } else {
            // Build op->decorator CSR for this node
            let max_op_idx = decorators_info.last().unwrap().0; // input is sorted by op index
            let mut it = decorators_info.into_iter().peekable();

            for op in 0..=max_op_idx {
                // pointer to start of decorator IDs for op
                self.op_indptr_for_dec_ids.push(self.decorator_ids.len());
                while it.peek().is_some_and(|(i, _)| *i == op) {
                    self.decorator_ids.push(it.next().unwrap().1);
                }
            }
            // final sentinel for this node
            self.op_indptr_for_dec_ids.push(self.decorator_ids.len());

            // Push end pointer for this node (index of last op pointer, which is the sentinel)
            // This is len()-1 because we just pushed the sentinel above
            let end_ops = self.op_indptr_for_dec_ids.len() - 1;
            self.node_indptr_for_op_idx
                .push(end_ops)
                .map_err(|_| DecoratorIndexError::OperationIndex { node, operation: end_ops })?;
        }

        Ok(())
    }

    /// Get the number of decorator IDs for a specific operation within a node.
    ///
    /// # Arguments
    /// * `node` - The node ID
    /// * `operation` - The operation index within the node
    ///
    /// # Returns
    /// The number of decorator IDs for the operation, or an error if indices are invalid.
    pub fn num_decorator_ids_for_operation(
        &self,
        node: MastNodeId,
        operation: usize,
    ) -> Result<usize, DecoratorIndexError> {
        self.decorator_ids_for_operation(node, operation).map(|slice| slice.len())
    }

    /// Get all decorator IDs for a specific operation within a node.
    ///
    /// # Arguments
    /// * `node` - The node ID
    /// * `operation` - The operation index within the node
    ///
    /// # Returns
    /// A slice of decorator IDs for the operation, or an error if indices are invalid.
    pub fn decorator_ids_for_operation(
        &self,
        node: MastNodeId,
        operation: usize,
    ) -> Result<&[DecoratorId], DecoratorIndexError> {
        let op_range = self.operation_range_for_node(node)?;
        // that operation does not have listed decorator indices
        if operation >= op_range.len() {
            return Ok(&[]);
        }

        let op_start_idx = op_range.start + operation;
        if op_start_idx + 1 >= self.op_indptr_for_dec_ids.len() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        let dec_start = self.op_indptr_for_dec_ids[op_start_idx];
        let dec_end = self.op_indptr_for_dec_ids[op_start_idx + 1];

        if dec_start > dec_end || dec_end > self.decorator_ids.len() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        Ok(&self.decorator_ids[dec_start..dec_end])
    }

    /// Get an iterator over all operations and their decorator IDs for a given node.
    ///
    /// # Arguments
    /// * `node` - The node ID
    ///
    /// # Returns
    /// An iterator yielding (operation_index, decorator_ids_slice) tuples, or an error if the node
    /// is invalid.
    pub fn decorator_ids_for_node(
        &self,
        node: MastNodeId,
    ) -> Result<impl Iterator<Item = (usize, &[DecoratorId])>, DecoratorIndexError> {
        let op_range = self.operation_range_for_node(node)?;
        let num_ops = op_range.len();

        Ok((0..num_ops).map(move |op_idx| {
            let op_start_idx = op_range.start + op_idx;
            let dec_start = self.op_indptr_for_dec_ids[op_start_idx];
            let dec_end = self.op_indptr_for_dec_ids[op_start_idx + 1];
            (op_idx, &self.decorator_ids[dec_start..dec_end])
        }))
    }

    /// Named, zero-alloc view flattened to `(relative_op_idx, DecoratorId)`.
    pub fn decorator_links_for_node<'a>(
        &'a self,
        node: MastNodeId,
    ) -> Result<DecoratedLinks<'a>, DecoratorIndexError> {
        let op_range = self.operation_range_for_node(node)?; // [start .. end) in op-pointer space
        Ok(DecoratedLinks::new(
            op_range.start,
            op_range.end,
            &self.op_indptr_for_dec_ids,
            &self.decorator_ids,
        ))
    }

    /// Check if a specific operation within a node has any decorator IDs.
    ///
    /// # Arguments
    /// * `node` - The node ID
    /// * `operation` - The operation index within the node
    ///
    /// # Returns
    /// True if the operation has at least one decorator ID, false otherwise, or an error if indices
    /// are invalid.
    pub fn operation_has_decorator_ids(
        &self,
        node: MastNodeId,
        operation: usize,
    ) -> Result<bool, DecoratorIndexError> {
        self.num_decorator_ids_for_operation(node, operation).map(|count| count > 0)
    }

    /// Get the range of operation indices for a given node.
    ///
    /// # Arguments
    /// * `node` - The node ID
    ///
    /// # Returns
    /// A range representing the start and end (exclusive) operation indices for the node.
    pub fn operation_range_for_node(
        &self,
        node: MastNodeId,
    ) -> Result<core::ops::Range<usize>, DecoratorIndexError> {
        let node_slice = self.node_indptr_for_op_idx.as_slice();
        let node_idx = node.to_usize();

        if node_idx + 1 >= node_slice.len() {
            return Err(DecoratorIndexError::NodeIndex(node));
        }

        let start = node_slice[node_idx];
        let end = node_slice[node_idx + 1];

        if start > end || end > self.op_indptr_for_dec_ids.len() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        Ok(start..end)
    }
}

impl Default for OpToDecoratorIds {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable view over all `(op_idx, DecoratorId)` pairs for a node.
/// Uses the two-level CSR encoded by `node_indptr_for_op_idx` and `op_indptr_for_dec_idx`.
pub struct DecoratedLinks<'a> {
    // Absolute op-pointer index range for this node: [start_op .. end_op)
    start_op: usize,
    end_op: usize,

    // CSR arrays (borrowed; not owned)
    op_indptr_for_dec_idx: &'a [usize], // len = total_ops + 1
    decorator_indices: &'a [DecoratorId],
}

impl<'a> DecoratedLinks<'a> {
    fn new(
        start_op: usize,
        end_op: usize,
        op_indptr_for_dec_idx: &'a [usize],
        decorator_indices: &'a [DecoratorId],
    ) -> Self {
        Self {
            start_op,
            end_op,
            op_indptr_for_dec_idx,
            decorator_indices,
        }
    }

    /// Total number of `(op_idx, DecoratorId)` pairs in this view (exact).
    #[inline]
    pub fn len_pairs(&self) -> usize {
        let s = self.op_indptr_for_dec_idx[self.start_op];
        let e = self.op_indptr_for_dec_idx[self.end_op];
        e - s
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len_pairs() == 0
    }
}

/// The concrete, zero-alloc iterator over `(relative_op_idx, DecoratorId)`.
pub struct DecoratedLinksIter<'a> {
    // absolute op-pointer indices (into op_indptr_for_dec_idx)
    cur_op: usize,
    end_op: usize,
    base_op: usize, // for relative index = cur_op - base_op

    // inner slice [inner_i .. inner_end) indexes into decorator_indices
    inner_i: usize,
    inner_end: usize,

    // borrowed CSR arrays
    op_indptr_for_dec_idx: &'a [usize],
    decorator_indices: &'a [DecoratorId],

    // exact count of remaining pairs
    remaining: usize,
}

impl<'a> IntoIterator for DecoratedLinks<'a> {
    type Item = DecoratedOpLink;
    type IntoIter = DecoratedLinksIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        // Precompute the exact number of pairs in the node's range.
        let remaining = {
            // Add bounds check to prevent panic on empty storage
            if self.start_op >= self.op_indptr_for_dec_idx.len()
                || self.end_op > self.op_indptr_for_dec_idx.len()  // Note: end_op can be equal to len
                || self.start_op > self.end_op
            // Invalid range
            {
                0
            } else {
                // For valid ranges, compute the actual number of decorator pairs
                let mut total = 0;
                for op_idx in self.start_op..self.end_op {
                    let start_idx = self.op_indptr_for_dec_idx[op_idx];
                    let end_idx = if op_idx + 1 < self.op_indptr_for_dec_idx.len() {
                        self.op_indptr_for_dec_idx[op_idx + 1]
                    } else {
                        self.op_indptr_for_dec_idx.len()
                    };
                    total += end_idx - start_idx;
                }
                total
            }
        };

        // Initialize inner range to the first op (if any).
        let (inner_i, inner_end) = if self.start_op < self.end_op
            && self.start_op + 1 < self.op_indptr_for_dec_idx.len()
        {
            let s0 = self.op_indptr_for_dec_idx[self.start_op];
            let e0 = self.op_indptr_for_dec_idx[self.start_op + 1];
            (s0, e0)
        } else {
            (0, 0)
        };

        DecoratedLinksIter {
            cur_op: self.start_op,
            end_op: self.end_op,
            base_op: self.start_op,
            inner_i,
            inner_end,
            op_indptr_for_dec_idx: self.op_indptr_for_dec_idx,
            decorator_indices: self.decorator_indices,
            remaining,
        }
    }
}

impl<'a> DecoratedLinksIter<'a> {
    #[inline]
    fn advance_outer(&mut self) -> bool {
        self.cur_op += 1;
        if self.cur_op >= self.end_op {
            return false;
        }
        // Bounds check: ensure cur_op and cur_op+1 are within the pointer array
        if self.cur_op + 1 >= self.op_indptr_for_dec_idx.len() {
            return false;
        }
        let s = self.op_indptr_for_dec_idx[self.cur_op];
        let e = self.op_indptr_for_dec_idx[self.cur_op + 1];
        self.inner_i = s;
        self.inner_end = e;
        true
    }
}

impl<'a> Iterator for DecoratedLinksIter<'a> {
    type Item = DecoratedOpLink;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.cur_op < self.end_op {
            // Emit from current op's decorator slice if non-empty
            if self.inner_i < self.inner_end {
                let rel_op = self.cur_op - self.base_op; // relative op index within the node
                let id = self.decorator_indices[self.inner_i];
                self.inner_i += 1;
                self.remaining -= 1;
                return Some((rel_op, id));
            }
            // Move to next operation (which might be empty as well)
            if !self.advance_outer() {
                break;
            }
        }
        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a> ExactSizeIterator for DecoratedLinksIter<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.remaining
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for OpToDecoratorIds {
    type Parameters = proptest::collection::SizeRange;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(size: Self::Parameters) -> Self::Strategy {
        use proptest::{collection::vec, prelude::*};

        // Generate small, controlled structures to avoid infinite loops
        // Keep node and operation counts small and bounded, always at least 1
        (1usize..40, 1usize..=72) // (max_nodes, max_ops_per_node)
            .prop_flat_map(move |(max_nodes, max_ops_per_node)| {
                vec(
                    // Generate (node_id, op_id, decorator_id) with bounded values
                    (0..max_nodes, 0..max_ops_per_node, any::<u32>()),
                    size.clone(), // Limit total entries to size
                )
                .prop_map(move |coo_data| {
                    // Build the OpToDecoratorIds incrementally
                    let mut mapping = OpToDecoratorIds::new();

                    // Group by node_id, then by op_id to maintain sorted order
                    use alloc::collections::BTreeMap;
                    let mut node_to_ops: BTreeMap<u32, BTreeMap<u32, Vec<u32>>> = BTreeMap::new();

                    for (node_id, op_id, decorator_id) in coo_data {
                        node_to_ops
                            .entry(node_id as u32)
                            .or_default()
                            .entry(op_id as u32)
                            .or_default()
                            .push(decorator_id);
                    }

                    // Add nodes in order to satisfy sequential constraint
                    for (node_id, ops_map) in node_to_ops {
                        let mut decorators_info: Vec<(usize, DecoratorId)> = Vec::new();
                        for (op_id, decorator_ids) in ops_map {
                            for decorator_id in decorator_ids {
                                decorators_info.push((op_id as usize, DecoratorId(decorator_id)));
                            }
                        }
                        // Sort by operation index to meet add_decorator_info_for_node requirements
                        decorators_info.sort_by_key(|(op_idx, _)| *op_idx);

                        mapping
                            .add_decorator_info_for_node(
                                MastNodeId::new_unchecked(node_id),
                                decorators_info,
                            )
                            .unwrap();
                    }

                    mapping
                })
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests;
