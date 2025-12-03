use alloc::vec::Vec;

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
    /// # Returns
    /// An error if the internal structure is inconsistent. Common issues that cause errors:
    /// - Empty `op_indptr_for_dec_ids` or `node_indptr_for_op_idx` vectors
    /// - Non-zero first element in either pointer array
    /// - Decreasing pointer values (pointers must be monotonically non-decreasing)
    /// - Pointer values that exceed the bounds of the arrays they index into
    /// - Invalid ranges (start > end) in any pointer window
    ///
    /// # Validation Restrictions
    /// The following constraints are enforced between components:
    /// - `op_indptr_for_dec_ids` length must be >= 1 (for the sentinel)
    /// - `node_indptr_for_op_idx` length must be >= 1 (for the sentinel)
    /// - Last value in `op_indptr_for_dec_ids` must be <= `decorator_ids.len()`
    /// - Last value in `node_indptr_for_op_idx` must be <= `op_indptr_for_dec_ids.len() - 1`
    /// - Both `op_indptr_for_dec_ids` and `node_indptr_for_op_idx` must be strictly monotonic (each
    ///   successive value must be >= the previous one)
    #[cfg(test)]
    pub fn from_components(
        decorator_ids: Vec<DecoratorId>,
        op_indptr_for_dec_ids: Vec<usize>,
        node_indptr_for_op_idx: IndexVec<MastNodeId, usize>,
    ) -> Result<Self, DecoratorIndexError> {
        // Validate the structure
        if op_indptr_for_dec_ids.is_empty() {
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
        let Some(&last_node_ptr) = node_slice.last() else {
            return Err(DecoratorIndexError::InternalStructure);
        };
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

    pub fn is_empty(&self) -> bool {
        self.node_indptr_for_op_idx.is_empty()
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
            // Empty node: no operations at all, just set the end pointer equal to start
            // This creates a node with an empty operations range
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

            // Push end pointer for this node (index of last op pointer)
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

    /// Helper to create standard test storage with 2 nodes, 3 operations, 6 decorator IDs
    /// Structure: Node 0: Op 0 -> [0, 1], Op 1 -> [2]; Node 1: Op 0 -> [3, 4, 5]
    fn create_standard_test_storage() -> OpToDecoratorIds {
        let decorator_ids = vec![
            test_decorator_id(0),
            test_decorator_id(1),
            test_decorator_id(2),
            test_decorator_id(3),
            test_decorator_id(4),
            test_decorator_id(5),
        ];
        let op_indptr_for_dec_ids = vec![0, 2, 3, 6];
        let mut node_indptr_for_op_idx = IndexVec::new();
        node_indptr_for_op_idx.push(0).expect("test setup: IndexVec capacity exceeded");
        node_indptr_for_op_idx.push(2).expect("test setup: IndexVec capacity exceeded");
        node_indptr_for_op_idx.push(3).expect("test setup: IndexVec capacity exceeded");

        OpToDecoratorIds::from_components(
            decorator_ids,
            op_indptr_for_dec_ids,
            node_indptr_for_op_idx,
        )
        .unwrap()
    }

    #[test]
    fn test_constructors() {
        // Test new()
        let storage = OpToDecoratorIds::new();
        assert_eq!(storage.num_nodes(), 0);
        assert_eq!(storage.num_decorator_ids(), 0);

        // Test with_capacity()
        let storage = OpToDecoratorIds::with_capacity(10, 20, 30);
        assert_eq!(storage.num_nodes(), 0);
        assert_eq!(storage.num_decorator_ids(), 0);

        // Test default()
        let storage = OpToDecoratorIds::default();
        assert_eq!(storage.num_nodes(), 0);
        assert_eq!(storage.num_decorator_ids(), 0);
    }

    #[test]
    fn test_from_components_simple() {
        // Create a simple structure:
        // Node 0: Op 0 -> [0, 1], Op 1 -> [2]
        // Node 1: Op 0 -> [3, 4, 5]
        let storage = create_standard_test_storage();

        assert_eq!(storage.num_nodes(), 2);
        assert_eq!(storage.num_decorator_ids(), 6);
    }

    #[test]
    fn test_from_components_invalid_structure() {
        // Test with empty operation pointers
        let result = OpToDecoratorIds::from_components(vec![], vec![], IndexVec::new());
        assert_eq!(result, Err(DecoratorIndexError::InternalStructure));

        // Test with operation pointer exceeding decorator indices
        let result = OpToDecoratorIds::from_components(
            vec![test_decorator_id(0)],
            vec![0, 2], // Points to index 2 but we only have 1 decorator
            IndexVec::new(),
        );
        assert_eq!(result, Err(DecoratorIndexError::InternalStructure));

        // Test with non-monotonic operation pointers
        let result = OpToDecoratorIds::from_components(
            vec![test_decorator_id(0), test_decorator_id(1)],
            vec![0, 2, 1], // 2 > 1, should be monotonic
            IndexVec::new(),
        );
        assert_eq!(result, Err(DecoratorIndexError::InternalStructure));
    }

    #[test]
    fn test_data_access_methods() {
        let storage = create_standard_test_storage();

        // Test decorator_ids_for_operation
        let decorators = storage.decorator_ids_for_operation(test_node_id(0), 0).unwrap();
        assert_eq!(decorators, &[test_decorator_id(0), test_decorator_id(1)]);

        let decorators = storage.decorator_ids_for_operation(test_node_id(0), 1).unwrap();
        assert_eq!(decorators, &[test_decorator_id(2)]);

        let decorators = storage.decorator_ids_for_operation(test_node_id(1), 0).unwrap();
        assert_eq!(decorators, &[test_decorator_id(3), test_decorator_id(4), test_decorator_id(5)]);

        // Test decorator_ids_for_node
        let decorators: Vec<_> = storage.decorator_ids_for_node(test_node_id(0)).unwrap().collect();
        assert_eq!(decorators.len(), 2);
        assert_eq!(decorators[0], (0, &[test_decorator_id(0), test_decorator_id(1)][..]));
        assert_eq!(decorators[1], (1, &[test_decorator_id(2)][..]));

        let decorators: Vec<_> = storage.decorator_ids_for_node(test_node_id(1)).unwrap().collect();
        assert_eq!(decorators.len(), 1);
        assert_eq!(
            decorators[0],
            (0, &[test_decorator_id(3), test_decorator_id(4), test_decorator_id(5)][..])
        );

        // Test operation_has_decorator_ids
        assert!(storage.operation_has_decorator_ids(test_node_id(0), 0).unwrap());
        assert!(storage.operation_has_decorator_ids(test_node_id(0), 1).unwrap());
        assert!(storage.operation_has_decorator_ids(test_node_id(1), 0).unwrap());
        assert!(!storage.operation_has_decorator_ids(test_node_id(0), 2).unwrap());

        // Test num_decorator_ids_for_operation
        assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(0), 0).unwrap(), 2);
        assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(0), 1).unwrap(), 1);
        assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(1), 0).unwrap(), 3);
        assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(0), 2).unwrap(), 0);

        // Test invalid operation returns empty slice
        let decorators = storage.decorator_ids_for_operation(test_node_id(0), 2).unwrap();
        assert_eq!(decorators, &[]);
    }

    #[test]
    fn test_empty_nodes_basic_functionality() {
        // Test 1: Empty nodes created via from_components (original
        // test_empty_nodes_and_operations)
        {
            // Create a structure with empty nodes/operations
            let decorator_indices = vec![];
            let op_indptr_for_dec_idx = vec![0, 0, 0]; // 2 operations, both empty
            let mut node_indptr_for_op_idx = IndexVec::new();
            node_indptr_for_op_idx.push(0).expect("test setup: IndexVec capacity exceeded");
            node_indptr_for_op_idx.push(2).expect("test setup: IndexVec capacity exceeded");

            let storage = OpToDecoratorIds::from_components(
                decorator_indices,
                op_indptr_for_dec_idx,
                node_indptr_for_op_idx,
            )
            .unwrap();

            assert_eq!(storage.num_nodes(), 1);
            assert_eq!(storage.num_decorator_ids(), 0);

            // Empty decorators
            let decorators = storage.decorator_ids_for_operation(test_node_id(0), 0).unwrap();
            assert_eq!(decorators, &[]);

            // Operation has no decorators
            assert!(!storage.operation_has_decorator_ids(test_node_id(0), 0).unwrap());
        }

        // Test 2: Empty nodes created via add_decorator_info_for_node (original
        // test_decorator_ids_for_node_with_empty_nodes)
        {
            let mut storage = OpToDecoratorIds::new();

            // Add node 0 with no decorators (empty node)
            storage.add_decorator_info_for_node(test_node_id(0), vec![]).unwrap();

            // Test 2a: operation_range_for_node should be empty for node with no decorators
            let range = storage.operation_range_for_node(test_node_id(0));
            assert!(range.is_ok(), "operation_range_for_node should return Ok for empty node");
            let range = range.unwrap();
            assert_eq!(range, 0..0, "Empty node should have empty operations range");

            // Test 2b: decorator_ids_for_node should return an empty iterator
            let result = storage.decorator_ids_for_node(test_node_id(0));
            assert!(result.is_ok(), "decorator_ids_for_node should return Ok for empty node");
            // The iterator should be empty
            let decorators: Vec<_> = result.unwrap().collect();
            assert_eq!(decorators, Vec::<(usize, &[DecoratorId])>::new());

            // Test 2c: decorator_links_for_node should return an empty iterator
            let result = storage.decorator_links_for_node(test_node_id(0));
            assert!(result.is_ok(), "decorator_links_for_node should return Ok for empty node");
            let links: Vec<_> = result.unwrap().into_iter().collect();
            assert_eq!(links, Vec::<(usize, DecoratorId)>::new());

            // Test 2d: Basic access methods on empty node
            assert_eq!(storage.num_nodes(), 1);
            assert_eq!(storage.num_decorator_ids(), 0);
        }
    }

    #[test]
    fn test_debug_impl() {
        let storage = OpToDecoratorIds::new();
        let debug_str = format!("{:?}", storage);
        assert!(debug_str.contains("OpToDecoratorIds"));
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
        node_indptr_for_op_idx.push(0).expect("test setup: IndexVec capacity exceeded");
        node_indptr_for_op_idx.push(2).expect("test setup: IndexVec capacity exceeded");
        node_indptr_for_op_idx.push(3).expect("test setup: IndexVec capacity exceeded");

        let storage1 = OpToDecoratorIds::from_components(
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
        different_node_indptr.push(0).expect("test setup: IndexVec capacity exceeded");
        different_node_indptr.push(1).expect("test setup: IndexVec capacity exceeded");

        let storage3 = OpToDecoratorIds::from_components(
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
        let mut storage = OpToDecoratorIds::new();

        // Add decorators for node 0
        let decorators_info = vec![
            (0, test_decorator_id(10)),
            (0, test_decorator_id(11)),
            (2, test_decorator_id(12)),
        ];
        storage.add_decorator_info_for_node(test_node_id(0), decorators_info).unwrap();

        assert_eq!(storage.num_nodes(), 1);
        assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(0), 0).unwrap(), 2);
        assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(0), 2).unwrap(), 1);

        // Add node 1 with simple decorators
        storage
            .add_decorator_info_for_node(test_node_id(1), vec![(0, test_decorator_id(20))])
            .unwrap();
        assert_eq!(storage.num_nodes(), 2);

        let node1_op0 = storage.decorator_ids_for_operation(test_node_id(1), 0).unwrap();
        assert_eq!(node1_op0, &[test_decorator_id(20)]);

        // Test 2: Sequential constraint validation
        let mut storage2 = OpToDecoratorIds::new();
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
        assert_eq!(result, Err(DecoratorIndexError::NodeIndex(test_node_id(0))));

        // Test 3: Empty input handling (creates empty nodes with no operations)
        let mut storage3 = OpToDecoratorIds::new();
        let result = storage3.add_decorator_info_for_node(test_node_id(0), vec![]);
        assert_eq!(result, Ok(()));
        assert_eq!(storage3.num_nodes(), 1); // Should create empty node

        // Empty node should have no operations (accessing any operation should return empty)
        let decorators = storage3.decorator_ids_for_operation(test_node_id(0), 0).unwrap();
        assert_eq!(decorators, &[]);

        // Should be able to add next node after empty node
        storage3
            .add_decorator_info_for_node(test_node_id(1), vec![(0, test_decorator_id(100))])
            .unwrap();
        assert_eq!(storage3.num_nodes(), 2);

        // Test 4: Operations with gaps
        let mut storage4 = OpToDecoratorIds::new();
        let gap_decorators = vec![
            (0, test_decorator_id(10)),
            (0, test_decorator_id(11)), // operation 0 has 2 decorators
            (3, test_decorator_id(12)), // operation 3 has 1 decorator
            (4, test_decorator_id(13)), // operation 4 has 1 decorator
        ];
        storage4.add_decorator_info_for_node(test_node_id(0), gap_decorators).unwrap();

        assert_eq!(storage4.num_decorator_ids_for_operation(test_node_id(0), 0).unwrap(), 2);
        assert_eq!(storage4.num_decorator_ids_for_operation(test_node_id(0), 1).unwrap(), 0);
        assert_eq!(storage4.num_decorator_ids_for_operation(test_node_id(0), 2).unwrap(), 0);
        assert_eq!(storage4.num_decorator_ids_for_operation(test_node_id(0), 3).unwrap(), 1);
        assert_eq!(storage4.num_decorator_ids_for_operation(test_node_id(0), 4).unwrap(), 1);

        // Test accessing operations without decorators returns empty slice
        let op1_decorators = storage4.decorator_ids_for_operation(test_node_id(0), 1).unwrap();
        assert_eq!(op1_decorators, &[]);

        // Test 5: Your specific use case - mixed empty and non-empty nodes
        let mut storage5 = OpToDecoratorIds::new();

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
            storage5.decorator_ids_for_operation(test_node_id(0), 0).unwrap(),
            &[test_decorator_id(1)]
        );
        assert_eq!(
            storage5.decorator_ids_for_operation(test_node_id(0), 1).unwrap(),
            &[test_decorator_id(0)]
        );

        // Verify node 1: has no operations at all, any operation access returns empty
        assert_eq!(storage5.decorator_ids_for_operation(test_node_id(1), 0).unwrap(), &[]);

        // Verify node 2: op 0 has [], op 1 has [1], op 2 has [2]
        assert_eq!(storage5.decorator_ids_for_operation(test_node_id(2), 0).unwrap(), &[]);
        assert_eq!(
            storage5.decorator_ids_for_operation(test_node_id(2), 1).unwrap(),
            &[test_decorator_id(1)]
        );
        assert_eq!(
            storage5.decorator_ids_for_operation(test_node_id(2), 2).unwrap(),
            &[test_decorator_id(2)]
        );
    }

    #[test]
    fn test_empty_nodes_edge_cases() {
        // Test edge cases with empty nodes (nodes with no decorators)
        // This consolidates test_decorator_ids_for_node_mixed_scenario and
        // test_decorated_links_overflow_bug

        let mut storage = OpToDecoratorIds::new();

        // Set up mixed scenario: some nodes have decorators, some don't
        // Node 0: Has decorators
        storage
            .add_decorator_info_for_node(
                test_node_id(0),
                vec![(0, test_decorator_id(10)), (2, test_decorator_id(20))],
            )
            .unwrap();

        // Node 1: Has decorators
        storage
            .add_decorator_info_for_node(
                test_node_id(1),
                vec![
                    (0, test_decorator_id(30)),
                    (0, test_decorator_id(31)),
                    (3, test_decorator_id(32)),
                ],
            )
            .unwrap();

        // Node 2: No decorators (empty node) - this is the edge case we're testing
        storage.add_decorator_info_for_node(test_node_id(2), vec![]).unwrap();

        // Test 1: Verify range handling for empty nodes
        let range0 = storage.operation_range_for_node(test_node_id(0)).unwrap();
        let range1 = storage.operation_range_for_node(test_node_id(1)).unwrap();
        let range2 = storage.operation_range_for_node(test_node_id(2)).unwrap();

        // Nodes with decorators should have non-empty ranges
        assert!(range0.end > range0.start, "Node with decorators should have non-empty range");
        assert!(range1.end > range1.start, "Node with decorators should have non-empty range");

        // Empty node should have range pointing to the end of op_indptr_for_dec_ids array
        // This is expected behavior: empty nodes get the range at the end of the array
        let op_indptr_len = storage.op_indptr_for_dec_ids.len();
        assert_eq!(
            range2.start, op_indptr_len,
            "Empty node should point to end of op_indptr array"
        );
        assert_eq!(range2.end, op_indptr_len, "Empty node should have empty range at array end");

        // Test 2: decorator_ids_for_node() should work for empty nodes
        // This should not panic - the iterator should be empty even though the range points to
        // array end
        let result = storage.decorator_ids_for_node(test_node_id(2));
        assert!(result.is_ok(), "decorator_ids_for_node should work for node with no decorators");
        let decorators: Vec<_> = result.unwrap().collect();
        assert_eq!(decorators, Vec::<(usize, &[DecoratorId])>::new());

        // Test 3: decorator_links_for_node() should work for empty nodes (tests overflow bug)
        // This tests the specific overflow bug in DecoratedLinks iterator
        let result = storage.decorator_links_for_node(test_node_id(2));
        assert!(result.is_ok(), "decorator_links_for_node should return Ok for empty node");

        let links = result.unwrap();
        // This should not panic, even when iterating
        let collected: Vec<_> = links.into_iter().collect();
        assert_eq!(collected, Vec::<(usize, DecoratorId)>::new());

        // Test 4: Multiple iterations should work (regression test for iterator reuse)
        let result2 = storage.decorator_links_for_node(test_node_id(2));
        assert!(
            result2.is_ok(),
            "decorator_links_for_node should work repeatedly for empty node"
        );
        let links2 = result2.unwrap();
        let collected2: Vec<_> = links2.into_iter().collect();
        assert_eq!(collected2, Vec::<(usize, DecoratorId)>::new());

        // Test 5: Multiple iterations of decorator_ids_for_node should also work
        let result3 = storage.decorator_ids_for_node(test_node_id(2));
        assert!(result3.is_ok(), "decorator_ids_for_node should work repeatedly for empty node");
        let decorators2: Vec<_> = result3.unwrap().collect();
        assert_eq!(decorators2, Vec::<(usize, &[DecoratorId])>::new());
    }

    #[test]
    fn test_decorator_links_for_node_flattened() {
        let storage = create_standard_test_storage();
        let n0 = MastNodeId::new_unchecked(0);
        let flat: Vec<_> = storage.decorator_links_for_node(n0).unwrap().into_iter().collect();
        // Node 0: Op0 -> [0,1], Op1 -> [2]
        assert_eq!(flat, vec![(0, DecoratorId(0)), (0, DecoratorId(1)), (1, DecoratorId(2)),]);

        let n1 = MastNodeId::new_unchecked(1);
        let flat1: Vec<_> = storage.decorator_links_for_node(n1).unwrap().into_iter().collect();
        // Node 1: Op0 -> [3,4,5]
        assert_eq!(flat1, vec![(0, DecoratorId(3)), (0, DecoratorId(4)), (0, DecoratorId(5)),]);
    }

    #[test]
    /// This test verifies that the CSR encoding described in the OpToDecoratorIds struct
    /// documentation correctly represents COO data. It also validates all accessor methods
    /// work as expected. Keep this test in sync with the documentation example (adding nodes
    /// to this test if you add nodes to the documentation example, and vice versa).
    fn test_csr_and_coo_produce_same_elements() {
        // Build a COO representation manually
        let coo_data = vec![
            // Node 0
            (MastNodeId::new_unchecked(0), 0, DecoratorId(10)),
            (MastNodeId::new_unchecked(0), 0, DecoratorId(11)),
            (MastNodeId::new_unchecked(0), 1, DecoratorId(12)),
            (MastNodeId::new_unchecked(0), 2, DecoratorId(13)),
            // Node 1
            (MastNodeId::new_unchecked(1), 0, DecoratorId(20)),
            (MastNodeId::new_unchecked(1), 2, DecoratorId(21)),
            (MastNodeId::new_unchecked(1), 2, DecoratorId(22)),
            // Node 2 (empty node, should still work)
            // Node 3
            (MastNodeId::new_unchecked(3), 0, DecoratorId(30)),
        ];

        // Build COO representation as a HashMap for easy lookup during verification
        let mut coo_map: alloc::collections::BTreeMap<(MastNodeId, usize), Vec<DecoratorId>> =
            alloc::collections::BTreeMap::new();
        for (node, op_idx, decorator_id) in &coo_data {
            coo_map.entry((*node, *op_idx)).or_default().push(*decorator_id);
        }

        // Build CSR representation using the builder API
        let mut csr_storage = OpToDecoratorIds::new();

        // Node 0: Op0 -> [10,11], Op1 -> [12], Op2 -> [13]
        csr_storage
            .add_decorator_info_for_node(
                MastNodeId::new_unchecked(0),
                vec![
                    (0, DecoratorId(10)),
                    (0, DecoratorId(11)),
                    (1, DecoratorId(12)),
                    (2, DecoratorId(13)),
                ],
            )
            .unwrap();

        // Node 1: Op0 -> [20], Op2 -> [21,22]
        csr_storage
            .add_decorator_info_for_node(
                MastNodeId::new_unchecked(1),
                vec![(0, DecoratorId(20)), (2, DecoratorId(21)), (2, DecoratorId(22))],
            )
            .unwrap();

        // Node 2: empty
        csr_storage
            .add_decorator_info_for_node(MastNodeId::new_unchecked(2), vec![])
            .unwrap();

        // Node 3: Op0 -> [30]
        csr_storage
            .add_decorator_info_for_node(MastNodeId::new_unchecked(3), vec![(0, DecoratorId(30))])
            .unwrap();

        // Verify that CSR and COO produce the same elements
        for node_idx in 0..4 {
            let node_id = MastNodeId::new_unchecked(node_idx);

            // Get all operations for this node from CSR
            let op_range = csr_storage.operation_range_for_node(node_id).unwrap();
            let num_ops = op_range.len();

            // For each operation in this node
            for op_idx in 0..num_ops {
                // Get decorator IDs from CSR
                let csr_decorator_ids =
                    csr_storage.decorator_ids_for_operation(node_id, op_idx).unwrap();

                // Get decorator IDs from COO map
                let coo_key = (node_id, op_idx);
                let coo_decorator_ids =
                    coo_map.get(&coo_key).map_or(&[] as &[DecoratorId], |v| v.as_slice());

                // They should be the same
                assert_eq!(
                    csr_decorator_ids, coo_decorator_ids,
                    "CSR and COO should produce the same decorator IDs for node {:?}, op {}",
                    node_id, op_idx
                );
            }
        }

        // Also verify using the flattened iterator approach
        for node_idx in 0..4 {
            let node_id = MastNodeId::new_unchecked(node_idx);

            // Get flattened view from CSR
            let csr_flat: Vec<(usize, DecoratorId)> =
                csr_storage.decorator_links_for_node(node_id).unwrap().into_iter().collect();

            // Build expected from COO map
            let mut expected_flat = Vec::new();
            for ((node, op_idx), decorator_ids) in &coo_map {
                if *node == node_id {
                    for decorator_id in decorator_ids {
                        expected_flat.push((*op_idx, *decorator_id));
                    }
                }
            }
            // Sort by operation index then decorator ID for consistent comparison
            expected_flat.sort_by_key(|(op_idx, dec_id)| (*op_idx, u32::from(*dec_id)));

            assert_eq!(
                csr_flat, expected_flat,
                "Flattened CSR and COO should produce the same elements for node {:?}",
                node_id
            );
        }
    }

    #[cfg(feature = "arbitrary")]
    proptest! {
        /// Property test that verifies decorator_links_for_node always produces a valid iterator
        /// that can be fully consumed without panicking for any OpToDecoratorIds.
        #[test]
        fn decorator_links_for_node_always_iterates_complete(
            mapping in any::<OpToDecoratorIds>()
        ) {
            // Skip empty mappings since they have no nodes to test
            if mapping.num_nodes() == 0 {
                return Ok(());
            }

            // Test every valid node in the mapping
            for node_idx in 0..mapping.num_nodes() {
                let node_id = MastNodeId::new_unchecked(node_idx as u32);

                // Call decorator_links_for_node - this should never return an error for valid nodes
                let result = mapping.decorator_links_for_node(node_id);

                // The result should always be Ok for valid node indices
                prop_assume!(result.is_ok(), "decorator_links_for_node should succeed for valid node");

                let decorated_links = result.unwrap();

                // Convert to iterator and collect all items - this should complete without panicking
                let collected: Vec<(usize, DecoratorId)> = decorated_links.into_iter().collect();

                // The collected items should match what we get from decorator_ids_for_node
                let expected_items: Vec<(usize, DecoratorId)> = mapping
                    .decorator_ids_for_node(node_id)
                    .unwrap()
                    .flat_map(|(op_idx, decorator_ids)| {
                        decorator_ids.iter().map(move |&decorator_id| (op_idx, decorator_id))
                    })
                    .collect();

                prop_assert_eq!(collected, expected_items);
            }
        }
    }
}
