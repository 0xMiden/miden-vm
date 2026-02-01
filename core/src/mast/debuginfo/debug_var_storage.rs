//! Dedicated storage for DebugVar decorators in a compressed sparse row (CSR) format.
//!
//! This module provides efficient storage and access for debug variable information,
//! separate from the main decorator storage. This allows debuggers to efficiently
//! query variable information without iterating through all decorators.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use miden_utils_indexing::{Idx, IndexVec};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::DecoratorIndexError;
use crate::{
    mast::MastNodeId,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// DEBUG VAR ID
// ================================================================================================

/// An identifier for a debug variable stored in [DebugInfo](super::DebugInfo).
///
/// This is analogous to [DecoratorId](crate::mast::DecoratorId) but specifically for debug
/// variable information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugVarId(u32);

impl DebugVarId {
    /// Returns a new `DebugVarId` with the provided inner value, or an error if the provided
    /// `value` is greater than or equal to `bound`.
    pub fn from_u32_bounded(value: u32, bound: usize) -> Result<Self, DeserializationError> {
        if (value as usize) < bound {
            Ok(Self(value))
        } else {
            Err(DeserializationError::InvalidValue(format!(
                "DebugVarId {} exceeds bound {}",
                value, bound
            )))
        }
    }

    /// Returns the inner value as a usize.
    pub fn to_usize(self) -> usize {
        self.0 as usize
    }

    /// Returns the inner value as a u32.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl Idx for DebugVarId {}

impl From<u32> for DebugVarId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<DebugVarId> for u32 {
    fn from(value: DebugVarId) -> Self {
        value.0
    }
}

impl Serializable for DebugVarId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }
}

impl Deserializable for DebugVarId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = u32::read_from(source)?;
        Ok(Self(value))
    }
}

// OP TO DEBUG VAR IDS
// ================================================================================================

/// A two-level compressed sparse row (CSR) representation for indexing debug variable IDs
/// per operation per node.
///
/// This structure is analogous to [OpToDecoratorIds](super::OpToDecoratorIds) but specifically for
/// debug variable information. It provides efficient access to debug variables in a hierarchical
/// manner:
/// 1. First level: Node -> Operations
/// 2. Second level: Operation -> DebugVarIds
///
/// The actual `DebugVarInfo` values are stored separately in the `debug_vars` field of
/// `DebugInfo`, indexed by `DebugVarId`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OpToDebugVarIds {
    /// All the debug var IDs per operation per node
    debug_var_ids: Vec<DebugVarId>,
    /// Pointer indices for operations within debug_var_ids
    op_indptr_for_var_ids: Vec<usize>,
    /// Pointer indices for nodes within op_indptr_for_var_ids
    node_indptr_for_op_idx: IndexVec<MastNodeId, usize>,
}

impl OpToDebugVarIds {
    /// Create a new empty OpToDebugVarIds.
    pub fn new() -> Self {
        Self::with_capacity(0, 0, 0)
    }

    /// Create a new empty OpToDebugVarIds with the specified capacity.
    pub fn with_capacity(
        nodes_capacity: usize,
        operations_capacity: usize,
        debug_var_ids_capacity: usize,
    ) -> Self {
        Self {
            debug_var_ids: Vec::with_capacity(debug_var_ids_capacity),
            op_indptr_for_var_ids: Vec::with_capacity(operations_capacity + 1),
            node_indptr_for_op_idx: IndexVec::with_capacity(nodes_capacity + 1),
        }
    }

    /// Create an OpToDebugVarIds from raw CSR components.
    pub(super) fn from_components(
        debug_var_ids: Vec<DebugVarId>,
        op_indptr_for_var_ids: Vec<usize>,
        node_indptr_for_op_idx: IndexVec<MastNodeId, usize>,
    ) -> Result<Self, DecoratorIndexError> {
        // Completely empty structures are valid
        if debug_var_ids.is_empty()
            && op_indptr_for_var_ids.is_empty()
            && node_indptr_for_op_idx.is_empty()
        {
            return Ok(Self {
                debug_var_ids,
                op_indptr_for_var_ids,
                node_indptr_for_op_idx,
            });
        }

        // Nodes with no debug vars are valid
        if debug_var_ids.is_empty() && op_indptr_for_var_ids.is_empty() {
            if node_indptr_for_op_idx.iter().all(|&ptr| ptr == 0) {
                return Ok(Self {
                    debug_var_ids,
                    op_indptr_for_var_ids,
                    node_indptr_for_op_idx,
                });
            } else {
                return Err(DecoratorIndexError::InternalStructure);
            }
        }

        // Validate the structure
        if op_indptr_for_var_ids.is_empty() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        if op_indptr_for_var_ids[0] != 0 {
            return Err(DecoratorIndexError::InternalStructure);
        }

        let Some(&last_op_ptr) = op_indptr_for_var_ids.last() else {
            return Err(DecoratorIndexError::InternalStructure);
        };
        if last_op_ptr > debug_var_ids.len() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        if node_indptr_for_op_idx.is_empty() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        let node_slice = node_indptr_for_op_idx.as_slice();

        if node_slice[0] != 0 {
            return Err(DecoratorIndexError::InternalStructure);
        }

        let Some(&last_node_ptr) = node_slice.last() else {
            return Err(DecoratorIndexError::InternalStructure);
        };
        if last_node_ptr > op_indptr_for_var_ids.len() - 1 {
            return Err(DecoratorIndexError::InternalStructure);
        }

        // Ensure monotonicity
        for window in op_indptr_for_var_ids.windows(2) {
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
            debug_var_ids,
            op_indptr_for_var_ids,
            node_indptr_for_op_idx,
        })
    }

    /// Validate CSR structure integrity.
    pub(super) fn validate_csr(&self, debug_var_count: usize) -> Result<(), String> {
        // Completely empty structures are valid
        if self.debug_var_ids.is_empty()
            && self.op_indptr_for_var_ids.is_empty()
            && self.node_indptr_for_op_idx.is_empty()
        {
            return Ok(());
        }

        // Nodes with no debug vars are valid
        if self.debug_var_ids.is_empty() && self.op_indptr_for_var_ids.is_empty() {
            if !self.node_indptr_for_op_idx.iter().all(|&ptr| ptr == 0) {
                return Err("node pointers must all be 0 when there are no debug vars".to_string());
            }
            return Ok(());
        }

        // Validate all debug var IDs
        for &var_id in &self.debug_var_ids {
            if var_id.to_usize() >= debug_var_count {
                return Err(format!(
                    "Invalid debug var ID {}: exceeds count {}",
                    var_id.to_usize(),
                    debug_var_count
                ));
            }
        }

        // Validate op_indptr_for_var_ids
        if self.op_indptr_for_var_ids.is_empty() {
            return Err("op_indptr_for_var_ids cannot be empty".to_string());
        }

        if self.op_indptr_for_var_ids[0] != 0 {
            return Err("op_indptr_for_var_ids must start at 0".to_string());
        }

        for window in self.op_indptr_for_var_ids.windows(2) {
            if window[0] > window[1] {
                return Err(format!(
                    "op_indptr_for_var_ids not monotonic: {} > {}",
                    window[0], window[1]
                ));
            }
        }

        if *self.op_indptr_for_var_ids.last().unwrap() != self.debug_var_ids.len() {
            return Err(format!(
                "op_indptr_for_var_ids end {} doesn't match debug_var_ids length {}",
                self.op_indptr_for_var_ids.last().unwrap(),
                self.debug_var_ids.len()
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

        let max_node_ptr = self.op_indptr_for_var_ids.len() - 1;
        if *node_slice.last().unwrap() > max_node_ptr {
            return Err(format!(
                "node_indptr_for_op_idx end {} exceeds op_indptr bounds {}",
                node_slice.last().unwrap(),
                max_node_ptr
            ));
        }

        Ok(())
    }

    /// Returns true if this storage is empty.
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

    /// Get the total number of debug var IDs.
    pub fn num_debug_var_ids(&self) -> usize {
        self.debug_var_ids.len()
    }

    /// Add debug variable information for a node incrementally.
    ///
    /// This method allows building up the structure by adding debug var IDs for nodes
    /// in sequential order only.
    pub fn add_debug_var_info_for_node(
        &mut self,
        node: MastNodeId,
        debug_vars_info: Vec<(usize, DebugVarId)>,
    ) -> Result<(), DecoratorIndexError> {
        // Enforce sequential node ids
        let expected = MastNodeId::new_unchecked(self.num_nodes() as u32);
        if node < expected {
            return Err(DecoratorIndexError::NodeIndex(node));
        }
        // Create empty nodes for gaps
        for idx in expected.0..node.0 {
            self.add_debug_var_info_for_node(MastNodeId::new_unchecked(idx), vec![])
                .unwrap();
        }

        let op_start = self.op_indptr_for_var_ids.len();

        if self.node_indptr_for_op_idx.is_empty() {
            self.node_indptr_for_op_idx
                .push(op_start)
                .map_err(|_| DecoratorIndexError::OperationIndex { node, operation: op_start })?;
        } else {
            let last = MastNodeId::new_unchecked((self.node_indptr_for_op_idx.len() - 1) as u32);
            self.node_indptr_for_op_idx[last] = op_start;
        }

        if debug_vars_info.is_empty() {
            if op_start == self.op_indptr_for_var_ids.len()
                && !self.op_indptr_for_var_ids.is_empty()
            {
                self.op_indptr_for_var_ids.push(self.debug_var_ids.len());
            }

            self.node_indptr_for_op_idx
                .push(op_start)
                .map_err(|_| DecoratorIndexError::OperationIndex { node, operation: op_start })?;
        } else {
            let max_op_idx = debug_vars_info.last().unwrap().0;
            let mut it = debug_vars_info.into_iter().peekable();

            for op in 0..=max_op_idx {
                self.op_indptr_for_var_ids.push(self.debug_var_ids.len());
                while it.peek().is_some_and(|(i, _)| *i == op) {
                    self.debug_var_ids.push(it.next().unwrap().1);
                }
            }
            self.op_indptr_for_var_ids.push(self.debug_var_ids.len());

            let end_ops = self.op_indptr_for_var_ids.len() - 1;
            self.node_indptr_for_op_idx
                .push(end_ops)
                .map_err(|_| DecoratorIndexError::OperationIndex { node, operation: end_ops })?;
        }

        Ok(())
    }

    /// Get all debug var IDs for a specific operation within a node.
    pub fn debug_var_ids_for_operation(
        &self,
        node: MastNodeId,
        operation: usize,
    ) -> Result<&[DebugVarId], DecoratorIndexError> {
        let op_range = self.operation_range_for_node(node)?;
        if operation >= op_range.len() {
            return Ok(&[]);
        }

        let op_start_idx = op_range.start + operation;
        if op_start_idx + 1 >= self.op_indptr_for_var_ids.len() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        let var_start = self.op_indptr_for_var_ids[op_start_idx];
        let var_end = self.op_indptr_for_var_ids[op_start_idx + 1];

        if var_start > var_end || var_end > self.debug_var_ids.len() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        Ok(&self.debug_var_ids[var_start..var_end])
    }

    /// Get the range of operation indices for a given node.
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

        if start > end || end > self.op_indptr_for_var_ids.len() {
            return Err(DecoratorIndexError::InternalStructure);
        }

        Ok(start..end)
    }

    /// Serialize this OpToDebugVarIds.
    pub(super) fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.debug_var_ids.write_into(target);
        self.op_indptr_for_var_ids.write_into(target);
        self.node_indptr_for_op_idx.write_into(target);
    }

    /// Deserialize OpToDebugVarIds.
    pub(super) fn read_from<R: ByteReader>(
        source: &mut R,
        debug_var_count: usize,
    ) -> Result<Self, DeserializationError> {
        let debug_var_ids: Vec<DebugVarId> = Deserializable::read_from(source)?;
        let op_indptr_for_var_ids: Vec<usize> = Deserializable::read_from(source)?;
        let node_indptr_for_op_idx: IndexVec<MastNodeId, usize> =
            Deserializable::read_from(source)?;

        let result =
            Self::from_components(debug_var_ids, op_indptr_for_var_ids, node_indptr_for_op_idx)
                .map_err(|e| DeserializationError::InvalidValue(e.to_string()))?;

        result.validate_csr(debug_var_count).map_err(|e| {
            DeserializationError::InvalidValue(format!("OpToDebugVarIds validation failed: {e}"))
        })?;

        Ok(result)
    }

    /// Clears this storage.
    pub fn clear(&mut self) {
        self.debug_var_ids.clear();
        self.op_indptr_for_var_ids.clear();
        self.node_indptr_for_op_idx = IndexVec::new();
    }
}

impl Default for OpToDebugVarIds {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_utils_indexing::IndexVec;

    use super::*;

    fn test_var_id(value: u32) -> DebugVarId {
        DebugVarId::from(value)
    }

    fn test_node_id(value: u32) -> MastNodeId {
        MastNodeId::new_unchecked(value)
    }

    /// Helper: Node 0: Op 0 -> [var0, var1], Op 1 -> [var2]; Node 1: Op 0 -> [var3, var4, var5]
    fn create_test_storage() -> OpToDebugVarIds {
        let debug_var_ids = vec![
            test_var_id(0),
            test_var_id(1),
            test_var_id(2),
            test_var_id(3),
            test_var_id(4),
            test_var_id(5),
        ];
        let op_indptr = vec![0, 2, 3, 6];
        let mut node_indptr = IndexVec::new();
        node_indptr.push(0).unwrap();
        node_indptr.push(2).unwrap();
        node_indptr.push(3).unwrap();

        OpToDebugVarIds::from_components(debug_var_ids, op_indptr, node_indptr).unwrap()
    }

    #[test]
    fn test_add_and_lookup() {
        let mut storage = OpToDebugVarIds::new();

        // Node 0: op 0 -> [var10, var11], op 2 -> [var12]
        storage
            .add_debug_var_info_for_node(
                test_node_id(0),
                vec![(0, test_var_id(10)), (0, test_var_id(11)), (2, test_var_id(12))],
            )
            .unwrap();

        // Node 1: op 0 -> [var20]
        storage
            .add_debug_var_info_for_node(test_node_id(1), vec![(0, test_var_id(20))])
            .unwrap();

        assert_eq!(storage.num_nodes(), 2);
        assert_eq!(storage.num_debug_var_ids(), 4);

        // Lookup node 0
        assert_eq!(
            storage.debug_var_ids_for_operation(test_node_id(0), 0).unwrap(),
            &[test_var_id(10), test_var_id(11)]
        );
        assert_eq!(storage.debug_var_ids_for_operation(test_node_id(0), 1).unwrap(), &[]);
        assert_eq!(
            storage.debug_var_ids_for_operation(test_node_id(0), 2).unwrap(),
            &[test_var_id(12)]
        );

        // Lookup node 1
        assert_eq!(
            storage.debug_var_ids_for_operation(test_node_id(1), 0).unwrap(),
            &[test_var_id(20)]
        );

        // Out-of-range operation returns empty
        assert_eq!(storage.debug_var_ids_for_operation(test_node_id(0), 99).unwrap(), &[]);
    }

    #[test]
    fn test_from_components_and_validate() {
        let storage = create_test_storage();
        assert_eq!(storage.num_nodes(), 2);
        assert_eq!(storage.num_debug_var_ids(), 6);
        assert!(storage.validate_csr(6).is_ok());

        // Validation fails when var count is too low
        assert!(storage.validate_csr(3).is_err());

        // Invalid components are rejected
        let result = OpToDebugVarIds::from_components(
            vec![test_var_id(0)],
            vec![0, 5], // points past end
            IndexVec::new(),
        );
        assert_eq!(result, Err(DecoratorIndexError::InternalStructure));
    }

    #[test]
    fn test_serialization_round_trip() {
        let storage = create_test_storage();

        let mut bytes = Vec::new();
        storage.write_into(&mut bytes);

        let mut reader = crate::utils::SliceReader::new(&bytes);
        let deserialized = OpToDebugVarIds::read_from(&mut reader, 6).unwrap();

        assert_eq!(storage, deserialized);
    }
}
