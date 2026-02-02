use alloc::string::String;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    mast::{DecoratorId, MastNodeId},
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
    utils::{CsrMatrix, CsrValidationError, Idx},
};

/// A CSR (Compressed Sparse Row) representation for storing node-level decorators (before_enter and
/// after_exit).
///
/// This structure provides efficient storage for before_enter and after_exit decorators across all
/// nodes in a MastForest, using a similar CSR pattern to OpToDecoratorIds but for node-level
/// decorators.
///
/// The data layout follows CSR format. For node `i`:
/// - Before-enter decorators are stored in `before_enter.row(i)`
/// - After-exit decorators are stored in `after_exit.row(i)`
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NodeToDecoratorIds {
    /// All `before_enter` decorators, stored by node in CSR format.
    before_enter: CsrMatrix<MastNodeId, DecoratorId>,
    /// All `after_exit` decorators, stored by node in CSR format.
    after_exit: CsrMatrix<MastNodeId, DecoratorId>,
}

impl NodeToDecoratorIds {
    /// Creates a new empty `NodeToDecoratorIds`.
    pub fn new() -> Self {
        Self {
            before_enter: CsrMatrix::new(),
            after_exit: CsrMatrix::new(),
        }
    }

    /// Create a NodeToDecoratorIds from raw CSR matrices.
    ///
    /// Used during deserialization. Validation happens separately via `validate_csr()`.
    pub fn from_matrices(
        before_enter: CsrMatrix<MastNodeId, DecoratorId>,
        after_exit: CsrMatrix<MastNodeId, DecoratorId>,
    ) -> Self {
        Self { before_enter, after_exit }
    }

    /// Validate CSR structure integrity.
    ///
    /// Checks:
    /// - All decorator IDs are valid (< decorator_count)
    /// - Both CSR matrices have valid structural invariants
    pub(super) fn validate_csr(&self, decorator_count: usize) -> Result<(), String> {
        // Validate before_enter CSR with domain-specific check
        self.before_enter
            .validate_with(|dec_id| dec_id.to_usize() < decorator_count)
            .map_err(|e| format_validation_error("before_enter", e, decorator_count))?;

        // Validate after_exit CSR with domain-specific check
        self.after_exit
            .validate_with(|dec_id| dec_id.to_usize() < decorator_count)
            .map_err(|e| format_validation_error("after_exit", e, decorator_count))?;

        Ok(())
    }

    /// Creates a new empty `NodeToDecoratorIds` with specified capacity.
    pub fn with_capacity(
        nodes_capacity: usize,
        before_decorators_capacity: usize,
        after_decorators_capacity: usize,
    ) -> Self {
        Self {
            before_enter: CsrMatrix::with_capacity(nodes_capacity, before_decorators_capacity),
            after_exit: CsrMatrix::with_capacity(nodes_capacity, after_decorators_capacity),
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
        // Fill with empty rows up to this node if needed
        self.before_enter.fill_to_row(node_id).expect("too many nodes for CSR matrix");
        self.after_exit.fill_to_row(node_id).expect("too many nodes for CSR matrix");

        // Add the row for this node
        self.before_enter
            .push_row(before.iter().copied())
            .expect("too many nodes for CSR matrix");
        self.after_exit
            .push_row(after.iter().copied())
            .expect("too many nodes for CSR matrix");
    }

    /// Gets the before_enter decorators for a given node.
    pub fn get_before_decorators(&self, node_id: MastNodeId) -> &[DecoratorId] {
        self.before_enter.row(node_id).unwrap_or(&[])
    }

    /// Gets the after_exit decorators for a given node.
    pub fn get_after_decorators(&self, node_id: MastNodeId) -> &[DecoratorId] {
        self.after_exit.row(node_id).unwrap_or(&[])
    }

    /// Finalizes the storage by ensuring sentinel pointers are properly set.
    /// This should be called after all nodes have been added.
    ///
    /// Note: With CsrMatrix, this is a no-op since the CSR is always in a valid state.
    pub fn finalize(&mut self) {
        // CsrMatrix is always in a valid state, nothing to do
    }

    /// Clears all decorators and mappings.
    pub fn clear(&mut self) {
        self.before_enter = CsrMatrix::new();
        self.after_exit = CsrMatrix::new();
    }

    /// Returns the number of nodes in this storage.
    pub fn len(&self) -> usize {
        self.before_enter.num_rows()
    }

    /// Returns true if this storage is empty.
    pub fn is_empty(&self) -> bool {
        self.before_enter.is_empty()
    }

    // SERIALIZATION HELPERS
    // --------------------------------------------------------------------------------------------

    /// Write this CSR structure to a target.
    pub(super) fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.before_enter.write_into(target);
        self.after_exit.write_into(target);
    }

    /// Read this CSR structure from a source, validating decorator IDs against decorator_count.
    pub(super) fn read_from<R: ByteReader>(
        source: &mut R,
        decorator_count: usize,
    ) -> Result<Self, DeserializationError> {
        let before_enter: CsrMatrix<MastNodeId, DecoratorId> = Deserializable::read_from(source)?;
        let after_exit: CsrMatrix<MastNodeId, DecoratorId> = Deserializable::read_from(source)?;

        let result = Self::from_matrices(before_enter, after_exit);

        result.validate_csr(decorator_count).map_err(|e| {
            DeserializationError::InvalidValue(format!("NodeToDecoratorIds validation failed: {e}"))
        })?;

        Ok(result)
    }
}

impl Default for NodeToDecoratorIds {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a CsrValidationError into a human-readable string.
fn format_validation_error(
    field: &str,
    error: CsrValidationError,
    decorator_count: usize,
) -> String {
    match error {
        CsrValidationError::IndptrStartNotZero(val) => {
            format!("{field} indptr must start at 0, got {val}")
        },
        CsrValidationError::IndptrNotMonotonic { index, prev, curr } => {
            format!("{field} indptr not monotonic at index {index}: {prev} > {curr}")
        },
        CsrValidationError::IndptrDataMismatch { indptr_end, data_len } => {
            format!("{field} indptr ends at {indptr_end}, but data.len() is {data_len}")
        },
        CsrValidationError::InvalidData { row, position } => {
            format!(
                "Invalid decorator ID in {field} at row {row}, position {position}: \
                 exceeds decorator count {decorator_count}"
            )
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_decorator_id(value: u32) -> DecoratorId {
        DecoratorId(value)
    }

    #[test]
    fn test_new_is_empty() {
        let storage = NodeToDecoratorIds::new();
        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);
    }

    #[test]
    fn test_add_node_decorators() {
        let mut storage = NodeToDecoratorIds::new();

        let before = vec![test_decorator_id(0), test_decorator_id(1)];
        let after = vec![test_decorator_id(2)];

        storage.add_node_decorators(MastNodeId::new_unchecked(0), &before, &after);

        assert_eq!(storage.len(), 1);
        assert_eq!(storage.get_before_decorators(MastNodeId::new_unchecked(0)), &before[..]);
        assert_eq!(storage.get_after_decorators(MastNodeId::new_unchecked(0)), &after[..]);
    }

    #[test]
    fn test_validate_csr_valid() {
        let mut storage = NodeToDecoratorIds::new();

        let before = vec![test_decorator_id(0)];
        let after = vec![test_decorator_id(1)];

        storage.add_node_decorators(MastNodeId::new_unchecked(0), &before, &after);

        assert!(storage.validate_csr(3).is_ok());
    }

    #[test]
    fn test_validate_csr_invalid_decorator_id() {
        let mut storage = NodeToDecoratorIds::new();

        let before = vec![test_decorator_id(5)]; // ID too high
        let after = vec![];

        storage.add_node_decorators(MastNodeId::new_unchecked(0), &before, &after);

        let result = storage.validate_csr(3);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid decorator ID"));
    }

    #[test]
    fn test_get_decorators_out_of_bounds() {
        let storage = NodeToDecoratorIds::new();
        assert_eq!(storage.get_before_decorators(MastNodeId::new_unchecked(0)), &[]);
        assert_eq!(storage.get_after_decorators(MastNodeId::new_unchecked(0)), &[]);
    }

    #[test]
    fn test_with_capacity() {
        let storage = NodeToDecoratorIds::with_capacity(10, 20, 30);
        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);
    }

    #[test]
    fn test_clear() {
        let mut storage = NodeToDecoratorIds::new();
        storage.add_node_decorators(
            MastNodeId::new_unchecked(0),
            &[test_decorator_id(0)],
            &[test_decorator_id(1)],
        );

        storage.clear();
        assert!(storage.is_empty());
    }
}
