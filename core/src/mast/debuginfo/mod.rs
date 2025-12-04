//! Debug information management for MAST forests.
//!
//! This module provides the [`DebugInfo`] struct which consolidates all debug-related
//! information for a MAST forest in a single location. This includes:
//!
//! - All decorators (debug, trace, and assembly operation metadata)
//! - Operation-indexed decorator mappings for efficient lookup
//! - Node-level decorator storage (before_enter/after_exit)
//! - Error code mappings for descriptive error messages
//!
//! The debug info is always available at the `MastForest` level (as per issue #1821),
//! but may be conditionally included during assembly to maintain backward compatibility.
//! Decorators are only executed when the processor is running in debug mode, allowing
//! debug information to be available for debugging and error reporting without
//! impacting performance in production execution.
//!
//! # Debug Mode Semantics
//!
//! Debug mode is controlled via [`ExecutionOptions`](air::options::ExecutionOptions):
//! - `with_debugging(true)` enables debug mode explicitly
//! - `with_tracing()` automatically enables debug mode (tracing requires debug info)
//! - By default, debug mode is disabled for maximum performance
//!
//! When debug mode is disabled:
//! - Debug decorators are not executed
//! - Trace decorators are not executed
//! - Assembly operation decorators are not recorded
//! - before_enter/after_exit decorators are not executed
//!
//! When debug mode is enabled:
//! - All decorator types are executed according to their semantics
//! - Debug decorators trigger host callbacks for breakpoints
//! - Trace decorators trigger host callbacks for tracing
//! - Assembly operation decorators provide source mapping information
//! - before_enter/after_exit decorators execute around node execution
//!
//! # Production Builds
//!
//! The `DebugInfo` can be stripped for production builds using the [`clear()`](Self::clear)
//! method, which removes decorators while preserving critical information. This allows
//! backward compatibility while enabling size optimization for deployment.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_utils_indexing::{Idx, IndexVec};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{Decorator, DecoratorId, MastForestError, MastNodeId};

mod decorator_storage;
pub use decorator_storage::{
    DecoratedLinks, DecoratedLinksIter, DecoratorIndexError, OpToDecoratorIds,
};

mod node_decorator_storage;
pub use node_decorator_storage::NodeToDecoratorIds;

// DEBUG INFO
// ================================================================================================

/// Debug information for a MAST forest, containing decorators and error messages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugInfo {
    /// All decorators in the MAST forest.
    decorators: IndexVec<DecoratorId, Decorator>,

    /// Efficient access to decorators per operation per node.
    op_decorator_storage: OpToDecoratorIds,

    /// Efficient storage for node-level decorators (before_enter and after_exit).
    node_decorator_storage: NodeToDecoratorIds,

    /// Maps error codes to error messages.
    error_codes: BTreeMap<u64, Arc<str>>,
}

impl DebugInfo {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new empty [DebugInfo].
    pub fn new() -> Self {
        Self {
            decorators: IndexVec::new(),
            op_decorator_storage: OpToDecoratorIds::new(),
            node_decorator_storage: NodeToDecoratorIds::new(),
            error_codes: BTreeMap::new(),
        }
    }

    /// Creates an empty [DebugInfo] with specified capacities.
    pub fn with_capacity(
        decorators_capacity: usize,
        nodes_capacity: usize,
        operations_capacity: usize,
        decorator_ids_capacity: usize,
    ) -> Self {
        Self {
            decorators: IndexVec::with_capacity(decorators_capacity),
            op_decorator_storage: OpToDecoratorIds::with_capacity(
                nodes_capacity,
                operations_capacity,
                decorator_ids_capacity,
            ),
            node_decorator_storage: NodeToDecoratorIds::with_capacity(nodes_capacity, 0, 0),
            error_codes: BTreeMap::new(),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns true if this [DebugInfo] has no decorators or error codes.
    pub fn is_empty(&self) -> bool {
        self.decorators.is_empty() && self.error_codes.is_empty()
    }

    /// Strips all debug information, removing decorators and error codes.
    ///
    /// This is used for release builds where debug info is not needed.
    pub fn clear(&mut self) {
        self.clear_mappings();
        self.decorators = IndexVec::new();
        self.error_codes.clear();
    }

    // DECORATOR ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of decorators.
    pub fn num_decorators(&self) -> usize {
        self.decorators.len()
    }

    /// Returns all decorators as a slice.
    pub fn decorators(&self) -> &[Decorator] {
        self.decorators.as_slice()
    }

    /// Returns the decorator with the given ID, if it exists.
    pub fn decorator(&self, decorator_id: DecoratorId) -> Option<&Decorator> {
        self.decorators.get(decorator_id)
    }

    /// Returns the before-enter decorators for the given node.
    pub fn before_enter_decorators(&self, node_id: MastNodeId) -> &[DecoratorId] {
        self.node_decorator_storage.get_before_decorators(node_id)
    }

    /// Returns the after-exit decorators for the given node.
    pub fn after_exit_decorators(&self, node_id: MastNodeId) -> &[DecoratorId] {
        self.node_decorator_storage.get_after_decorators(node_id)
    }

    /// Returns decorators for a specific operation within a node.
    pub fn decorators_for_operation(
        &self,
        node_id: MastNodeId,
        local_op_idx: usize,
    ) -> &[DecoratorId] {
        self.op_decorator_storage
            .decorator_ids_for_operation(node_id, local_op_idx)
            .unwrap_or(&[])
    }

    /// Returns decorator links for a node, including operation indices.
    pub(super) fn decorator_links_for_node(
        &self,
        node_id: MastNodeId,
    ) -> Result<DecoratedLinks<'_>, DecoratorIndexError> {
        self.op_decorator_storage.decorator_links_for_node(node_id)
    }

    // DECORATOR MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds a decorator and returns its ID.
    pub fn add_decorator(&mut self, decorator: Decorator) -> Result<DecoratorId, MastForestError> {
        self.decorators.push(decorator).map_err(|_| MastForestError::TooManyDecorators)
    }

    /// Returns a mutable reference the decorator with the given ID, if it exists.
    pub(super) fn decorator_mut(&mut self, decorator_id: DecoratorId) -> Option<&mut Decorator> {
        if decorator_id.to_usize() < self.decorators.len() {
            Some(&mut self.decorators[decorator_id])
        } else {
            None
        }
    }

    /// Adds node-level decorators (before_enter and after_exit) for the given node.
    ///
    /// # Note
    /// This method does not validate decorator IDs immediately. Validation occurs during
    /// operations that need to access the actual decorator data (e.g., merging, serialization).
    pub(super) fn register_node_decorators(
        &mut self,
        node_id: MastNodeId,
        before_enter: &[DecoratorId],
        after_exit: &[DecoratorId],
    ) {
        self.node_decorator_storage
            .add_node_decorators(node_id, before_enter, after_exit);
    }

    /// Registers operation-indexed decorators for a node.
    ///
    /// This associates already-added decorators with specific operations within a node.
    pub(crate) fn register_op_indexed_decorators(
        &mut self,
        node_id: MastNodeId,
        decorators_info: Vec<(usize, DecoratorId)>,
    ) -> Result<(), crate::mast::debuginfo::decorator_storage::DecoratorIndexError> {
        self.op_decorator_storage.add_decorator_info_for_node(node_id, decorators_info)
    }

    /// Clears all decorator information while preserving error codes.
    ///
    /// This is used when rebuilding decorator information from nodes.
    pub fn clear_mappings(&mut self) {
        self.op_decorator_storage = OpToDecoratorIds::new();
        self.node_decorator_storage.clear();
    }

    // ERROR CODE METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns an error message by code.
    pub fn error_message(&self, code: u64) -> Option<Arc<str>> {
        self.error_codes.get(&code).cloned()
    }

    /// Returns an iterator over error codes.
    pub fn error_codes(&self) -> impl Iterator<Item = (&u64, &Arc<str>)> {
        self.error_codes.iter()
    }

    /// Inserts an error code with its message.
    pub fn insert_error_code(&mut self, code: u64, msg: Arc<str>) {
        self.error_codes.insert(code, msg);
    }

    /// Inserts multiple error codes at once.
    ///
    /// This is used when bulk error code insertion is needed.
    pub fn extend_error_codes<I>(&mut self, error_codes: I)
    where
        I: IntoIterator<Item = (u64, Arc<str>)>,
    {
        self.error_codes.extend(error_codes);
    }

    /// Clears all error codes.
    ///
    /// This is used when error code information needs to be reset.
    pub fn clear_error_codes(&mut self) {
        self.error_codes.clear();
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the operation decorator storage.
    #[cfg(test)]
    pub(crate) fn op_decorator_storage(&self) -> &OpToDecoratorIds {
        &self.op_decorator_storage
    }
}

impl Default for DebugInfo {
    fn default() -> Self {
        Self::new()
    }
}
