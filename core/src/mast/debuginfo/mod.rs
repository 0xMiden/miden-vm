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
//! The `DebugInfo` can be stripped for production builds using the [`strip()`](Self::strip)
//! method, which removes decorators while preserving critical information. This allows
//! backward compatibility while enabling size optimization for deployment.

use alloc::{collections::BTreeMap, sync::Arc};

use miden_utils_indexing::IndexVec;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{Decorator, DecoratorId};

mod decorator_storage;
pub use decorator_storage::{
    DecoratedLinks, DecoratedLinksIter, DecoratorIndexError, OpToDecoratorIds,
};

mod node_decorator_storage;
pub use node_decorator_storage::NodeToDecoratorIds;

// DEBUG INFO
// ================================================================================================

/// Debug information for a MAST forest, containing decorators and error messages.
/// This is always present in a MastForest (as per issue #1821), but may be "stripped"
/// in the future for release builds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugInfo {
    /// All decorators in the MAST forest.
    pub decorators: IndexVec<DecoratorId, Decorator>,

    /// Efficient access to decorators per operation per node.
    pub op_decorator_storage: OpToDecoratorIds,

    /// Efficient storage for node-level decorators (before_enter and after_exit).
    pub node_decorator_storage: NodeToDecoratorIds,

    /// Maps error codes to error messages.
    pub error_codes: BTreeMap<u64, Arc<str>>,
}

impl DebugInfo {
    /// Creates a new empty DebugInfo.
    pub fn new() -> Self {
        Self {
            decorators: IndexVec::new(),
            op_decorator_storage: OpToDecoratorIds::new(),
            node_decorator_storage: NodeToDecoratorIds::new(),
            error_codes: BTreeMap::new(),
        }
    }

    /// Creates an empty DebugInfo with specified capacities.
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

    /// Strips all debug information, removing decorators and error codes.
    /// This is used for release builds where debug info is not needed.
    pub fn strip(&mut self) {
        self.decorators = IndexVec::new();
        self.op_decorator_storage = OpToDecoratorIds::new();
        self.node_decorator_storage.clear();
        self.error_codes.clear();
    }

    /// Returns true if this DebugInfo has no decorators or error codes.
    pub fn is_empty(&self) -> bool {
        self.decorators.is_empty() && self.error_codes.is_empty()
    }
}

impl Default for DebugInfo {
    fn default() -> Self {
        Self::new()
    }
}
