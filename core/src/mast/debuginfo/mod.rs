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
