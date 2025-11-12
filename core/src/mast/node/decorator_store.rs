use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    DecoratorList,
    mast::{DecoratorId, MastNodeId},
};

/// A data structure for storing decorators for MAST nodes, including both
/// operation-level decorators and node-level decorators (before_enter/after_exit).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DecoratorStore {
    /// The decorators are owned by this node. This is the case for nodes
    /// which have not yet been inserted into a MAST forest.
    Owned {
        /// Operation-level decorators indexed by operation position
        /// (Note: Only used by BasicBlockNode, other nodes will have empty decorators)
        decorators: DecoratorList,
        /// Node-level decorators executed before entering the node
        before_enter: Vec<DecoratorId>,
        /// Node-level decorators executed after exiting the node
        after_exit: Vec<DecoratorId>,
    },
    /// The decorators are stored in a MAST forest and can be accessed via
    /// this node's ID. All decorator reads borrow from the forest's storage.
    Linked { id: MastNodeId },
}

impl Default for DecoratorStore {
    fn default() -> Self {
        Self::Owned {
            decorators: DecoratorList::new(),
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }
}

impl DecoratorStore {
    /// Create a new Owned decorator store with the specified before/after decorators
    pub fn new_owned_with_decorators(
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Self {
        Self::Owned {
            decorators: DecoratorList::new(),
            before_enter,
            after_exit,
        }
    }

    /// Get the before_enter decorators, borrowing from the forest if linked
    pub fn before_enter<'a>(&'a self, forest: &'a crate::mast::MastForest) -> &'a [DecoratorId] {
        match self {
            DecoratorStore::Owned { before_enter, .. } => before_enter,
            DecoratorStore::Linked { id } => {
                forest.node_decorator_storage.get_before_decorators(*id)
            },
        }
    }

    /// Get the after_exit decorators, borrowing from the forest if linked
    pub fn after_exit<'a>(&'a self, forest: &'a crate::mast::MastForest) -> &'a [DecoratorId] {
        match self {
            DecoratorStore::Owned { after_exit, .. } => after_exit,
            DecoratorStore::Linked { id } => {
                forest.node_decorator_storage.get_after_decorators(*id)
            },
        }
    }

    /// Check if this store is in the Linked state
    pub fn is_linked(&self) -> bool {
        matches!(self, DecoratorStore::Linked { .. })
    }

    /// Remove all decorators (no-op for Linked state as decorators are managed centrally)
    pub fn remove_decorators(&mut self) {
        match self {
            DecoratorStore::Owned { before_enter, after_exit, .. } => {
                before_enter.clear();
                after_exit.clear();
            },
            DecoratorStore::Linked { .. } => {
                // No-op: decorators are managed by NodeToDecoratorIds
            },
        }
    }
}
