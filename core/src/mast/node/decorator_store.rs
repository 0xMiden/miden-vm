use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    mast::{DecoratorId, ExecutableMastForest, MastForest, MastNodeId},
    operations::DecoratorList,
};

/// A link from a MAST node to its forest-owned operation-level and node-level decorators.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LinkedDecoratorStore {
    /// The decorators are stored in a MAST forest and can be accessed via
    /// this node's ID. All decorator reads borrow from the forest's storage.
    id: MastNodeId,
}

impl LinkedDecoratorStore {
    pub(crate) const fn linked(id: MastNodeId) -> Self {
        Self { id }
    }

    /// Get the before_enter decorators, borrowing from the forest.
    pub fn before_enter<'a, F>(&'a self, forest: &'a F) -> &'a [DecoratorId]
    where
        F: ExecutableMastForest + ?Sized,
    {
        forest.linked_before_enter_decorators(self.id)
    }

    /// Get the after_exit decorators, borrowing from the forest.
    pub fn after_exit<'a, F>(&'a self, forest: &'a F) -> &'a [DecoratorId]
    where
        F: ExecutableMastForest + ?Sized,
    {
        forest.linked_after_exit_decorators(self.id)
    }

    pub(crate) fn into_node_level_decorators(
        self,
        forest: &MastForest,
    ) -> (Vec<DecoratorId>, Vec<DecoratorId>) {
        (
            forest.before_enter_decorators(self.id).to_vec(),
            forest.after_exit_decorators(self.id).to_vec(),
        )
    }

    pub(crate) fn into_parts(
        self,
        forest: &MastForest,
    ) -> (DecoratorList, Vec<DecoratorId>, Vec<DecoratorId>) {
        let decorators = forest
            .decorator_links_for_node(self.id)
            .expect("linked node decorators should be available; forest may be inconsistent")
            .into_iter()
            .collect();
        let before_enter = forest.before_enter_decorators(self.id).to_vec();
        let after_exit = forest.after_exit_decorators(self.id).to_vec();
        (decorators, before_enter, after_exit)
    }

    /// Get the node ID that links this store to its MAST forest.
    pub fn linked_id(&self) -> MastNodeId {
        self.id
    }
}
