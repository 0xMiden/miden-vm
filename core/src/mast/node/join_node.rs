use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_crypto::{Felt, Word};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastNodeErrorContext, MastNodeExt};
use crate::{
    OPCODE_JOIN,
    chiplets::hasher,
    mast::{DecoratedOpLink, DecoratorId, MastForest, MastForestError, MastNodeId, Remapping},
    prettier::PrettyPrint,
};

// JOIN NODE
// ================================================================================================

/// A Join node describe sequential execution. When the VM encounters a Join node, it executes the
/// first child first and the second child second.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct JoinNode {
    children: [MastNodeId; 2],
    digest: Word,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    before_enter: Vec<DecoratorId>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    after_exit: Vec<DecoratorId>,
}

/// Constants
impl JoinNode {
    /// The domain of the join block (used for control block hashing).
    pub const DOMAIN: Felt = Felt::new(OPCODE_JOIN as u64);
}

/// Constructors
impl JoinNode {
    /// Returns a new [`JoinNode`] instantiated with the specified children nodes.
    pub fn new(
        children: [MastNodeId; 2],
        mast_forest: &MastForest,
    ) -> Result<Self, MastForestError> {
        let forest_len = mast_forest.nodes.len();
        if children[0].as_usize() >= forest_len {
            return Err(MastForestError::NodeIdOverflow(children[0], forest_len));
        } else if children[1].as_usize() >= forest_len {
            return Err(MastForestError::NodeIdOverflow(children[1], forest_len));
        }
        let digest = {
            let left_child_hash = mast_forest[children[0]].digest();
            let right_child_hash = mast_forest[children[1]].digest();

            hasher::merge_in_domain(&[left_child_hash, right_child_hash], Self::DOMAIN)
        };

        Ok(Self {
            children,
            digest,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        })
    }

    /// Returns a new [`JoinNode`] from values that are assumed to be correct.
    /// Should only be used when the source of the inputs is trusted (e.g. deserialization).
    pub fn new_unsafe(children: [MastNodeId; 2], digest: Word) -> Self {
        Self {
            children,
            digest,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }
}

/// Public accessors
impl JoinNode {
    /// Returns the ID of the node that is to be executed first.
    pub fn first(&self) -> MastNodeId {
        self.children[0]
    }

    /// Returns the ID of the node that is to be executed after the execution of the program
    /// defined by the first node completes.
    pub fn second(&self) -> MastNodeId {
        self.children[1]
    }
}

impl MastNodeErrorContext for JoinNode {
    fn decorators(&self) -> impl Iterator<Item = DecoratedOpLink> {
        self.before_enter.iter().chain(&self.after_exit).copied().enumerate()
    }
}

// PRETTY PRINTING
// ================================================================================================

impl JoinNode {
    pub(super) fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        JoinNodePrettyPrint { join_node: self, mast_forest }
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        JoinNodePrettyPrint { join_node: self, mast_forest }
    }
}

struct JoinNodePrettyPrint<'a> {
    join_node: &'a JoinNode,
    mast_forest: &'a MastForest,
}

impl PrettyPrint for JoinNodePrettyPrint<'_> {
    #[rustfmt::skip]
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let pre_decorators = {
            let mut pre_decorators = self
                .join_node
                .before_enter()
                .iter()
                .map(|&decorator_id| self.mast_forest[decorator_id].render())
                .reduce(|acc, doc| acc + const_text(" ") + doc)
                .unwrap_or_default();
            if !pre_decorators.is_empty() {
                pre_decorators += nl();
            }

            pre_decorators
        };

        let post_decorators = {
            let mut post_decorators = self
                .join_node
                .after_exit()
                .iter()
                .map(|&decorator_id| self.mast_forest[decorator_id].render())
                .reduce(|acc, doc| acc + const_text(" ") + doc)
                .unwrap_or_default();
            if !post_decorators.is_empty() {
                post_decorators = nl() + post_decorators;
            }

            post_decorators
        };

        let first_child =
            self.mast_forest[self.join_node.first()].to_pretty_print(self.mast_forest);
        let second_child =
            self.mast_forest[self.join_node.second()].to_pretty_print(self.mast_forest);

        pre_decorators
        + indent(
            4,
            const_text("join")
            + nl()
            + first_child.render()
            + nl()
            + second_child.render(),
        ) + nl() + const_text("end")
        + post_decorators
    }
}

impl fmt::Display for JoinNodePrettyPrint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

// MAST NODE TRAIT IMPLEMENTATION
// ================================================================================================

impl MastNodeExt for JoinNode {
    /// Returns a commitment to this Join node.
    ///
    /// The commitment is computed as a hash of the `first` and `second` child node in the domain
    /// defined by [Self::DOMAIN] - i.e.,:
    /// ```
    /// # use miden_core::mast::JoinNode;
    /// # use miden_crypto::{Word, hash::rpo::Rpo256 as Hasher};
    /// # let first_child_digest = Word::default();
    /// # let second_child_digest = Word::default();
    /// Hasher::merge_in_domain(&[first_child_digest, second_child_digest], JoinNode::DOMAIN);
    /// ```
    fn digest(&self) -> Word {
        self.digest
    }

    /// Returns the decorators to be executed before this node is executed.
    fn before_enter(&self) -> &[DecoratorId] {
        &self.before_enter
    }

    /// Returns the decorators to be executed after this node is executed.
    fn after_exit(&self) -> &[DecoratorId] {
        &self.after_exit
    }
    /// Sets the list of decorators to be executed before this node.
    fn append_before_enter(&mut self, decorator_ids: &[DecoratorId]) {
        self.before_enter.extend_from_slice(decorator_ids);
    }

    /// Sets the list of decorators to be executed after this node.
    fn append_after_exit(&mut self, decorator_ids: &[DecoratorId]) {
        self.after_exit.extend_from_slice(decorator_ids);
    }

    /// Removes all decorators from this node.
    fn remove_decorators(&mut self) {
        self.before_enter.truncate(0);
        self.after_exit.truncate(0);
    }

    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a> {
        Box::new(JoinNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(JoinNode::to_pretty_print(self, mast_forest))
    }

    fn remap_children(&self, remapping: &Remapping) -> Self {
        let mut node = self.clone();
        node.children[0] = node.children[0].remap(remapping);
        node.children[1] = node.children[1].remap(remapping);
        node
    }

    fn has_children(&self) -> bool {
        true
    }

    fn append_children_to(&self, target: &mut Vec<MastNodeId>) {
        target.push(self.first());
        target.push(self.second());
    }

    fn domain(&self) -> Felt {
        Self::DOMAIN
    }
}
