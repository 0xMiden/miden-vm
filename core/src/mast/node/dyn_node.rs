use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_crypto::{Felt, Word};
use miden_formatting::prettier::{Document, PrettyPrint, const_text, nl};

use super::{MastNodeErrorContext, MastNodeExt};
use crate::{
    OPCODE_DYN, OPCODE_DYNCALL,
    mast::{DecoratorId, MastForest, MastNodeId, Remapping},
};

// DYN NODE
// ================================================================================================

/// A Dyn node specifies that the node to be executed next is defined dynamically via the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynNode {
    is_dyncall: bool,
    before_enter: Vec<DecoratorId>,
    after_exit: Vec<DecoratorId>,
}

/// Constants
impl DynNode {
    /// The domain of the Dyn block (used for control block hashing).
    pub const DYN_DOMAIN: Felt = Felt::new(OPCODE_DYN as u64);

    /// The domain of the Dyncall block (used for control block hashing).
    pub const DYNCALL_DOMAIN: Felt = Felt::new(OPCODE_DYNCALL as u64);
}

/// Public accessors
impl DynNode {
    /// Creates a new [`DynNode`] representing a dynexec operation.
    pub fn new_dyn() -> Self {
        Self {
            is_dyncall: false,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }

    /// Creates a new [`DynNode`] representing a dyncall operation.
    pub fn new_dyncall() -> Self {
        Self {
            is_dyncall: true,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }

    /// Returns true if the [`DynNode`] represents a dyncall operation, and false for dynexec.
    pub fn is_dyncall(&self) -> bool {
        self.is_dyncall
    }

    /// Returns the domain of this dyn node.
    pub fn domain(&self) -> Felt {
        if self.is_dyncall() {
            Self::DYNCALL_DOMAIN
        } else {
            Self::DYN_DOMAIN
        }
    }
}

//-------------------------------------------------------------------------------------------------
/// Mutators
impl DynNode {
    /// Sets the list of decorators to be executed before this node.
    pub fn append_before_enter(&mut self, decorator_ids: &[DecoratorId]) {
        self.before_enter.extend_from_slice(decorator_ids);
    }

    /// Sets the list of decorators to be executed after this node.
    pub fn append_after_exit(&mut self, decorator_ids: &[DecoratorId]) {
        self.after_exit.extend_from_slice(decorator_ids);
    }

    /// Removes all decorators from this node.
    pub fn remove_decorators(&mut self) {
        self.before_enter.truncate(0);
        self.after_exit.truncate(0);
    }
}

impl MastNodeErrorContext for DynNode {
    fn decorators(&self) -> impl Iterator<Item = (usize, DecoratorId)> {
        self.before_enter.iter().chain(&self.after_exit).copied().enumerate()
    }
}

// PRETTY PRINTING
// ================================================================================================

impl DynNode {
    pub(super) fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        DynNodePrettyPrint { node: self, mast_forest }
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        DynNodePrettyPrint { node: self, mast_forest }
    }
}

struct DynNodePrettyPrint<'a> {
    node: &'a DynNode,
    mast_forest: &'a MastForest,
}

impl DynNodePrettyPrint<'_> {
    /// Concatenates the provided decorators in a single line. If the list of decorators is not
    /// empty, prepends `prepend` and appends `append` to the decorator document.
    fn concatenate_decorators(
        &self,
        decorator_ids: &[DecoratorId],
        prepend: Document,
        append: Document,
    ) -> Document {
        let decorators = decorator_ids
            .iter()
            .map(|&decorator_id| self.mast_forest[decorator_id].render())
            .reduce(|acc, doc| acc + const_text(" ") + doc)
            .unwrap_or_default();

        if decorators.is_empty() {
            decorators
        } else {
            prepend + decorators + append
        }
    }

    fn single_line_pre_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.before_enter(), Document::Empty, const_text(" "))
    }

    fn single_line_post_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.after_exit(), const_text(" "), Document::Empty)
    }

    fn multi_line_pre_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.before_enter(), Document::Empty, nl())
    }

    fn multi_line_post_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.after_exit(), nl(), Document::Empty)
    }
}

impl crate::prettier::PrettyPrint for DynNodePrettyPrint<'_> {
    fn render(&self) -> crate::prettier::Document {
        let dyn_text = if self.node.is_dyncall() {
            const_text("dyncall")
        } else {
            const_text("dyn")
        };

        let single_line = self.single_line_pre_decorators()
            + dyn_text.clone()
            + self.single_line_post_decorators();
        let multi_line =
            self.multi_line_pre_decorators() + dyn_text + self.multi_line_post_decorators();

        single_line | multi_line
    }
}

impl fmt::Display for DynNodePrettyPrint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.pretty_print(f)
    }
}

// MAST NODE TRAIT IMPLEMENTATION
// ================================================================================================

impl MastNodeExt for DynNode {
    /// Returns a commitment to a Dyn node.
    ///
    /// The commitment is computed by hashing two empty words ([ZERO; 4]) in the domain defined
    /// by [Self::DYN_DOMAIN] or [Self::DYNCALL_DOMAIN], i.e.:
    ///
    /// ```
    /// # use miden_core::mast::DynNode;
    /// # use miden_crypto::{Word, hash::rpo::Rpo256 as Hasher};
    /// Hasher::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYN_DOMAIN);
    /// Hasher::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYNCALL_DOMAIN);
    /// ```
    fn digest(&self) -> Word {
        if self.is_dyncall {
            Word::new([
                Felt::new(8751004906421739448),
                Felt::new(13469709002495534233),
                Felt::new(12584249374630430826),
                Felt::new(7624899870831503004),
            ])
        } else {
            Word::new([
                Felt::new(8115106948140260551),
                Felt::new(13491227816952616836),
                Felt::new(15015806788322198710),
                Felt::new(16575543461540527115),
            ])
        }
    }

    /// Returns the decorators to be executed before this node is executed.
    fn before_enter(&self) -> &[DecoratorId] {
        &self.before_enter
    }

    /// Returns the decorators to be executed after this node is executed.
    fn after_exit(&self) -> &[DecoratorId] {
        &self.after_exit
    }

    fn append_before_enter(&mut self, decorator_ids: &[DecoratorId]) {
        self.append_before_enter(decorator_ids);
    }

    fn append_after_exit(&mut self, decorator_ids: &[DecoratorId]) {
        self.append_after_exit(decorator_ids);
    }

    fn remove_decorators(&mut self) {
        self.remove_decorators();
    }

    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a> {
        Box::new(DynNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(DynNode::to_pretty_print(self, mast_forest))
    }

    fn remap_children(&self, _remapping: &Remapping) -> Self {
        self.clone()
    }

    fn has_children(&self) -> bool {
        false
    }

    fn append_children_to(&self, _target: &mut Vec<MastNodeId>) {
        // No children for dyn nodes
    }

    fn domain(&self) -> Felt {
        self.domain()
    }
}

#[cfg(test)]
mod tests {
    use miden_crypto::hash::rpo::Rpo256;

    use super::*;

    /// Ensures that the hash of `DynNode` is indeed the hash of 2 empty words, in the `DynNode`
    /// domain.
    #[test]
    pub fn test_dyn_node_digest() {
        assert_eq!(
            DynNode::new_dyn().digest(),
            Rpo256::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYN_DOMAIN)
        );

        assert_eq!(
            DynNode::new_dyncall().digest(),
            Rpo256::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYNCALL_DOMAIN)
        );
    }
}
