use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_crypto::{Felt, Word};
use miden_formatting::prettier::{Document, PrettyPrint, const_text, nl};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastForestContributor, MastNodeErrorContext, MastNodeExt};
use crate::{
    OPCODE_DYN, OPCODE_DYNCALL,
    mast::{DecoratedOpLink, DecoratorId, MastForest, MastForestError, MastNodeId},
};

// DYN NODE
// ================================================================================================

/// A Dyn node specifies that the node to be executed next is defined dynamically via the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct DynNode {
    is_dyncall: bool,
    digest: Word,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    before_enter: Vec<DecoratorId>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
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

impl MastNodeErrorContext for DynNode {
    fn decorators<'a>(
        &'a self,
        _forest: &'a MastForest,
    ) -> impl Iterator<Item = DecoratedOpLink> + 'a {
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

    /// Removes all decorators from this node.
    fn remove_decorators(&mut self) {
        self.before_enter.truncate(0);
        self.after_exit.truncate(0);
    }

    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a> {
        Box::new(DynNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(DynNode::to_pretty_print(self, mast_forest))
    }

    fn has_children(&self) -> bool {
        false
    }

    fn append_children_to(&self, _target: &mut Vec<MastNodeId>) {
        // No children for dyn nodes
    }

    fn for_each_child<F>(&self, _f: F)
    where
        F: FnMut(MastNodeId),
    {
        // DynNode has no children
    }

    fn domain(&self) -> Felt {
        self.domain()
    }

    type Builder = DynNodeBuilder;

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        if self.is_dyncall {
            DynNodeBuilder::new_dyncall()
        } else {
            DynNodeBuilder::new_dyn()
        }
        .with_before_enter(self.before_enter)
        .with_after_exit(self.after_exit)
    }
}

// ARBITRARY IMPLEMENTATION
// ================================================================================================

#[cfg(all(feature = "arbitrary", test))]
impl proptest::prelude::Arbitrary for DynNode {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        // Generate whether it's a dyncall or dynexec
        any::<bool>()
            .prop_map(|is_dyncall| {
                if is_dyncall {
                    DynNodeBuilder::new_dyncall().build()
                } else {
                    DynNodeBuilder::new_dyn().build()
                }
            })
            .no_shrink()  // Pure random values, no meaningful shrinking pattern
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`DynNode`] instances with decorators.
#[derive(Debug)]
pub struct DynNodeBuilder {
    is_dyncall: bool,
    before_enter: Vec<DecoratorId>,
    after_exit: Vec<DecoratorId>,
    digest: Option<Word>,
}

impl DynNodeBuilder {
    /// Creates a new builder for a DynNode representing a dynexec operation.
    pub fn new_dyn() -> Self {
        Self {
            is_dyncall: false,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
            digest: None,
        }
    }

    /// Creates a new builder for a DynNode representing a dyncall operation.
    pub fn new_dyncall() -> Self {
        Self {
            is_dyncall: true,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
            digest: None,
        }
    }

    /// Builds the DynNode with the specified decorators.
    pub fn build(self) -> DynNode {
        // Use the forced digest if provided, otherwise use the default digest
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else if self.is_dyncall {
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
        };

        DynNode {
            is_dyncall: self.is_dyncall,
            digest,
            before_enter: self.before_enter,
            after_exit: self.after_exit,
        }
    }
}

impl MastForestContributor for DynNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        forest
            .nodes
            .push(self.build().into())
            .map_err(|_| MastForestError::TooManyNodes)
    }

    fn fingerprint_for_node(
        &self,
        forest: &MastForest,
        _hash_by_node_id: &impl crate::LookupByIdx<MastNodeId, crate::mast::MastNodeFingerprint>,
    ) -> Result<crate::mast::MastNodeFingerprint, MastForestError> {
        // DynNode has no children, so we don't need hash_by_node_id
        // Use the fingerprint_from_parts helper function with empty children array
        crate::mast::node_fingerprint::fingerprint_from_parts(
            forest,
            _hash_by_node_id,
            &self.before_enter,
            &self.after_exit,
            &[], // DynNode has no children
            // Use the forced digest if available, otherwise use the default digest values
            if let Some(forced_digest) = self.digest {
                forced_digest
            } else if self.is_dyncall {
                miden_crypto::Word::new([
                    miden_crypto::Felt::new(8751004906421739448),
                    miden_crypto::Felt::new(13469709002495534233),
                    miden_crypto::Felt::new(12584249374630430826),
                    miden_crypto::Felt::new(7624899870831503004),
                ])
            } else {
                miden_crypto::Word::new([
                    miden_crypto::Felt::new(8115106948140260551),
                    miden_crypto::Felt::new(13491227816952616836),
                    miden_crypto::Felt::new(15015806788322198710),
                    miden_crypto::Felt::new(16575543461540527115),
                ])
            },
        )
    }

    fn remap_children(
        self,
        _remapping: &impl crate::LookupByIdx<crate::mast::MastNodeId, crate::mast::MastNodeId>,
    ) -> Self {
        // DynNode has no children to remap, but preserve the digest
        self
    }

    fn with_before_enter(mut self, decorators: impl Into<Vec<crate::mast::DecoratorId>>) -> Self {
        self.before_enter = decorators.into();
        self
    }

    fn with_after_exit(mut self, decorators: impl Into<Vec<crate::mast::DecoratorId>>) -> Self {
        self.after_exit = decorators.into();
        self
    }

    fn append_before_enter(
        &mut self,
        decorators: impl IntoIterator<Item = crate::mast::DecoratorId>,
    ) {
        self.before_enter.extend(decorators);
    }

    fn append_after_exit(
        &mut self,
        decorators: impl IntoIterator<Item = crate::mast::DecoratorId>,
    ) {
        self.after_exit.extend(decorators);
    }

    fn with_digest(mut self, digest: crate::Word) -> Self {
        self.digest = Some(digest);
        self
    }
}

impl DynNodeBuilder {
    /// Add this node to a forest using relaxed validation.
    ///
    /// This method is used during deserialization where nodes may reference child nodes
    /// that haven't been added to the forest yet. The child node IDs have already been
    /// validated against the expected final node count during the `try_into_mast_node_builder`
    /// step, so we can safely skip validation here.
    ///
    /// Note: This is not part of the `MastForestContributor` trait because it's only
    /// intended for internal use during deserialization.
    ///
    /// For DynNode, this is equivalent to the normal `add_to_forest` since dyn nodes
    /// don't have child nodes to validate.
    pub(in crate::mast) fn add_to_forest_relaxed(
        self,
        forest: &mut MastForest,
    ) -> Result<MastNodeId, MastForestError> {
        // DynNode doesn't have child dependencies, so relaxed validation is the same
        // as normal validation. We delegate to the normal method for consistency.
        self.add_to_forest(forest)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for DynNodeBuilder {
    type Parameters = DynNodeBuilderParams;
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (
            any::<bool>(),
            proptest::collection::vec(
                super::arbitrary::decorator_id_strategy(params.max_decorator_id_u32),
                0..=params.max_decorators,
            ),
            proptest::collection::vec(
                super::arbitrary::decorator_id_strategy(params.max_decorator_id_u32),
                0..=params.max_decorators,
            ),
        )
            .prop_map(|(is_dyncall, before_enter, after_exit)| {
                let builder = if is_dyncall {
                    Self::new_dyncall()
                } else {
                    Self::new_dyn()
                };
                builder.with_before_enter(before_enter).with_after_exit(after_exit)
            })
            .boxed()
    }
}

/// Parameters for generating DynNodeBuilder instances
#[cfg(any(test, feature = "arbitrary"))]
#[derive(Clone, Debug)]
pub struct DynNodeBuilderParams {
    pub max_decorators: usize,
    pub max_decorator_id_u32: u32,
}

#[cfg(any(test, feature = "arbitrary"))]
impl Default for DynNodeBuilderParams {
    fn default() -> Self {
        Self {
            max_decorators: 4,
            max_decorator_id_u32: 10,
        }
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
            DynNodeBuilder::new_dyn().build().digest(),
            Rpo256::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYN_DOMAIN)
        );

        assert_eq!(
            DynNodeBuilder::new_dyncall().build().digest(),
            Rpo256::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYNCALL_DOMAIN)
        );
    }
}
