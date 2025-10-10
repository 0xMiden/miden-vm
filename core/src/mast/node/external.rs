use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_crypto::{Felt, Word};
use miden_formatting::{
    hex::ToHex,
    prettier::{Document, PrettyPrint, const_text, nl, text},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastForestContributor, MastNodeErrorContext, MastNodeExt};
use crate::mast::{DecoratedOpLink, DecoratorId, MastForest, MastForestError, MastNodeId};

// EXTERNAL NODE
// ================================================================================================

/// Node for referencing procedures not present in a given [`MastForest`] (hence "external").
///
/// External nodes can be used to verify the integrity of a program's hash while keeping parts of
/// the program secret. They also allow a program to refer to a well-known procedure that was not
/// compiled with the program (e.g. a procedure in the standard library).
///
/// The hash of an external node is the hash of the procedure it represents, such that an external
/// node can be swapped with the actual subtree that it represents without changing the MAST root.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct ExternalNode {
    digest: Word,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    before_enter: Vec<DecoratorId>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    after_exit: Vec<DecoratorId>,
}

impl ExternalNode {
    /// Returns a new [`ExternalNode`] instantiated with the specified procedure hash.
    pub(in crate::mast) fn new(procedure_hash: Word) -> Self {
        Self {
            digest: procedure_hash,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }
}

impl MastNodeErrorContext for ExternalNode {
    fn decorators(&self) -> impl Iterator<Item = DecoratedOpLink> {
        self.before_enter.iter().chain(&self.after_exit).copied().enumerate()
    }
}

// PRETTY PRINTING
// ================================================================================================

impl ExternalNode {
    pub(super) fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        ExternalNodePrettyPrint { node: self, mast_forest }
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        ExternalNodePrettyPrint { node: self, mast_forest }
    }
}

struct ExternalNodePrettyPrint<'a> {
    node: &'a ExternalNode,
    mast_forest: &'a MastForest,
}

impl ExternalNodePrettyPrint<'_> {
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

impl crate::prettier::PrettyPrint for ExternalNodePrettyPrint<'_> {
    fn render(&self) -> crate::prettier::Document {
        let external = const_text("external")
            + const_text(".")
            + text(self.node.digest.as_bytes().to_hex_with_prefix());

        let single_line = self.single_line_pre_decorators()
            + external.clone()
            + self.single_line_post_decorators();
        let multi_line =
            self.multi_line_pre_decorators() + external + self.multi_line_post_decorators();

        single_line | multi_line
    }
}

impl fmt::Display for ExternalNodePrettyPrint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

// MAST NODE TRAIT IMPLEMENTATION
// ================================================================================================

impl MastNodeExt for ExternalNode {
    /// Returns the commitment to the MAST node referenced by this external node.
    ///
    /// The hash of an external node is the hash of the procedure it represents, such that an
    /// external node can be swapped with the actual subtree that it represents without changing
    /// the MAST root.
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
        Box::new(ExternalNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(ExternalNode::to_pretty_print(self, mast_forest))
    }

    fn has_children(&self) -> bool {
        false
    }

    fn append_children_to(&self, _target: &mut Vec<MastNodeId>) {
        // No children for external nodes
    }

    fn for_each_child<F>(&self, _f: F)
    where
        F: FnMut(MastNodeId),
    {
        // ExternalNode has no children
    }

    fn domain(&self) -> Felt {
        panic!("Can't fetch domain for an `External` node.")
    }

    type Builder = ExternalNodeBuilder;

    fn to_builder(self) -> Self::Builder {
        ExternalNodeBuilder::new(self.digest)
            .with_before_enter(self.before_enter)
            .with_after_exit(self.after_exit)
    }
}

// ARBITRARY IMPLEMENTATION
// ================================================================================================

#[cfg(all(feature = "arbitrary", test))]
impl proptest::prelude::Arbitrary for ExternalNode {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        use crate::Felt;

        // Generate a random Word to use as the procedure hash/digest
        any::<[u64; 4]>()
            .prop_map(|[a, b, c, d]| {
                let word = Word::from([Felt::new(a), Felt::new(b), Felt::new(c), Felt::new(d)]);
                ExternalNode::new(word)
            })
            .no_shrink()  // Pure random values, no meaningful shrinking pattern
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`ExternalNode`] instances with decorators.
#[derive(Debug)]
pub struct ExternalNodeBuilder {
    digest: Word,
    before_enter: Vec<DecoratorId>,
    after_exit: Vec<DecoratorId>,
}

impl ExternalNodeBuilder {
    /// Creates a new builder for an ExternalNode with the specified procedure hash.
    pub fn new(digest: Word) -> Self {
        Self {
            digest,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }

    /// Builds the ExternalNode with the specified decorators.
    pub fn build(self) -> ExternalNode {
        ExternalNode {
            digest: self.digest,
            before_enter: self.before_enter,
            after_exit: self.after_exit,
        }
    }
}

impl MastForestContributor for ExternalNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        forest
            .nodes
            .push(self.build().into())
            .map_err(|_| MastForestError::TooManyNodes)
    }

    fn with_before_enter(mut self, decorators: impl Into<Vec<DecoratorId>>) -> Self {
        self.before_enter = decorators.into();
        self
    }

    fn with_after_exit(mut self, decorators: impl Into<Vec<DecoratorId>>) -> Self {
        self.after_exit = decorators.into();
        self
    }

    fn fingerprint_for_node(
        &self,
        forest: &MastForest,
        _hash_by_node_id: &impl crate::LookupByIdx<MastNodeId, crate::mast::MastNodeFingerprint>,
    ) -> Result<crate::mast::MastNodeFingerprint, MastForestError> {
        // ExternalNode has no children, so we don't need hash_by_node_id
        // Use the fingerprint_from_parts helper function with empty children array
        crate::mast::node_fingerprint::fingerprint_from_parts(
            forest,
            _hash_by_node_id,
            &self.before_enter,
            &self.after_exit,
            &[],         // ExternalNode has no children
            self.digest, // ExternalNodeBuilder stores the digest directly
        )
    }

    fn remap_children(self, _remapping: &crate::mast::Remapping) -> Self {
        // ExternalNode has no children to remap, so return self unchanged
        self
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for ExternalNodeBuilder {
    type Parameters = ExternalNodeBuilderParams;
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (
            any::<[u64; 4]>().prop_map(|[a, b, c, d]| {
                miden_crypto::Word::new([
                    miden_crypto::Felt::new(a),
                    miden_crypto::Felt::new(b),
                    miden_crypto::Felt::new(c),
                    miden_crypto::Felt::new(d),
                ])
            }),
            proptest::collection::vec(
                super::arbitrary::decorator_id_strategy(params.max_decorator_id_u32),
                0..=params.max_decorators,
            ),
            proptest::collection::vec(
                super::arbitrary::decorator_id_strategy(params.max_decorator_id_u32),
                0..=params.max_decorators,
            ),
        )
            .prop_map(|(digest, before_enter, after_exit)| {
                Self::new(digest).with_before_enter(before_enter).with_after_exit(after_exit)
            })
            .boxed()
    }
}

/// Parameters for generating ExternalNodeBuilder instances
#[cfg(any(test, feature = "arbitrary"))]
#[derive(Clone, Debug)]
pub struct ExternalNodeBuilderParams {
    pub max_decorators: usize,
    pub max_decorator_id_u32: u32,
}

#[cfg(any(test, feature = "arbitrary"))]
impl Default for ExternalNodeBuilderParams {
    fn default() -> Self {
        Self {
            max_decorators: 4,
            max_decorator_id_u32: 10,
        }
    }
}
