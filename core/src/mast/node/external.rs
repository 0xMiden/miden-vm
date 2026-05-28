use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_formatting::{
    hex::ToHex,
    prettier::{Document, PrettyPrint, const_text, text},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastForestContributor, MastNodeExt};
use crate::{
    Felt, Word,
    mast::{MastForest, MastForestError, MastNodeId},
    utils::LookupByIdx,
};

// EXTERNAL NODE
// ================================================================================================

/// Node for referencing procedures not present in a given [`MastForest`] (hence "external").
///
/// External nodes can be used to verify the integrity of a program's hash while keeping parts of
/// the program secret. They also allow a program to refer to a well-known procedure that was not
/// compiled with the program (e.g. a procedure in the core library).
///
/// The hash of an external node is the hash of the procedure it represents, such that an external
/// node can be swapped with the actual subtree that it represents without changing the MAST root.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct ExternalNode {
    digest: Word,
}

// PRETTY PRINTING
// ================================================================================================

impl ExternalNode {
    pub(super) fn to_display<'a>(&'a self, _mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        self.clone()
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        _mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        self.clone()
    }
}

impl PrettyPrint for ExternalNode {
    fn render(&self) -> Document {
        const_text("external") + const_text(".") + text(self.digest.as_bytes().to_hex_with_prefix())
    }
}

impl fmt::Display for ExternalNode {
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

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        ExternalNodeBuilder::new(self.digest)
    }

    #[cfg(debug_assertions)]
    fn verify_node_in_forest<F>(&self, _forest: &F)
    where
        F: crate::mast::ExecutableMastForest + ?Sized,
    {
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
                let word = Word::from([Felt::new_unchecked(a), Felt::new_unchecked(b), Felt::new_unchecked(c), Felt::new_unchecked(d)]);
                ExternalNodeBuilder::new(word).build()
            })
            .no_shrink()  // Pure random values, no meaningful shrinking pattern
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`ExternalNode`] instances.
#[derive(Debug)]
pub struct ExternalNodeBuilder {
    digest: Word,
}

impl ExternalNodeBuilder {
    /// Creates a new builder for an ExternalNode with the specified procedure hash.
    pub fn new(digest: Word) -> Self {
        Self { digest }
    }

    /// Builds the ExternalNode.
    pub fn build(self) -> ExternalNode {
        ExternalNode { digest: self.digest }
    }
}

impl MastForestContributor for ExternalNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(ExternalNode { digest: self.digest }.into())
            .map_err(|_| MastForestError::TooManyNodes)?;

        Ok(node_id)
    }

    fn fingerprint_for_node(&self, _forest: &MastForest) -> Result<Word, MastForestError> {
        Ok(self.digest)
    }

    fn remap_children(self, _remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        // ExternalNode has no children to remap, so return self unchanged
        self
    }

    fn with_digest(mut self, digest: Word) -> Self {
        self.digest = digest;
        self
    }
}

impl ExternalNodeBuilder {
    /// Add this node to a forest using relaxed validation.
    ///
    /// This method is used during deserialization where nodes may reference child nodes
    /// that haven't been added to the forest yet. The child node IDs have already been
    /// validated against the expected final node count during the `try_into_mast_node_builder`
    /// step, so we can safely skip validation here.
    ///
    /// Note: This is not part of the `MastForestContributor` trait because it's only
    /// intended for internal use during deserialization.
    pub(in crate::mast) fn add_to_forest_relaxed(
        self,
        forest: &mut MastForest,
    ) -> Result<MastNodeId, MastForestError> {
        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(ExternalNode { digest: self.digest }.into())
            .map_err(|_| MastForestError::TooManyNodes)?;

        Ok(node_id)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for ExternalNodeBuilder {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        any::<[u64; 4]>()
            .prop_map(|[a, b, c, d]| {
                Word::new([
                    Felt::new_unchecked(a),
                    Felt::new_unchecked(b),
                    Felt::new_unchecked(c),
                    Felt::new_unchecked(d),
                ])
            })
            .prop_map(Self::new)
            .boxed()
    }
}
