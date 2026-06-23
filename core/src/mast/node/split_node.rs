use alloc::{boxed::Box, vec::Vec};
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastForestContributor, MastNodeExt, fingerprint_with_child_fingerprints};
use crate::{
    Felt, Word,
    chiplets::hasher,
    mast::{MastForest, MastForestError, MastNodeId},
    operations::opcodes,
    prettier::PrettyPrint,
    utils::{Idx, LookupByIdx},
};

// SPLIT NODE
// ================================================================================================

/// A Split node defines conditional execution. When the VM encounters a Split node it executes
/// either the `on_true` child or `on_false` child.
///
/// Which child is executed is determined based on the top of the stack. If the value is `1`, then
/// the `on_true` child is executed. If the value is `0`, then the `on_false` child is executed. If
/// the value is neither `0` nor `1`, the execution fails.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct SplitNode {
    branches: [MastNodeId; 2],
    digest: Word,
}

/// Constants
impl SplitNode {
    /// The domain of the split node (used for control block hashing).
    pub const DOMAIN: Felt = Felt::new_unchecked(opcodes::SPLIT as u64);
}

/// Public accessors
impl SplitNode {
    /// Returns the ID of the node which is to be executed if the top of the stack is `1`.
    pub fn on_true(&self) -> MastNodeId {
        self.branches[0]
    }

    /// Returns the ID of the node which is to be executed if the top of the stack is `0`.
    pub fn on_false(&self) -> MastNodeId {
        self.branches[1]
    }
}

// PRETTY PRINTING
// ================================================================================================

impl SplitNode {
    pub(super) fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        SplitNodePrettyPrint { split_node: self, mast_forest }
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        SplitNodePrettyPrint { split_node: self, mast_forest }
    }
}

struct SplitNodePrettyPrint<'a> {
    split_node: &'a SplitNode,
    mast_forest: &'a MastForest,
}

impl PrettyPrint for SplitNodePrettyPrint<'_> {
    #[rustfmt::skip]
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let true_branch = self.mast_forest[self.split_node.on_true()].to_pretty_print(self.mast_forest);
        let false_branch = self.mast_forest[self.split_node.on_false()].to_pretty_print(self.mast_forest);

        let mut doc = Document::Empty;
        doc += indent(4, const_text("if.true") + nl() + true_branch.render()) + nl();
        doc += indent(4, const_text("else") + nl() + false_branch.render());
        doc += nl() + const_text("end");
        doc
    }
}

impl fmt::Display for SplitNodePrettyPrint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

// MAST NODE TRAIT IMPLEMENTATION
// ================================================================================================

impl MastNodeExt for SplitNode {
    /// Returns a commitment to this Split node.
    ///
    /// The commitment is computed as a hash of the `on_true` and `on_false` child nodes in the
    /// domain defined by [Self::DOMAIN] - i..e,:
    /// ```
    /// # use miden_core::mast::SplitNode;
    /// # use miden_crypto::{Word, hash::eidos::Eidos as Hasher};
    /// # let on_true_digest = Word::default();
    /// # let on_false_digest = Word::default();
    /// Hasher::merge_in_domain(&[on_true_digest, on_false_digest], SplitNode::DOMAIN);
    /// ```
    fn digest(&self) -> Word {
        self.digest
    }

    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a> {
        Box::new(SplitNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(SplitNode::to_pretty_print(self, mast_forest))
    }

    fn has_children(&self) -> bool {
        true
    }

    fn append_children_to(&self, target: &mut Vec<MastNodeId>) {
        target.push(self.on_true());
        target.push(self.on_false());
    }

    fn for_each_child<F>(&self, mut f: F)
    where
        F: FnMut(MastNodeId),
    {
        f(self.on_true());
        f(self.on_false());
    }

    fn domain(&self) -> Felt {
        Self::DOMAIN
    }

    type Builder = SplitNodeBuilder;

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        SplitNodeBuilder::new(self.branches).with_digest(self.digest)
    }
}

// ARBITRARY IMPLEMENTATION
// ================================================================================================

#[cfg(all(feature = "arbitrary", test))]
impl proptest::prelude::Arbitrary for SplitNode {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        use crate::Felt;

        // Generate two MastNodeId values and digest for the children
        (any::<MastNodeId>(), any::<MastNodeId>(), any::<[u64; 4]>())
            .prop_map(|(true_branch, false_branch, digest_array)| {
                // Generate a random digest
                let digest = Word::from(digest_array.map(Felt::new_unchecked));
                // Construct directly to avoid MastForest validation for arbitrary data
                SplitNode {
                    branches: [true_branch, false_branch],
                    digest,
                }
            })
            .no_shrink()  // Pure random values, no meaningful shrinking pattern
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`SplitNode`] instances.
#[derive(Debug)]
pub struct SplitNodeBuilder {
    branches: [MastNodeId; 2],
    digest: Option<Word>,
}

impl SplitNodeBuilder {
    /// Creates a new builder for a SplitNode with the specified branches.
    pub fn new(branches: [MastNodeId; 2]) -> Self {
        Self { branches, digest: None }
    }

    /// Builds the SplitNode.
    pub fn build(self, mast_forest: &MastForest) -> Result<SplitNode, MastForestError> {
        let forest_len = mast_forest.nodes.len();
        if self.branches[0].to_usize() >= forest_len {
            return Err(MastForestError::NodeIdOverflow(self.branches[0], forest_len));
        } else if self.branches[1].to_usize() >= forest_len {
            return Err(MastForestError::NodeIdOverflow(self.branches[1], forest_len));
        }

        // Use the forced digest if provided, otherwise compute the digest
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
            let true_branch_hash = mast_forest[self.branches[0]].digest();
            let false_branch_hash = mast_forest[self.branches[1]].digest();

            hasher::merge_in_domain(&[true_branch_hash, false_branch_hash], SplitNode::DOMAIN)
        };

        Ok(SplitNode { branches: self.branches, digest })
    }

    pub(in crate::mast) fn build_linked(self) -> Result<SplitNode, MastForestError> {
        Ok(SplitNode {
            branches: self.branches,
            digest: self.digest.ok_or(MastForestError::DigestRequiredForDeserialization)?,
        })
    }
}

impl MastForestContributor for SplitNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        // Validate branch node IDs
        let forest_len = forest.nodes.len();
        if self.branches[0].to_usize() >= forest_len {
            return Err(MastForestError::NodeIdOverflow(self.branches[0], forest_len));
        } else if self.branches[1].to_usize() >= forest_len {
            return Err(MastForestError::NodeIdOverflow(self.branches[1], forest_len));
        }

        // Use the forced digest if provided, otherwise compute the digest
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
            let true_branch_hash = forest[self.branches[0]].digest();
            let false_branch_hash = forest[self.branches[1]].digest();

            hasher::merge_in_domain(&[true_branch_hash, false_branch_hash], SplitNode::DOMAIN)
        };

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(SplitNode { branches: self.branches, digest }.into())
            .map_err(|_| MastForestError::TooManyNodes)?;

        Ok(node_id)
    }

    fn fingerprint_for_node(
        &self,
        forest: &MastForest,
        hash_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
    ) -> Result<Word, MastForestError> {
        let node_digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
            let if_branch_hash = forest[self.branches[0]].digest();
            let else_branch_hash = forest[self.branches[1]].digest();

            hasher::merge_in_domain(&[if_branch_hash, else_branch_hash], SplitNode::DOMAIN)
        };

        fingerprint_with_child_fingerprints(node_digest, &self.branches, forest, hash_by_node_id)
    }

    fn remap_children(self, remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        SplitNodeBuilder {
            branches: [
                *remapping.get(self.branches[0]).unwrap_or(&self.branches[0]),
                *remapping.get(self.branches[1]).unwrap_or(&self.branches[1]),
            ],
            digest: self.digest,
        }
    }

    fn with_digest(mut self, digest: Word) -> Self {
        self.digest = Some(digest);
        self
    }
}

impl SplitNodeBuilder {
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
        // Use the forced digest if provided, otherwise use a default digest
        // The actual digest computation will be handled when the forest is complete
        let Some(digest) = self.digest else {
            return Err(MastForestError::DigestRequiredForDeserialization);
        };

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(SplitNode { branches: self.branches, digest }.into())
            .map_err(|_| MastForestError::TooManyNodes)?;

        Ok(node_id)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for SplitNodeBuilder {
    type Parameters = SplitNodeBuilderParams;
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        let _ = params;
        any::<[MastNodeId; 2]>().prop_map(Self::new).boxed()
    }
}

/// Parameters for generating SplitNodeBuilder instances
#[cfg(any(test, feature = "arbitrary"))]
#[derive(Clone, Debug, Default)]
pub struct SplitNodeBuilderParams {}
