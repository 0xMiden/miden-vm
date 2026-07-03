use alloc::{boxed::Box, vec::Vec};
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{
    MastForestContributor, MastNodeContext, MastNodeExt, fingerprint_with_child_fingerprints,
};
use crate::{
    Felt, Word,
    chiplets::hasher,
    mast::{MastForest, MastForestError, MastNodeId},
    operations::opcodes,
    prettier::PrettyPrint,
    utils::LookupByIdx,
};

// JOIN NODE
// ================================================================================================

/// A Join node describe sequential execution. When the VM encounters a Join node, it executes the
/// first child first and the second child second.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct JoinNode {
    children: [MastNodeId; 2],
    digest: Word,
}

/// Constants
impl JoinNode {
    /// The domain of the join block (used for control block hashing).
    pub const DOMAIN: Felt = Felt::new_unchecked(opcodes::JOIN as u64);
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

        let first_child =
            self.mast_forest[self.join_node.first()].to_pretty_print(self.mast_forest);
        let second_child =
            self.mast_forest[self.join_node.second()].to_pretty_print(self.mast_forest);

        indent(
            4,
            const_text("join")
            + nl()
            + first_child.render()
            + nl()
            + second_child.render(),
        ) + nl() + const_text("end")
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
    /// # use miden_crypto::{Word, hash::poseidon2::Poseidon2 as Hasher};
    /// # let first_child_digest = Word::default();
    /// # let second_child_digest = Word::default();
    /// Hasher::merge_in_domain(&[first_child_digest, second_child_digest], JoinNode::DOMAIN);
    /// ```
    fn digest(&self) -> Word {
        self.digest
    }

    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a> {
        Box::new(JoinNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(JoinNode::to_pretty_print(self, mast_forest))
    }

    fn has_children(&self) -> bool {
        true
    }

    fn append_children_to(&self, target: &mut Vec<MastNodeId>) {
        target.push(self.first());
        target.push(self.second());
    }

    fn for_each_child<F>(&self, mut f: F)
    where
        F: FnMut(MastNodeId),
    {
        f(self.first());
        f(self.second());
    }

    fn domain(&self) -> Felt {
        Self::DOMAIN
    }

    type Builder = JoinNodeBuilder;

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        JoinNodeBuilder::new(self.children).with_digest(self.digest)
    }
}

// ARBITRARY IMPLEMENTATION
// ================================================================================================

#[cfg(all(feature = "arbitrary", test))]
impl proptest::prelude::Arbitrary for JoinNode {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        use crate::Felt;

        // Generate two MastNodeId values and digest for the children
        (any::<MastNodeId>(), any::<MastNodeId>(), any::<[u64; 4]>())
            .prop_map(|(first_child, second_child, digest_array)| {
                // Generate a random digest
                let digest = Word::from(digest_array.map(Felt::new_unchecked));
                // Construct directly to avoid MastForest validation for arbitrary data
                JoinNode {
                    children: [first_child, second_child],
                    digest,
                }
            })
            .no_shrink()  // Pure random values, no meaningful shrinking pattern
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`JoinNode`] instances.
#[derive(Debug)]
pub struct JoinNodeBuilder {
    children: [MastNodeId; 2],
    digest: Option<Word>,
}

impl JoinNodeBuilder {
    /// Creates a new builder for a JoinNode with the specified children.
    pub fn new(children: [MastNodeId; 2]) -> Self {
        Self { children, digest: None }
    }

    /// Builds the JoinNode.
    pub fn build(self, context: &impl MastNodeContext) -> Result<JoinNode, MastForestError> {
        let left_child = context.get_node_by_id(self.children[0]).ok_or_else(|| {
            MastForestError::NodeIdOverflow(self.children[0], context.node_count())
        })?;
        let right_child = context.get_node_by_id(self.children[1]).ok_or_else(|| {
            MastForestError::NodeIdOverflow(self.children[1], context.node_count())
        })?;

        // Use the forced digest if provided, otherwise compute the digest
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
            let left_child_hash = left_child.digest();
            let right_child_hash = right_child.digest();

            hasher::merge_in_domain(&[left_child_hash, right_child_hash], JoinNode::DOMAIN)
        };

        Ok(JoinNode { children: self.children, digest })
    }

    pub(in crate::mast) fn build_linked(self) -> Result<JoinNode, MastForestError> {
        Ok(JoinNode {
            children: self.children,
            digest: self.digest.ok_or(MastForestError::DigestRequiredForDeserialization)?,
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl JoinNodeBuilder {
    pub fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        let node = self.build(forest)?;
        forest.nodes.push(node.into()).map_err(|_| MastForestError::TooManyNodes)
    }
}

impl MastForestContributor for JoinNodeBuilder {
    fn fingerprint_for_node(
        &self,
        context: &impl MastNodeContext,
        hash_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
    ) -> Result<Word, MastForestError> {
        let node_digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
            let left_child_hash = context
                .get_node_by_id(self.children[0])
                .ok_or_else(|| {
                    MastForestError::NodeIdOverflow(self.children[0], context.node_count())
                })?
                .digest();
            let right_child_hash = context
                .get_node_by_id(self.children[1])
                .ok_or_else(|| {
                    MastForestError::NodeIdOverflow(self.children[1], context.node_count())
                })?
                .digest();

            hasher::merge_in_domain(&[left_child_hash, right_child_hash], JoinNode::DOMAIN)
        };

        fingerprint_with_child_fingerprints(node_digest, &self.children, context, hash_by_node_id)
    }

    fn remap_children(self, remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        JoinNodeBuilder {
            children: [
                *remapping.get(self.children[0]).unwrap_or(&self.children[0]),
                *remapping.get(self.children[1]).unwrap_or(&self.children[1]),
            ],
            digest: self.digest,
        }
    }

    fn with_digest(mut self, digest: Word) -> Self {
        self.digest = Some(digest);
        self
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for JoinNodeBuilder {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        any::<[MastNodeId; 2]>().prop_map(Self::new).boxed()
    }
}
