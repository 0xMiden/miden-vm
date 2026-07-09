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

// LOOP NODE
// ================================================================================================

/// A Loop node defines condition-controlled iterative execution. When the VM encounters a Loop
/// node, it will keep executing the body of the loop as long as the top of the stack is `1``,
/// except for the encounter which it executes unconditionally.
///
/// The loop is exited when at the end of executing the loop body the top of the stack is `0``.
/// If the top of the stack is neither `0` nor `1` when the condition is checked, the execution
/// fails.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct LoopNode {
    body: MastNodeId,
    digest: Word,
}

/// Constants
impl LoopNode {
    /// The domain of the loop node (used for control block hashing).
    pub const DOMAIN: Felt = Felt::new_unchecked(opcodes::LOOP as u64);
}

impl LoopNode {
    /// Returns the ID of the node presenting the body of the loop.
    pub fn body(&self) -> MastNodeId {
        self.body
    }
}

// PRETTY PRINTING
// ================================================================================================

impl LoopNode {
    pub(super) fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        LoopNodePrettyPrint { loop_node: self, mast_forest }
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        LoopNodePrettyPrint { loop_node: self, mast_forest }
    }
}

struct LoopNodePrettyPrint<'a> {
    loop_node: &'a LoopNode,
    mast_forest: &'a MastForest,
}

impl PrettyPrint for LoopNodePrettyPrint<'_> {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let loop_body = self.mast_forest[self.loop_node.body].to_pretty_print(self.mast_forest);

        indent(4, const_text("loop") + nl() + loop_body.render()) + nl() + const_text("end")
    }
}

impl fmt::Display for LoopNodePrettyPrint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

// MAST NODE TRAIT IMPLEMENTATION
// ================================================================================================

impl MastNodeExt for LoopNode {
    /// Returns a commitment to this Loop node.
    ///
    /// The commitment is computed as a hash of the loop body and an empty word ([ZERO; 4]) in
    /// the domain defined by [Self::DOMAIN] - i..e,:
    /// ```
    /// # use miden_core::mast::LoopNode;
    /// # use miden_crypto::{Word, hash::poseidon2::Poseidon2 as Hasher};
    /// # let body_digest = Word::default();
    /// Hasher::merge_in_domain(&[body_digest, Word::default()], LoopNode::DOMAIN);
    /// ```
    fn digest(&self) -> Word {
        self.digest
    }

    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a> {
        Box::new(LoopNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(LoopNode::to_pretty_print(self, mast_forest))
    }

    fn has_children(&self) -> bool {
        true
    }

    fn append_children_to(&self, target: &mut Vec<MastNodeId>) {
        target.push(self.body());
    }

    fn for_each_child<F>(&self, mut f: F)
    where
        F: FnMut(MastNodeId),
    {
        f(self.body());
    }

    fn domain(&self) -> Felt {
        Self::DOMAIN
    }

    type Builder = LoopNodeBuilder;

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        LoopNodeBuilder::new(self.body).with_digest(self.digest)
    }
}

// ARBITRARY IMPLEMENTATION
// ================================================================================================

#[cfg(all(feature = "arbitrary", test))]
impl proptest::prelude::Arbitrary for LoopNode {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        use crate::Felt;

        // Generate one MastNodeId value and digest for the body
        (any::<MastNodeId>(), any::<[u64; 4]>())
            .prop_map(|(body, digest_array)| {
                // Generate a random digest
                let digest = Word::from(digest_array.map(Felt::new_unchecked));
                // Construct directly to avoid MastForest validation for arbitrary data
                LoopNode {
                    body,
                    digest,
                }
            })
            .no_shrink()  // Pure random values, no meaningful shrinking pattern
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`LoopNode`] instances.
#[derive(Debug)]
pub struct LoopNodeBuilder {
    body: MastNodeId,
    digest: Option<Word>,
}

impl LoopNodeBuilder {
    /// Creates a new builder for a LoopNode with the specified body.
    pub fn new(body: MastNodeId) -> Self {
        Self { body, digest: None }
    }

    /// Builds the LoopNode.
    pub fn build(self, context: &impl MastNodeContext) -> Result<LoopNode, MastForestError> {
        let body = context
            .get_node_by_id(self.body)
            .ok_or_else(|| MastForestError::NodeIdOverflow(self.body, context.node_count()))?;

        // Use the forced digest if provided, otherwise compute the digest
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
            let body_hash = body.digest();

            hasher::merge_in_domain(&[body_hash, Word::default()], LoopNode::DOMAIN)
        };

        Ok(LoopNode { body: self.body, digest })
    }

    pub(in crate::mast) fn build_linked(self) -> Result<LoopNode, MastForestError> {
        Ok(LoopNode {
            body: self.body,
            digest: self.digest.ok_or(MastForestError::DigestRequiredForDeserialization)?,
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl LoopNodeBuilder {
    /// Adds this builder to a mutable forest for test and arbitrary data construction.
    pub fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        let node = self.build(forest)?;
        forest.nodes.push(node.into()).map_err(|_| MastForestError::TooManyNodes)
    }
}

impl MastForestContributor for LoopNodeBuilder {
    fn fingerprint_for_node(
        &self,
        context: &impl MastNodeContext,
        hash_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
    ) -> Result<Word, MastForestError> {
        let node_digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
            let body_hash = context
                .get_node_by_id(self.body)
                .ok_or_else(|| MastForestError::NodeIdOverflow(self.body, context.node_count()))?
                .digest();

            hasher::merge_in_domain(&[body_hash, Word::default()], LoopNode::DOMAIN)
        };

        fingerprint_with_child_fingerprints(node_digest, &[self.body], context, hash_by_node_id)
    }

    fn remap_children(self, remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        LoopNodeBuilder {
            body: *remapping.get(self.body).unwrap_or(&self.body),
            digest: self.digest,
        }
    }

    fn with_digest(mut self, digest: Word) -> Self {
        self.digest = Some(digest);
        self
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for LoopNodeBuilder {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        any::<MastNodeId>().prop_map(Self::new).boxed()
    }
}
