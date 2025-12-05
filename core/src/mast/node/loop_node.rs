use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_crypto::{Felt, Word};
use miden_formatting::prettier::PrettyPrint;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastForestContributor, MastNodeExt};
use crate::{
    Idx, OPCODE_LOOP,
    chiplets::hasher,
    mast::{DecoratorId, DecoratorStore, MastForest, MastForestError, MastNode, MastNodeId},
};

// LOOP NODE
// ================================================================================================

/// A Loop node defines condition-controlled iterative execution. When the VM encounters a Loop
/// node, it will keep executing the body of the loop as long as the top of the stack is `1``.
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
    decorator_store: DecoratorStore,
}

/// Constants
impl LoopNode {
    /// The domain of the loop node (used for control block hashing).
    pub const DOMAIN: Felt = Felt::new(OPCODE_LOOP as u64);
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

impl crate::prettier::PrettyPrint for LoopNodePrettyPrint<'_> {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let pre_decorators = {
            let mut pre_decorators = self
                .loop_node
                .before_enter(self.mast_forest)
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
                .loop_node
                .after_exit(self.mast_forest)
                .iter()
                .map(|&decorator_id| self.mast_forest[decorator_id].render())
                .reduce(|acc, doc| acc + const_text(" ") + doc)
                .unwrap_or_default();
            if !post_decorators.is_empty() {
                post_decorators = nl() + post_decorators;
            }

            post_decorators
        };

        let loop_body = self.mast_forest[self.loop_node.body].to_pretty_print(self.mast_forest);

        pre_decorators
            + indent(4, const_text("while.true") + nl() + loop_body.render())
            + nl()
            + const_text("end")
            + post_decorators
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
    /// # use miden_crypto::{Word, hash::rpo::Rpo256 as Hasher};
    /// # let body_digest = Word::default();
    /// Hasher::merge_in_domain(&[body_digest, Word::default()], LoopNode::DOMAIN);
    /// ```
    fn digest(&self) -> Word {
        self.digest
    }

    /// Returns the decorators to be executed before this node is executed.
    fn before_enter<'a>(&'a self, forest: &'a MastForest) -> &'a [DecoratorId] {
        #[cfg(debug_assertions)]
        self.verify_node_in_forest(forest);
        self.decorator_store.before_enter(forest)
    }

    /// Returns the decorators to be executed after this node is executed.
    fn after_exit<'a>(&'a self, forest: &'a MastForest) -> &'a [DecoratorId] {
        #[cfg(debug_assertions)]
        self.verify_node_in_forest(forest);
        self.decorator_store.after_exit(forest)
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

    fn to_builder(self, forest: &MastForest) -> Self::Builder {
        // Extract decorators from decorator_store if in Owned state
        match self.decorator_store {
            DecoratorStore::Owned { before_enter, after_exit, .. } => {
                let mut builder = LoopNodeBuilder::new(self.body);
                builder = builder.with_before_enter(before_enter).with_after_exit(after_exit);
                builder
            },
            DecoratorStore::Linked { id } => {
                // Extract decorators from forest storage when in Linked state
                let before_enter = forest.before_enter_decorators(id).to_vec();
                let after_exit = forest.after_exit_decorators(id).to_vec();
                let mut builder = LoopNodeBuilder::new(self.body);
                builder = builder.with_before_enter(before_enter).with_after_exit(after_exit);
                builder
            },
        }
    }

    #[cfg(debug_assertions)]
    fn verify_node_in_forest(&self, forest: &MastForest) {
        if let Some(id) = self.decorator_store.linked_id() {
            // Verify that this node is the one stored at the given ID in the forest
            let self_ptr = self as *const Self;
            let forest_node = &forest.nodes[id];
            let forest_node_ptr = match forest_node {
                MastNode::Loop(loop_node) => loop_node as *const LoopNode as *const (),
                _ => panic!("Node type mismatch at {:?}", id),
            };
            let self_as_void = self_ptr as *const ();
            debug_assert_eq!(
                self_as_void, forest_node_ptr,
                "Node pointer mismatch: expected node at {:?} to be self",
                id
            );
        }
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
                let digest = Word::from(digest_array.map(Felt::new));
                // Construct directly to avoid MastForest validation for arbitrary data
                LoopNode {
                    body,
                    digest,
                    decorator_store: DecoratorStore::default(),
                }
            })
            .no_shrink()  // Pure random values, no meaningful shrinking pattern
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`LoopNode`] instances with decorators.
#[derive(Debug)]
pub struct LoopNodeBuilder {
    body: MastNodeId,
    before_enter: Vec<DecoratorId>,
    after_exit: Vec<DecoratorId>,
    digest: Option<Word>,
}

impl LoopNodeBuilder {
    /// Creates a new builder for a LoopNode with the specified body.
    pub fn new(body: MastNodeId) -> Self {
        Self {
            body,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
            digest: None,
        }
    }

    /// Builds the LoopNode with the specified decorators.
    pub fn build(self, mast_forest: &MastForest) -> Result<LoopNode, MastForestError> {
        if self.body.to_usize() >= mast_forest.nodes.len() {
            return Err(MastForestError::NodeIdOverflow(self.body, mast_forest.nodes.len()));
        }

        // Use the forced digest if provided, otherwise compute the digest
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
            let body_hash = mast_forest[self.body].digest();

            hasher::merge_in_domain(&[body_hash, Word::default()], LoopNode::DOMAIN)
        };

        Ok(LoopNode {
            body: self.body,
            digest,
            decorator_store: DecoratorStore::new_owned_with_decorators(
                self.before_enter,
                self.after_exit,
            ),
        })
    }
}

impl MastForestContributor for LoopNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        let node = self.build(forest)?;

        let LoopNode {
            body,
            digest,
            decorator_store: DecoratorStore::Owned { before_enter, after_exit, .. },
        } = node
        else {
            unreachable!("LoopNodeBuilder::build() should always return owned decorators");
        };

        // Determine the node ID that will be assigned
        let future_node_id = MastNodeId::new_unchecked(forest.nodes.len() as u32);

        // Store node-level decorators in the centralized NodeToDecoratorIds for efficient access
        forest
            .debug_info
            .register_node_decorators(future_node_id, &before_enter, &after_exit);

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(
                LoopNode {
                    body,
                    digest,
                    decorator_store: DecoratorStore::Linked { id: future_node_id },
                }
                .into(),
            )
            .map_err(|_| MastForestError::TooManyNodes)?;

        Ok(node_id)
    }

    fn fingerprint_for_node(
        &self,
        forest: &MastForest,
        hash_by_node_id: &impl crate::LookupByIdx<MastNodeId, crate::mast::MastNodeFingerprint>,
    ) -> Result<crate::mast::MastNodeFingerprint, MastForestError> {
        // Use the fingerprint_from_parts helper function
        crate::mast::node_fingerprint::fingerprint_from_parts(
            forest,
            hash_by_node_id,
            &self.before_enter,
            &self.after_exit,
            &[self.body],
            // Use the forced digest if available, otherwise compute the digest
            if let Some(forced_digest) = self.digest {
                forced_digest
            } else {
                let body_hash = forest[self.body].digest();

                crate::chiplets::hasher::merge_in_domain(
                    &[body_hash, miden_crypto::Word::default()],
                    LoopNode::DOMAIN,
                )
            },
        )
    }

    fn remap_children(
        self,
        remapping: &impl crate::LookupByIdx<crate::mast::MastNodeId, crate::mast::MastNodeId>,
    ) -> Self {
        LoopNodeBuilder {
            body: *remapping.get(self.body).unwrap_or(&self.body),
            before_enter: self.before_enter,
            after_exit: self.after_exit,
            digest: self.digest,
        }
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

impl LoopNodeBuilder {
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

        let future_node_id = MastNodeId::new_unchecked(forest.nodes.len() as u32);

        // Store node-level decorators in the centralized NodeToDecoratorIds for efficient access
        forest.register_node_decorators(future_node_id, &self.before_enter, &self.after_exit);

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(
                LoopNode {
                    body: self.body,
                    digest,
                    decorator_store: DecoratorStore::Linked { id: future_node_id },
                }
                .into(),
            )
            .map_err(|_| MastForestError::TooManyNodes)?;

        Ok(node_id)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for LoopNodeBuilder {
    type Parameters = LoopNodeBuilderParams;
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (
            any::<crate::mast::MastNodeId>(),
            proptest::collection::vec(
                super::arbitrary::decorator_id_strategy(params.max_decorator_id_u32),
                0..=params.max_decorators,
            ),
            proptest::collection::vec(
                super::arbitrary::decorator_id_strategy(params.max_decorator_id_u32),
                0..=params.max_decorators,
            ),
        )
            .prop_map(|(body, before_enter, after_exit)| {
                Self::new(body).with_before_enter(before_enter).with_after_exit(after_exit)
            })
            .boxed()
    }
}

/// Parameters for generating LoopNodeBuilder instances
#[cfg(any(test, feature = "arbitrary"))]
#[derive(Clone, Debug)]
pub struct LoopNodeBuilderParams {
    pub max_decorators: usize,
    pub max_decorator_id_u32: u32,
}

#[cfg(any(test, feature = "arbitrary"))]
impl Default for LoopNodeBuilderParams {
    fn default() -> Self {
        Self {
            max_decorators: 4,
            max_decorator_id_u32: 10,
        }
    }
}
