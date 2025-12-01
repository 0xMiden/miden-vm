use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_crypto::{Felt, Word};
use miden_formatting::prettier::PrettyPrint;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastForestContributor, MastNodeErrorContext, MastNodeExt};
use crate::{
    Idx, OPCODE_SPLIT,
    chiplets::hasher,
    mast::{
        DecoratedOpLink, DecoratorId, DecoratorStore, MastForest, MastForestError, MastNode,
        MastNodeId,
    },
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
    decorator_store: DecoratorStore,
}

/// Constants
impl SplitNode {
    /// The domain of the split node (used for control block hashing).
    pub const DOMAIN: Felt = Felt::new(OPCODE_SPLIT as u64);
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

impl MastNodeErrorContext for SplitNode {
    fn decorators<'a>(
        &'a self,
        forest: &'a MastForest,
    ) -> impl Iterator<Item = DecoratedOpLink> + 'a {
        // Use the decorator_store for efficient O(1) decorator access
        let before_enter = self.decorator_store.before_enter(forest);
        let after_exit = self.decorator_store.after_exit(forest);

        // Convert decorators to DecoratedOpLink tuples
        before_enter
            .iter()
            .map(|&deco_id| (0, deco_id))
            .chain(after_exit.iter().map(|&deco_id| (1, deco_id)))
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

        let pre_decorators = {
            let mut pre_decorators = self
                .split_node
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
                .split_node
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

        let true_branch = self.mast_forest[self.split_node.on_true()].to_pretty_print(self.mast_forest);
        let false_branch = self.mast_forest[self.split_node.on_false()].to_pretty_print(self.mast_forest);

        let mut doc = pre_decorators;
        doc += indent(4, const_text("if.true") + nl() + true_branch.render()) + nl();
        doc += indent(4, const_text("else") + nl() + false_branch.render());
        doc += nl() + const_text("end");
        doc + post_decorators
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
    /// # use miden_crypto::{Word, hash::rpo::Rpo256 as Hasher};
    /// # let on_true_digest = Word::default();
    /// # let on_false_digest = Word::default();
    /// Hasher::merge_in_domain(&[on_true_digest, on_false_digest], SplitNode::DOMAIN);
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

    fn to_builder(self, forest: &MastForest) -> Self::Builder {
        // Extract decorators from decorator_store if in Owned state
        match self.decorator_store {
            DecoratorStore::Owned { before_enter, after_exit, .. } => {
                let mut builder = SplitNodeBuilder::new(self.branches);
                builder = builder.with_before_enter(before_enter).with_after_exit(after_exit);
                builder
            },
            DecoratorStore::Linked { id } => {
                // Extract decorators from forest storage when in Linked state
                let before_enter = forest.before_enter_decorators(id).to_vec();
                let after_exit = forest.after_exit_decorators(id).to_vec();
                let mut builder = SplitNodeBuilder::new(self.branches);
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
                MastNode::Split(split_node) => split_node as *const SplitNode as *const (),
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
impl proptest::prelude::Arbitrary for SplitNode {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        use crate::Felt;

        // Generate two MastNodeId values and digest for the children
        (any::<MastNodeId>(), any::<MastNodeId>(), any::<[u64; 4]>())
            .prop_map(|(true_branch, false_branch, digest_array)| {
                // Generate a random digest
                let digest = Word::from(digest_array.map(Felt::new));
                // Construct directly to avoid MastForest validation for arbitrary data
                SplitNode {
                    branches: [true_branch, false_branch],
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
/// Builder for creating [`SplitNode`] instances with decorators.
#[derive(Debug)]
pub struct SplitNodeBuilder {
    branches: [MastNodeId; 2],
    before_enter: Vec<DecoratorId>,
    after_exit: Vec<DecoratorId>,
    digest: Option<Word>,
}

impl SplitNodeBuilder {
    /// Creates a new builder for a SplitNode with the specified branches.
    pub fn new(branches: [MastNodeId; 2]) -> Self {
        Self {
            branches,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
            digest: None,
        }
    }

    /// Builds the SplitNode with the specified decorators.
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

        Ok(SplitNode {
            branches: self.branches,
            digest,
            decorator_store: DecoratorStore::new_owned_with_decorators(
                self.before_enter,
                self.after_exit,
            ),
        })
    }
}

impl MastForestContributor for SplitNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        let node = self.build(forest)?;

        let SplitNode {
            branches,
            digest,
            decorator_store: DecoratorStore::Owned { before_enter, after_exit, .. },
        } = node
        else {
            unreachable!("SplitNodeBuilder::build() should always return owned decorators");
        };

        // Determine the node ID that will be assigned
        let future_node_id = MastNodeId::new_unchecked(forest.nodes.len() as u32);

        // Store node-level decorators in the centralized NodeToDecoratorIds for efficient access
        forest.register_node_decorators(future_node_id, &before_enter, &after_exit);

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(
                SplitNode {
                    branches,
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
            &self.branches,
            // Use the forced digest if available, otherwise compute the digest
            if let Some(forced_digest) = self.digest {
                forced_digest
            } else {
                let if_branch_hash = forest[self.branches[0]].digest();
                let else_branch_hash = forest[self.branches[1]].digest();

                crate::chiplets::hasher::merge_in_domain(
                    &[if_branch_hash, else_branch_hash],
                    SplitNode::DOMAIN,
                )
            },
        )
    }

    fn remap_children(
        self,
        remapping: &impl crate::LookupByIdx<crate::mast::MastNodeId, crate::mast::MastNodeId>,
    ) -> Self {
        SplitNodeBuilder {
            branches: [
                *remapping.get(self.branches[0]).unwrap_or(&self.branches[0]),
                *remapping.get(self.branches[1]).unwrap_or(&self.branches[1]),
            ],
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
            panic!("Digest is required for deserialization")
        };

        let future_node_id = MastNodeId::new_unchecked(forest.nodes.len() as u32);

        // Store node-level decorators in the centralized NodeToDecoratorIds for efficient access
        forest.register_node_decorators(future_node_id, &self.before_enter, &self.after_exit);

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(
                SplitNode {
                    branches: self.branches,
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
impl proptest::prelude::Arbitrary for SplitNodeBuilder {
    type Parameters = SplitNodeBuilderParams;
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (
            any::<[crate::mast::MastNodeId; 2]>(),
            proptest::collection::vec(
                super::arbitrary::decorator_id_strategy(params.max_decorator_id_u32),
                0..=params.max_decorators,
            ),
            proptest::collection::vec(
                super::arbitrary::decorator_id_strategy(params.max_decorator_id_u32),
                0..=params.max_decorators,
            ),
        )
            .prop_map(|(branches, before_enter, after_exit)| {
                Self::new(branches).with_before_enter(before_enter).with_after_exit(after_exit)
            })
            .boxed()
    }
}

/// Parameters for generating SplitNodeBuilder instances
#[cfg(any(test, feature = "arbitrary"))]
#[derive(Clone, Debug)]
pub struct SplitNodeBuilderParams {
    pub max_decorators: usize,
    pub max_decorator_id_u32: u32,
}

#[cfg(any(test, feature = "arbitrary"))]
impl Default for SplitNodeBuilderParams {
    fn default() -> Self {
        Self {
            max_decorators: 4,
            max_decorator_id_u32: 10,
        }
    }
}
