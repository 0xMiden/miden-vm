use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_crypto::{Felt, Word};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastForestContributor, MastNodeErrorContext, MastNodeExt};
use crate::{
    Idx, OPCODE_JOIN,
    chiplets::hasher,
    mast::{
        DecoratedOpLink, DecoratorId, DecoratorStore, MastForest, MastForestError, MastNode,
        MastNodeId,
    },
    prettier::PrettyPrint,
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
    decorator_store: DecoratorStore,
}

/// Constants
impl JoinNode {
    /// The domain of the join block (used for control block hashing).
    pub const DOMAIN: Felt = Felt::new(OPCODE_JOIN as u64);
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
                .join_node
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

// SEMANTIC EQUALITY (FOR TESTING)
// ================================================================================================

#[cfg(test)]
impl JoinNode {
    /// Checks if two JoinNodes are semantically equal (i.e., they represent the same join
    /// operation).
    ///
    /// Unlike the derived PartialEq, this method works correctly with both owned and linked
    /// decorator storage by accessing the actual decorator data from the forest when needed.
    #[cfg(test)]
    pub fn semantic_eq(&self, other: &JoinNode, forest: &MastForest) -> bool {
        // Compare children
        if self.first() != other.first() || self.second() != other.second() {
            return false;
        }

        // Compare digests
        if self.digest() != other.digest() {
            return false;
        }

        // Compare before-enter decorators
        if self.before_enter(forest) != other.before_enter(forest) {
            return false;
        }

        // Compare after-exit decorators
        if self.after_exit(forest) != other.after_exit(forest) {
            return false;
        }

        true
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

    fn to_builder(self, forest: &MastForest) -> Self::Builder {
        // Extract decorators from decorator_store if in Owned state
        match self.decorator_store {
            DecoratorStore::Owned { before_enter, after_exit, .. } => {
                let mut builder = JoinNodeBuilder::new(self.children);
                builder = builder.with_before_enter(before_enter).with_after_exit(after_exit);
                builder
            },
            DecoratorStore::Linked { id } => {
                // Extract decorators from forest storage when in Linked state
                let before_enter = forest.before_enter_decorators(id).to_vec();
                let after_exit = forest.after_exit_decorators(id).to_vec();
                let mut builder = JoinNodeBuilder::new(self.children);
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
                MastNode::Join(join_node) => join_node as *const JoinNode as *const (),
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
impl proptest::prelude::Arbitrary for JoinNode {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        use crate::Felt;

        // Generate two MastNodeId values and digest for the children
        (any::<MastNodeId>(), any::<MastNodeId>(), any::<[u64; 4]>())
            .prop_map(|(first_child, second_child, digest_array)| {
                // Generate a random digest
                let digest = Word::from(digest_array.map(Felt::new));
                // Construct directly to avoid MastForest validation for arbitrary data
                JoinNode {
                    children: [first_child, second_child],
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
/// Builder for creating [`JoinNode`] instances with decorators.
#[derive(Debug)]
pub struct JoinNodeBuilder {
    children: [MastNodeId; 2],
    before_enter: Vec<DecoratorId>,
    after_exit: Vec<DecoratorId>,
    digest: Option<Word>,
}

impl JoinNodeBuilder {
    /// Creates a new builder for a JoinNode with the specified children.
    pub fn new(children: [MastNodeId; 2]) -> Self {
        Self {
            children,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
            digest: None,
        }
    }

    /// Builds the JoinNode with the specified decorators.
    pub fn build(self, mast_forest: &MastForest) -> Result<JoinNode, MastForestError> {
        let forest_len = mast_forest.nodes.len();
        if self.children[0].to_usize() >= forest_len {
            return Err(MastForestError::NodeIdOverflow(self.children[0], forest_len));
        } else if self.children[1].to_usize() >= forest_len {
            return Err(MastForestError::NodeIdOverflow(self.children[1], forest_len));
        }

        // Use the forced digest if provided, otherwise compute the digest
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
            let left_child_hash = mast_forest[self.children[0]].digest();
            let right_child_hash = mast_forest[self.children[1]].digest();

            hasher::merge_in_domain(&[left_child_hash, right_child_hash], JoinNode::DOMAIN)
        };

        Ok(JoinNode {
            children: self.children,
            digest,
            decorator_store: DecoratorStore::new_owned_with_decorators(
                self.before_enter,
                self.after_exit,
            ),
        })
    }
}

impl MastForestContributor for JoinNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        let node = self.build(forest)?;

        let JoinNode {
            children,
            digest,
            decorator_store: DecoratorStore::Owned { before_enter, after_exit, .. },
        } = node
        else {
            unreachable!("JoinNodeBuilder::build() should always return owned decorators");
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
                JoinNode {
                    children,
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
            &self.children,
            // Use the forced digest if available, otherwise compute the digest
            if let Some(forced_digest) = self.digest {
                forced_digest
            } else {
                let left_child_hash = forest[self.children[0]].digest();
                let right_child_hash = forest[self.children[1]].digest();

                crate::chiplets::hasher::merge_in_domain(
                    &[left_child_hash, right_child_hash],
                    JoinNode::DOMAIN,
                )
            },
        )
    }

    fn remap_children(
        self,
        remapping: &impl crate::LookupByIdx<crate::mast::MastNodeId, crate::mast::MastNodeId>,
    ) -> Self {
        JoinNodeBuilder {
            children: [
                *remapping.get(self.children[0]).unwrap_or(&self.children[0]),
                *remapping.get(self.children[1]).unwrap_or(&self.children[1]),
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

impl JoinNodeBuilder {
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
                JoinNode {
                    children: self.children,
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
impl proptest::prelude::Arbitrary for JoinNodeBuilder {
    type Parameters = JoinNodeBuilderParams;
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
            .prop_map(|(children, before_enter, after_exit)| {
                Self::new(children).with_before_enter(before_enter).with_after_exit(after_exit)
            })
            .boxed()
    }
}

/// Parameters for generating JoinNodeBuilder instances
#[cfg(any(test, feature = "arbitrary"))]
#[derive(Clone, Debug)]
pub struct JoinNodeBuilderParams {
    pub max_decorators: usize,
    pub max_decorator_id_u32: u32,
}

#[cfg(any(test, feature = "arbitrary"))]
impl Default for JoinNodeBuilderParams {
    fn default() -> Self {
        Self {
            max_decorators: 4,
            max_decorator_id_u32: 10,
        }
    }
}
