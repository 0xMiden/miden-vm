use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_crypto::{Felt, Word};
use miden_formatting::prettier::{Document, PrettyPrint, const_text, nl};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastForestContributor, MastNodeExt};
use crate::{
    OPCODE_DYN, OPCODE_DYNCALL,
    mast::{DecoratorId, DecoratorStore, MastForest, MastForestError, MastNodeId},
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
    decorator_store: DecoratorStore,
}

/// Constants
impl DynNode {
    /// The domain of the Dyn block (used for control block hashing).
    pub const DYN_DOMAIN: Felt = Felt::new(OPCODE_DYN as u64);

    /// The domain of the Dyncall block (used for control block hashing).
    pub const DYNCALL_DOMAIN: Felt = Felt::new(OPCODE_DYNCALL as u64);
}

/// Default digest constants
impl DynNode {
    /// The default digest for a DynNode representing a dyncall operation.
    pub const DYNCALL_DEFAULT_DIGEST: Word = Word::new([
        Felt::new(18153562947144664406),
        Felt::new(4931170883977271433),
        Felt::new(18183136473628023536),
        Felt::new(6489282016600636545),
    ]);

    /// The default digest for a DynNode representing a dynexec operation.
    pub const DYN_DEFAULT_DIGEST: Word = Word::new([
        Felt::new(16931814232667048363),
        Felt::new(5757421171745063062),
        Felt::new(12557766285964467316),
        Felt::new(826610245118922423),
    ]);
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
        self.concatenate_decorators(
            self.node.before_enter(self.mast_forest),
            Document::Empty,
            const_text(" "),
        )
    }

    fn single_line_post_decorators(&self) -> Document {
        self.concatenate_decorators(
            self.node.after_exit(self.mast_forest),
            const_text(" "),
            Document::Empty,
        )
    }

    fn multi_line_pre_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.before_enter(self.mast_forest), Document::Empty, nl())
    }

    fn multi_line_post_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.after_exit(self.mast_forest), nl(), Document::Empty)
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

    fn to_builder(self, forest: &MastForest) -> Self::Builder {
        // Extract decorators from decorator_store if in Owned state
        match self.decorator_store {
            DecoratorStore::Owned { before_enter, after_exit, .. } => {
                let mut builder = if self.is_dyncall {
                    DynNodeBuilder::new_dyncall()
                } else {
                    DynNodeBuilder::new_dyn()
                };
                builder = builder.with_before_enter(before_enter).with_after_exit(after_exit);
                builder
            },
            DecoratorStore::Linked { id } => {
                // Extract decorators from forest storage when in Linked state
                let before_enter = forest.before_enter_decorators(id).to_vec();
                let after_exit = forest.after_exit_decorators(id).to_vec();
                let mut builder = if self.is_dyncall {
                    DynNodeBuilder::new_dyncall()
                } else {
                    DynNodeBuilder::new_dyn()
                };
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
                crate::mast::MastNode::Dyn(dyn_node) => dyn_node as *const DynNode as *const (),
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
            DynNode::DYNCALL_DEFAULT_DIGEST
        } else {
            DynNode::DYN_DEFAULT_DIGEST
        };

        DynNode {
            is_dyncall: self.is_dyncall,
            digest,
            decorator_store: DecoratorStore::new_owned_with_decorators(
                self.before_enter,
                self.after_exit,
            ),
        }
    }
}

impl MastForestContributor for DynNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        // Use the forced digest if provided, otherwise use the default digest
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else if self.is_dyncall {
            DynNode::DYNCALL_DEFAULT_DIGEST
        } else {
            DynNode::DYN_DEFAULT_DIGEST
        };

        // Determine the node ID that will be assigned
        let future_node_id = MastNodeId::new_unchecked(forest.nodes.len() as u32);

        // Store node-level decorators in the centralized NodeToDecoratorIds for efficient access
        forest.register_node_decorators(future_node_id, &self.before_enter, &self.after_exit);

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(
                DynNode {
                    is_dyncall: self.is_dyncall,
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
                DynNode::DYNCALL_DEFAULT_DIGEST
            } else {
                DynNode::DYN_DEFAULT_DIGEST
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
    pub(in crate::mast) fn add_to_forest_relaxed(
        self,
        forest: &mut MastForest,
    ) -> Result<MastNodeId, MastForestError> {
        // Use the forced digest if provided, otherwise use the default digest
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else if self.is_dyncall {
            DynNode::DYNCALL_DEFAULT_DIGEST
        } else {
            DynNode::DYN_DEFAULT_DIGEST
        };

        // Determine the node ID that will be assigned
        let future_node_id = MastNodeId::new_unchecked(forest.nodes.len() as u32);

        // Create the node in the forest with Linked variant from the start
        // Note: Decorators are already in forest.debug_info from deserialization
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(
                DynNode {
                    is_dyncall: self.is_dyncall,
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
        let mut forest = MastForest::new();
        let dyn_node_id = DynNodeBuilder::new_dyn().add_to_forest(&mut forest).unwrap();
        let dyn_node = forest.get_node_by_id(dyn_node_id).unwrap().unwrap_dyn();
        assert_eq!(
            dyn_node.digest(),
            Rpo256::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYN_DOMAIN)
        );

        let dyncall_node_id = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();
        let dyncall_node = forest.get_node_by_id(dyncall_node_id).unwrap().unwrap_dyn();
        assert_eq!(
            dyncall_node.digest(),
            Rpo256::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYNCALL_DOMAIN)
        );
    }
}
