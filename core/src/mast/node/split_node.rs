use alloc::{boxed::Box, vec::Vec};
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{
    MastForestContributor, MastNodeExt,
    mast_forest_contributor::{NodeBuilderLifecycle, remap_child_id},
};
#[cfg(debug_assertions)]
use crate::mast::MastNode;
use crate::{
    Felt, Word,
    mast::{
        DecoratorId, DecoratorStore, ExecutableMastForest, MastForest, MastForestError,
        MastNodeFingerprint, MastNodeId, digest,
    },
    operations::opcodes,
    prettier::PrettyPrint,
    utils::LookupByIdx,
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
pub struct SplitNode {
    branches: [MastNodeId; 2],
    digest: Word,
    decorator_store: DecoratorStore,
}

impl SplitNode {
    pub(crate) fn linked_decorator_store_id(&self) -> Option<MastNodeId> {
        self.decorator_store.linked_id()
    }
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
    /// # use miden_crypto::{Word, hash::poseidon2::Poseidon2 as Hasher};
    /// # let on_true_digest = Word::default();
    /// # let on_false_digest = Word::default();
    /// Hasher::merge_in_domain(&[on_true_digest, on_false_digest], SplitNode::DOMAIN);
    /// ```
    fn digest(&self) -> Word {
        self.digest
    }

    /// Returns the decorators to be executed before this node is executed.
    fn before_enter<'a, F>(&'a self, forest: &'a F) -> &'a [DecoratorId]
    where
        F: ExecutableMastForest + ?Sized,
    {
        #[cfg(debug_assertions)]
        self.verify_node_in_forest(forest);
        self.decorator_store.before_enter(forest)
    }

    /// Returns the decorators to be executed after this node is executed.
    fn after_exit<'a, F>(&'a self, forest: &'a F) -> &'a [DecoratorId]
    where
        F: ExecutableMastForest + ?Sized,
    {
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
        let (before_enter, after_exit) = self.decorator_store.into_node_level_decorators(forest);

        SplitNodeBuilder::new(self.branches)
            .with_before_enter(before_enter)
            .with_after_exit(after_exit)
            .with_digest(self.digest)
    }

    #[cfg(debug_assertions)]
    fn verify_node_in_forest<F>(&self, forest: &F)
    where
        F: ExecutableMastForest + ?Sized,
    {
        if let Some(id) = self.decorator_store.linked_id() {
            // Verify that this node is the one stored at the given ID in the forest
            let self_ptr = self as *const Self;
            let forest_node =
                forest.get_node_by_id(id).expect("linked node id must be present in forest");
            let forest_node_ptr = match forest_node {
                MastNode::Split(split_node) => split_node as *const SplitNode as *const (),
                _ => panic!("Node type mismatch at {id:?}"),
            };
            let self_as_void = self_ptr as *const ();
            debug_assert_eq!(
                self_as_void, forest_node_ptr,
                "Node pointer mismatch: expected node at {id:?} to be self"
            );
        }
    }
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

    pub(in crate::mast) fn build_linked_with_decorators(
        self,
        node_id: MastNodeId,
    ) -> Result<(SplitNode, Vec<DecoratorId>, Vec<DecoratorId>), MastForestError> {
        let Self {
            branches,
            before_enter,
            after_exit,
            digest,
        } = self;
        let digest =
            NodeBuilderLifecycle::new(&before_enter, &after_exit, digest).forced_digest()?;

        Ok((
            SplitNode {
                branches,
                digest,
                decorator_store: DecoratorStore::Linked { id: node_id },
            },
            before_enter,
            after_exit,
        ))
    }
}

impl MastForestContributor for SplitNodeBuilder {
    #[cfg(any(test, feature = "arbitrary", feature = "testing"))]
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        NodeBuilderLifecycle::validate_children(forest, &self.branches)?;

        let lifecycle =
            NodeBuilderLifecycle::new(&self.before_enter, &self.after_exit, self.digest);
        let digest = lifecycle.digest_or_compute(|| {
            let true_branch_hash = forest[self.branches[0]].digest();
            let false_branch_hash = forest[self.branches[1]].digest();

            digest::split_digest(true_branch_hash, false_branch_hash)
        });

        lifecycle.add_linked_node(forest, |future_node_id| {
            SplitNode {
                branches: self.branches,
                digest,
                decorator_store: DecoratorStore::Linked { id: future_node_id },
            }
            .into()
        })
    }

    fn fingerprint_for_node(
        &self,
        forest: &MastForest,
        hash_by_node_id: &impl LookupByIdx<MastNodeId, MastNodeFingerprint>,
    ) -> Result<MastNodeFingerprint, MastForestError> {
        NodeBuilderLifecycle::new(&self.before_enter, &self.after_exit, self.digest).fingerprint(
            forest,
            hash_by_node_id,
            &self.branches,
            || {
                let if_branch_hash = forest[self.branches[0]].digest();
                let else_branch_hash = forest[self.branches[1]].digest();

                digest::split_digest(if_branch_hash, else_branch_hash)
            },
        )
    }

    fn remap_children(self, remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        SplitNodeBuilder {
            branches: [
                remap_child_id(self.branches[0], remapping),
                remap_child_id(self.branches[1], remapping),
            ],
            before_enter: self.before_enter,
            after_exit: self.after_exit,
            digest: self.digest,
        }
    }

    fn with_before_enter(mut self, decorators: impl Into<Vec<DecoratorId>>) -> Self {
        self.before_enter = decorators.into();
        self
    }

    fn with_after_exit(mut self, decorators: impl Into<Vec<DecoratorId>>) -> Self {
        self.after_exit = decorators.into();
        self
    }

    fn append_before_enter(&mut self, decorators: impl IntoIterator<Item = DecoratorId>) {
        self.before_enter.extend(decorators);
    }

    fn append_after_exit(&mut self, decorators: impl IntoIterator<Item = DecoratorId>) {
        self.after_exit.extend(decorators);
    }

    fn with_digest(mut self, digest: Word) -> Self {
        self.digest = Some(digest);
        self
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for SplitNodeBuilder {
    type Parameters = SplitNodeBuilderParams;
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (
            any::<[MastNodeId; 2]>(),
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
