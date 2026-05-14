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
        MastNodeFingerprint, MastNodeId,
        digest,
    },
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
    decorator_store: DecoratorStore,
}

impl LoopNode {
    pub(super) fn into_linked_decorator_store(mut self, node_id: MastNodeId) -> Self {
        self.decorator_store = DecoratorStore::Linked { id: node_id };
        self
    }

    pub(crate) fn linked_decorator_store_id(&self) -> Option<MastNodeId> {
        self.decorator_store.linked_id()
    }
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
            + indent(4, const_text("loop") + nl() + loop_body.render())
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
    /// # use miden_crypto::{Word, hash::poseidon2::Poseidon2 as Hasher};
    /// # let body_digest = Word::default();
    /// Hasher::merge_in_domain(&[body_digest, Word::default()], LoopNode::DOMAIN);
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
                builder = builder
                    .with_before_enter(before_enter)
                    .with_after_exit(after_exit)
                    .with_digest(self.digest);
                builder
            },
            DecoratorStore::Linked { id } => {
                // Extract decorators from forest storage when in Linked state
                let before_enter = forest.before_enter_decorators(id).to_vec();
                let after_exit = forest.after_exit_decorators(id).to_vec();
                let mut builder = LoopNodeBuilder::new(self.body);
                builder = builder
                    .with_before_enter(before_enter)
                    .with_after_exit(after_exit)
                    .with_digest(self.digest);
                builder
            },
        }
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
                MastNode::Loop(loop_node) => loop_node as *const LoopNode as *const (),
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
        NodeBuilderLifecycle::validate_children(mast_forest, &[self.body])?;

        let lifecycle =
            NodeBuilderLifecycle::new(&self.before_enter, &self.after_exit, self.digest);
        let digest = lifecycle.digest_or_compute(|| {
            let body_hash = mast_forest[self.body].digest();

            digest::loop_digest(body_hash)
        });

        Ok(LoopNode {
            body: self.body,
            digest,
            decorator_store: DecoratorStore::new_owned_with_decorators(
                self.before_enter,
                self.after_exit,
            ),
        })
    }

    pub(in crate::mast) fn build_with_forced_digest(self) -> Result<LoopNode, MastForestError> {
        let digest = NodeBuilderLifecycle::new(&self.before_enter, &self.after_exit, self.digest)
            .forced_digest()?;

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
    #[cfg(any(test, feature = "arbitrary", feature = "testing"))]
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        NodeBuilderLifecycle::validate_children(forest, &[self.body])?;

        let lifecycle =
            NodeBuilderLifecycle::new(&self.before_enter, &self.after_exit, self.digest);
        let digest = lifecycle.digest_or_compute(|| {
            let body_hash = forest[self.body].digest();

            digest::loop_digest(body_hash)
        });

        lifecycle.add_linked_node(forest, |future_node_id| {
            LoopNode {
                body: self.body,
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
            &[self.body],
            || {
                let body_hash = forest[self.body].digest();

                digest::loop_digest(body_hash)
            },
        )
    }

    fn remap_children(self, remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        LoopNodeBuilder {
            body: remap_child_id(self.body, remapping),
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
impl proptest::prelude::Arbitrary for LoopNodeBuilder {
    type Parameters = LoopNodeBuilderParams;
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (
            any::<MastNodeId>(),
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
