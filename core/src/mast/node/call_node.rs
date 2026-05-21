use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_formatting::{
    hex::ToHex,
    prettier::{Document, PrettyPrint, const_text, nl, text},
};
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
        DecoratorId, ExecutableMastForest, LinkedDecoratorStore, MastForest, MastForestError,
        MastNodeFingerprint, MastNodeId, digest,
    },
    operations::opcodes,
    utils::LookupByIdx,
};

// CALL NODE
// ================================================================================================

/// A Call node describes a function call such that the callee is executed in a different execution
/// context from the currently executing code.
///
/// A call node can be of two types:
/// - A simple call: the callee is executed in the new user context.
/// - A syscall: the callee is executed in the root context.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CallNode {
    callee: MastNodeId,
    is_syscall: bool,
    digest: Word,
    decorator_store: LinkedDecoratorStore,
}

impl CallNode {
    pub(crate) fn linked_decorator_store_id(&self) -> MastNodeId {
        self.decorator_store.linked_id()
    }
}

//-------------------------------------------------------------------------------------------------
/// Constants
impl CallNode {
    /// The domain of the call block (used for control block hashing).
    pub const CALL_DOMAIN: Felt = Felt::new_unchecked(opcodes::CALL as u64);
    /// The domain of the syscall block (used for control block hashing).
    pub const SYSCALL_DOMAIN: Felt = Felt::new_unchecked(opcodes::SYSCALL as u64);
}

//-------------------------------------------------------------------------------------------------
/// Public accessors
impl CallNode {
    /// Returns the ID of the node to be invoked by this call node.
    pub fn callee(&self) -> MastNodeId {
        self.callee
    }

    /// Returns true if this call node represents a syscall.
    pub fn is_syscall(&self) -> bool {
        self.is_syscall
    }

    /// Returns the domain of this call node.
    pub fn domain(&self) -> Felt {
        if self.is_syscall() {
            Self::SYSCALL_DOMAIN
        } else {
            Self::CALL_DOMAIN
        }
    }
}

// PRETTY PRINTING
// ================================================================================================

impl CallNode {
    pub(super) fn to_pretty_print<'a>(
        &'a self,
        mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        CallNodePrettyPrint { node: self, mast_forest }
    }

    pub(super) fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        CallNodePrettyPrint { node: self, mast_forest }
    }
}

struct CallNodePrettyPrint<'a> {
    node: &'a CallNode,
    mast_forest: &'a MastForest,
}

impl CallNodePrettyPrint<'_> {
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

impl PrettyPrint for CallNodePrettyPrint<'_> {
    fn render(&self) -> Document {
        let call_or_syscall = {
            let callee_digest = self.mast_forest[self.node.callee].digest();
            if self.node.is_syscall {
                const_text("syscall")
                    + const_text(".")
                    + text(callee_digest.as_bytes().to_hex_with_prefix())
            } else {
                const_text("call")
                    + const_text(".")
                    + text(callee_digest.as_bytes().to_hex_with_prefix())
            }
        };

        let single_line = self.single_line_pre_decorators()
            + call_or_syscall.clone()
            + self.single_line_post_decorators();
        let multi_line =
            self.multi_line_pre_decorators() + call_or_syscall + self.multi_line_post_decorators();

        single_line | multi_line
    }
}

impl fmt::Display for CallNodePrettyPrint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

// MAST NODE TRAIT IMPLEMENTATION
// ================================================================================================

impl MastNodeExt for CallNode {
    /// Returns a commitment to this Call node.
    ///
    /// The commitment is computed as a hash of the callee and an empty word ([ZERO; 4]) in the
    /// domain defined by either [Self::CALL_DOMAIN] or [Self::SYSCALL_DOMAIN], depending on
    /// whether the node represents a simple call or a syscall - i.e.,:
    /// ```
    /// # use miden_core::mast::CallNode;
    /// # use miden_crypto::{Word, hash::poseidon2::Poseidon2 as Hasher};
    /// # let callee_digest = Word::default();
    /// Hasher::merge_in_domain(&[callee_digest, Word::default()], CallNode::CALL_DOMAIN);
    /// ```
    /// or
    /// ```
    /// # use miden_core::mast::CallNode;
    /// # use miden_crypto::{Word, hash::poseidon2::Poseidon2 as Hasher};
    /// # let callee_digest = Word::default();
    /// Hasher::merge_in_domain(&[callee_digest, Word::default()], CallNode::SYSCALL_DOMAIN);
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
        Box::new(CallNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(CallNode::to_pretty_print(self, mast_forest))
    }

    fn has_children(&self) -> bool {
        true
    }

    fn append_children_to(&self, target: &mut Vec<MastNodeId>) {
        target.push(self.callee());
    }

    fn for_each_child<F>(&self, mut f: F)
    where
        F: FnMut(MastNodeId),
    {
        f(self.callee());
    }

    fn domain(&self) -> Felt {
        self.domain()
    }

    type Builder = CallNodeBuilder;

    fn to_builder(self, forest: &MastForest) -> Self::Builder {
        let (before_enter, after_exit) = self.decorator_store.into_node_level_decorators(forest);
        let builder = if self.is_syscall {
            CallNodeBuilder::new_syscall(self.callee)
        } else {
            CallNodeBuilder::new(self.callee)
        };

        builder
            .with_before_enter(before_enter)
            .with_after_exit(after_exit)
            .with_digest(self.digest)
    }

    #[cfg(debug_assertions)]
    fn verify_node_in_forest<F>(&self, forest: &F)
    where
        F: ExecutableMastForest + ?Sized,
    {
        let id = self.decorator_store.linked_id();
        // Verify that this node is the one stored at the given ID in the forest
        let self_ptr = self as *const Self;
        let forest_node =
            forest.get_node_by_id(id).expect("linked node id must be present in forest");
        let forest_node_ptr = match forest_node {
            MastNode::Call(call_node) => call_node as *const CallNode as *const (),
            _ => panic!("Node type mismatch at {id:?}"),
        };
        let self_as_void = self_ptr as *const ();
        debug_assert_eq!(
            self_as_void, forest_node_ptr,
            "Node pointer mismatch: expected node at {id:?} to be self"
        );
    }
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`CallNode`] instances with decorators.
#[derive(Debug)]
pub struct CallNodeBuilder {
    callee: MastNodeId,
    is_syscall: bool,
    before_enter: Vec<DecoratorId>,
    after_exit: Vec<DecoratorId>,
    digest: Option<Word>,
}

impl CallNodeBuilder {
    /// Creates a new builder for a CallNode with the specified callee.
    pub fn new(callee: MastNodeId) -> Self {
        Self {
            callee,
            is_syscall: false,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
            digest: None,
        }
    }

    /// Creates a new builder for a syscall CallNode with the specified callee.
    pub fn new_syscall(callee: MastNodeId) -> Self {
        Self {
            callee,
            is_syscall: true,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
            digest: None,
        }
    }

    pub(in crate::mast) fn build_linked_with_decorators(
        self,
        node_id: MastNodeId,
    ) -> Result<(CallNode, Vec<DecoratorId>, Vec<DecoratorId>), MastForestError> {
        let Self {
            callee,
            is_syscall,
            before_enter,
            after_exit,
            digest,
        } = self;
        let digest =
            NodeBuilderLifecycle::new(&before_enter, &after_exit, digest).forced_digest()?;

        Ok((
            CallNode {
                callee,
                is_syscall,
                digest,
                decorator_store: LinkedDecoratorStore::linked(node_id),
            },
            before_enter,
            after_exit,
        ))
    }
}

impl MastForestContributor for CallNodeBuilder {
    #[cfg(any(test, feature = "arbitrary", feature = "testing"))]
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        NodeBuilderLifecycle::validate_children(forest, &[self.callee])?;

        let lifecycle =
            NodeBuilderLifecycle::new(&self.before_enter, &self.after_exit, self.digest);
        let digest = lifecycle.digest_or_compute(|| {
            let callee_digest = forest[self.callee].digest();

            digest::call_digest(callee_digest, self.is_syscall)
        });

        lifecycle.add_linked_node(forest, |future_node_id| {
            CallNode {
                callee: self.callee,
                is_syscall: self.is_syscall,
                digest,
                decorator_store: LinkedDecoratorStore::linked(future_node_id),
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
            &[self.callee],
            || {
                let callee_digest = forest[self.callee].digest();

                digest::call_digest(callee_digest, self.is_syscall)
            },
        )
    }

    fn remap_children(self, remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        CallNodeBuilder {
            callee: remap_child_id(self.callee, remapping),
            is_syscall: self.is_syscall,
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
impl proptest::prelude::Arbitrary for CallNodeBuilder {
    type Parameters = CallNodeBuilderParams;
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (
            any::<MastNodeId>(),
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
            .prop_map(|(callee, is_syscall, before_enter, after_exit)| {
                let mut builder = if is_syscall {
                    Self::new_syscall(callee)
                } else {
                    Self::new(callee)
                };
                builder = builder.with_before_enter(before_enter).with_after_exit(after_exit);
                builder
            })
            .boxed()
    }
}

/// Parameters for generating CallNodeBuilder instances
#[cfg(any(test, feature = "arbitrary"))]
#[derive(Clone, Debug)]
pub struct CallNodeBuilderParams {
    pub max_decorators: usize,
    pub max_decorator_id_u32: u32,
}

#[cfg(any(test, feature = "arbitrary"))]
impl Default for CallNodeBuilderParams {
    fn default() -> Self {
        Self {
            max_decorators: 4,
            max_decorator_id_u32: 10,
        }
    }
}
