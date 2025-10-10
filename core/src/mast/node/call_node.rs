use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_crypto::{Felt, Word};
use miden_formatting::{
    hex::ToHex,
    prettier::{Document, PrettyPrint, const_text, nl, text},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastForestContributor, MastNodeErrorContext, MastNodeExt};
use crate::{
    Idx, OPCODE_CALL, OPCODE_SYSCALL,
    chiplets::hasher,
    mast::{DecoratedOpLink, DecoratorId, MastForest, MastForestError, MastNodeId},
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
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct CallNode {
    callee: MastNodeId,
    is_syscall: bool,
    digest: Word,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    before_enter: Vec<DecoratorId>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    after_exit: Vec<DecoratorId>,
}

//-------------------------------------------------------------------------------------------------
/// Constants
impl CallNode {
    /// The domain of the call block (used for control block hashing).
    pub const CALL_DOMAIN: Felt = Felt::new(OPCODE_CALL as u64);
    /// The domain of the syscall block (used for control block hashing).
    pub const SYSCALL_DOMAIN: Felt = Felt::new(OPCODE_SYSCALL as u64);
}

//-------------------------------------------------------------------------------------------------
/// Constructors
impl CallNode {
    /// Returns a new [`CallNode`] instantiated with the specified callee.
    pub(in crate::mast) fn new(
        callee: MastNodeId,
        mast_forest: &MastForest,
    ) -> Result<Self, MastForestError> {
        if callee.to_usize() >= mast_forest.nodes.len() {
            return Err(MastForestError::NodeIdOverflow(callee, mast_forest.nodes.len()));
        }
        let digest = {
            let callee_digest = mast_forest[callee].digest();

            hasher::merge_in_domain(&[callee_digest, Word::default()], Self::CALL_DOMAIN)
        };

        Ok(Self {
            callee,
            is_syscall: false,
            digest,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        })
    }

    /// Returns a new [`CallNode`] from values that are assumed to be correct.
    /// Should only be used when the source of the inputs is trusted (e.g. deserialization).
    pub(in crate::mast) fn new_unsafe(callee: MastNodeId, digest: Word) -> Self {
        Self {
            callee,
            is_syscall: false,
            digest,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }

    /// Returns a new [`CallNode`] instantiated with the specified callee and marked as a kernel
    /// call.
    #[allow(dead_code)]
    pub(in crate::mast) fn new_syscall(
        callee: MastNodeId,
        mast_forest: &MastForest,
    ) -> Result<Self, MastForestError> {
        if callee.to_usize() >= mast_forest.nodes.len() {
            return Err(MastForestError::NodeIdOverflow(callee, mast_forest.nodes.len()));
        }
        let digest = {
            let callee_digest = mast_forest[callee].digest();

            hasher::merge_in_domain(&[callee_digest, Word::default()], Self::SYSCALL_DOMAIN)
        };

        Ok(Self {
            callee,
            is_syscall: true,
            digest,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        })
    }

    /// Returns a new syscall [`CallNode`] from values that are assumed to be correct.
    /// Should only be used when the source of the inputs is trusted (e.g. deserialization).
    pub(in crate::mast) fn new_syscall_unsafe(callee: MastNodeId, digest: Word) -> Self {
        Self {
            callee,
            is_syscall: true,
            digest,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }
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

impl MastNodeErrorContext for CallNode {
    fn decorators(&self) -> impl Iterator<Item = DecoratedOpLink> {
        self.before_enter.iter().chain(&self.after_exit).copied().enumerate()
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
        self.concatenate_decorators(self.node.before_enter(), Document::Empty, const_text(" "))
    }

    fn single_line_post_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.after_exit(), const_text(" "), Document::Empty)
    }

    fn multi_line_pre_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.before_enter(), Document::Empty, nl())
    }

    fn multi_line_post_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.after_exit(), nl(), Document::Empty)
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
    /// # use miden_crypto::{Word, hash::rpo::Rpo256 as Hasher};
    /// # let callee_digest = Word::default();
    /// Hasher::merge_in_domain(&[callee_digest, Word::default()], CallNode::CALL_DOMAIN);
    /// ```
    /// or
    /// ```
    /// # use miden_core::mast::CallNode;
    /// # use miden_crypto::{Word, hash::rpo::Rpo256 as Hasher};
    /// # let callee_digest = Word::default();
    /// Hasher::merge_in_domain(&[callee_digest, Word::default()], CallNode::SYSCALL_DOMAIN);
    /// ```
    fn digest(&self) -> Word {
        self.digest
    }

    /// Returns the decorators to be executed before this node is executed.
    fn before_enter(&self) -> &[DecoratorId] {
        &self.before_enter
    }

    /// Returns the decorators to be executed after this node is executed.
    fn after_exit(&self) -> &[DecoratorId] {
        &self.after_exit
    }

    /// Sets the list of decorators to be executed before this node.
    fn append_before_enter(&mut self, decorator_ids: &[DecoratorId]) {
        self.before_enter.extend_from_slice(decorator_ids);
    }

    /// Sets the list of decorators to be executed after this node.
    fn append_after_exit(&mut self, decorator_ids: &[DecoratorId]) {
        self.after_exit.extend_from_slice(decorator_ids);
    }

    /// Removes all decorators from this node.
    fn remove_decorators(&mut self) {
        self.before_enter.truncate(0);
        self.after_exit.truncate(0);
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

    fn to_builder(self) -> Self::Builder {
        let builder = if self.is_syscall {
            CallNodeBuilder::new_syscall(self.callee)
        } else {
            CallNodeBuilder::new(self.callee)
        };
        builder.with_before_enter(self.before_enter).with_after_exit(self.after_exit)
    }
}

// ARBITRARY IMPLEMENTATION
// ================================================================================================

#[cfg(all(feature = "arbitrary", test))]
impl proptest::prelude::Arbitrary for CallNode {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        use crate::Felt;

        // Generate callee, digest, and whether it's a syscall
        (any::<MastNodeId>(), any::<[u64; 4]>(), any::<bool>())
            .prop_map(|(callee, digest_array, is_syscall)| {
                // Use new_unsafe since we're generating arbitrary nodes
                // The digest is also arbitrary since we can't compute it without a MastForest
                let digest = Word::from(digest_array.map(Felt::new));
                let mut node = CallNode::new_unsafe(callee, digest);
                node.is_syscall = is_syscall;
                node
            })
            .no_shrink()  // Pure random values, no meaningful shrinking pattern
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`CallNode`] instances with decorators.
#[derive(Debug)]
pub struct CallNodeBuilder {
    callee: MastNodeId,
    is_syscall: bool,
    before_enter: Vec<DecoratorId>,
    after_exit: Vec<DecoratorId>,
}

impl CallNodeBuilder {
    /// Creates a new builder for a CallNode with the specified callee.
    pub fn new(callee: MastNodeId) -> Self {
        Self {
            callee,
            is_syscall: false,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }

    /// Creates a new builder for a syscall CallNode with the specified callee.
    pub fn new_syscall(callee: MastNodeId) -> Self {
        Self {
            callee,
            is_syscall: true,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }

    /// Builds the CallNode with the specified decorators.
    pub fn build(self, mast_forest: &MastForest) -> Result<CallNode, MastForestError> {
        if self.callee.to_usize() >= mast_forest.nodes.len() {
            return Err(MastForestError::NodeIdOverflow(self.callee, mast_forest.nodes.len()));
        }
        let digest = {
            let callee_digest = mast_forest[self.callee].digest();
            let domain = if self.is_syscall {
                CallNode::SYSCALL_DOMAIN
            } else {
                CallNode::CALL_DOMAIN
            };

            hasher::merge_in_domain(&[callee_digest, Word::default()], domain)
        };

        Ok(CallNode {
            callee: self.callee,
            is_syscall: self.is_syscall,
            digest,
            before_enter: self.before_enter,
            after_exit: self.after_exit,
        })
    }
}

impl MastForestContributor for CallNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        forest
            .nodes
            .push(self.build(forest)?.into())
            .map_err(|_| MastForestError::TooManyNodes)
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
            &[self.callee],
            // Compute digest the same way as in build()
            {
                let callee_digest = forest[self.callee].digest();
                let domain = if self.is_syscall {
                    CallNode::SYSCALL_DOMAIN
                } else {
                    CallNode::CALL_DOMAIN
                };

                crate::chiplets::hasher::merge_in_domain(
                    &[callee_digest, miden_crypto::Word::default()],
                    domain,
                )
            },
        )
    }

    fn remap_children(self, remapping: &crate::mast::Remapping) -> Self {
        CallNodeBuilder {
            callee: self.callee.remap(remapping),
            is_syscall: self.is_syscall,
            before_enter: self.before_enter,
            after_exit: self.after_exit,
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
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for CallNodeBuilder {
    type Parameters = CallNodeBuilderParams;
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (
            any::<crate::mast::MastNodeId>(),
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
