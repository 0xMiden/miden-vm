use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_crypto::{Felt, Word};
use miden_formatting::{
    hex::ToHex,
    prettier::{Document, PrettyPrint, const_text, nl, text},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastNodeErrorContext, MastNodeExt};
use crate::{
    Idx, OPCODE_CALL, OPCODE_SYSCALL,
    chiplets::hasher,
    mast::{DecoratedOpLink, DecoratorId, MastForest, MastForestError, MastNodeId, Remapping},
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

    fn remap_children(&self, remapping: &Remapping) -> Self {
        let mut node = self.clone();
        node.callee = node.callee.remap(remapping);
        node
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

    /// Adds decorators to be executed before this node.
    pub fn with_before_enter(mut self, decorators: impl Into<Vec<DecoratorId>>) -> Self {
        self.before_enter = decorators.into();
        self
    }

    /// Adds decorators to be executed after this node.
    pub fn with_after_exit(mut self, decorators: impl Into<Vec<DecoratorId>>) -> Self {
        self.after_exit = decorators.into();
        self
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
