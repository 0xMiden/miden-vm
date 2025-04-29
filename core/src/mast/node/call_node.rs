use alloc::vec::Vec;
use core::fmt;

use miden_crypto::{Felt, PrimeCharacteristicRing, hash::rpo::RpoDigest};
use miden_formatting::{
    hex::ToHex,
    prettier::{Document, PrettyPrint, const_text, nl, text},
};

use crate::{
    OPCODE_CALL, OPCODE_SYSCALL,
    chiplets::hasher,
    mast::{DecoratorId, MastForest, MastForestError, MastNodeId, Remapping},
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
pub struct CallNode {
    callee: MastNodeId,
    is_syscall: bool,
    digest: RpoDigest,
    before_enter: Vec<DecoratorId>,
    after_exit: Vec<DecoratorId>,
}

//-------------------------------------------------------------------------------------------------
/// Constants
impl CallNode {
    /// The domain of the call block (used for control block hashing).
    pub fn call_domain() -> Felt {
        Felt::from_u64(OPCODE_CALL as u64)
    }

    /// The domain of the syscall block (used for control block hashing).
    pub fn syscall_domain() -> Felt {
        Felt::from_u64(OPCODE_SYSCALL as u64)
    }
}

//-------------------------------------------------------------------------------------------------
/// Constructors
impl CallNode {
    /// Returns a new [`CallNode`] instantiated with the specified callee.
    pub fn new(callee: MastNodeId, mast_forest: &MastForest) -> Result<Self, MastForestError> {
        if callee.as_usize() >= mast_forest.nodes.len() {
            return Err(MastForestError::NodeIdOverflow(callee, mast_forest.nodes.len()));
        }
        let digest = {
            let callee_digest = mast_forest[callee].digest();

            hasher::merge_in_domain(&[callee_digest, RpoDigest::default()], Self::call_domain())
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
    pub fn new_unsafe(callee: MastNodeId, digest: RpoDigest) -> Self {
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
    pub fn new_syscall(
        callee: MastNodeId,
        mast_forest: &MastForest,
    ) -> Result<Self, MastForestError> {
        if callee.as_usize() >= mast_forest.nodes.len() {
            return Err(MastForestError::NodeIdOverflow(callee, mast_forest.nodes.len()));
        }
        let digest = {
            let callee_digest = mast_forest[callee].digest();

            hasher::merge_in_domain(&[callee_digest, RpoDigest::default()], Self::syscall_domain())
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
    pub fn new_syscall_unsafe(callee: MastNodeId, digest: RpoDigest) -> Self {
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
    /// Returns a commitment to this Call node.
    ///
    /// The commitment is computed as a hash of the callee and an empty word ([ZERO; 4]) in the
    /// domain defined by either [Self::call_domain()] or [Self::syscall_domain()], depending on
    /// whether the node represents a simple call or a syscall - i.e.,:
    /// ```
    /// # use miden_core::mast::CallNode;
    /// # use miden_crypto::{hash::rpo::{RpoDigest as Digest, Rpo256 as Hasher}};
    /// # let callee_digest = Digest::default();
    /// Hasher::merge_in_domain(&[callee_digest, Digest::default()], CallNode::call_domain());
    /// ```
    /// or
    /// ```
    /// # use miden_core::mast::CallNode;
    /// # use miden_crypto::{hash::rpo::{RpoDigest as Digest, Rpo256 as Hasher}};
    /// # let callee_digest = Digest::default();
    /// Hasher::merge_in_domain(&[callee_digest, Digest::default()], CallNode::syscall_domain());
    /// ```
    pub fn digest(&self) -> RpoDigest {
        self.digest
    }

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
            Self::syscall_domain()
        } else {
            Self::call_domain()
        }
    }

    /// Returns the decorators to be executed before this node is executed.
    pub fn before_enter(&self) -> &[DecoratorId] {
        &self.before_enter
    }

    /// Returns the decorators to be executed after this node is executed.
    pub fn after_exit(&self) -> &[DecoratorId] {
        &self.after_exit
    }
}

/// Mutators
impl CallNode {
    pub fn remap_children(&self, remapping: &Remapping) -> Self {
        let mut node = self.clone();
        node.callee = node.callee.remap(remapping);
        node
    }

    /// Sets the list of decorators to be executed before this node.
    pub fn set_before_enter(&mut self, decorator_ids: Vec<DecoratorId>) {
        self.before_enter = decorator_ids;
    }

    /// Sets the list of decorators to be executed after this node.
    pub fn set_after_exit(&mut self, decorator_ids: Vec<DecoratorId>) {
        self.after_exit = decorator_ids;
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
