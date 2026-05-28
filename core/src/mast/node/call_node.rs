use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use miden_formatting::{
    hex::ToHex,
    prettier::{Document, PrettyPrint, const_text, text},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastForestContributor, MastNodeExt};
use crate::{
    Felt, Word,
    chiplets::hasher,
    mast::{MastForest, MastForestError, MastNodeId},
    operations::opcodes,
    utils::{Idx, LookupByIdx},
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

impl PrettyPrint for CallNodePrettyPrint<'_> {
    fn render(&self) -> Document {
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

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        if self.is_syscall {
            CallNodeBuilder::new_syscall(self.callee)
        } else {
            CallNodeBuilder::new(self.callee)
        }
    }

    #[cfg(debug_assertions)]
    fn verify_node_in_forest<F>(&self, _forest: &F)
    where
        F: crate::mast::ExecutableMastForest + ?Sized,
    {
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
                // Generate a random digest
                let digest = Word::from(digest_array.map(Felt::new_unchecked));
                // Construct directly to avoid MastForest validation for arbitrary data
                CallNode {
                    callee,
                    is_syscall,
                    digest,
                }
            })
            .no_shrink()  // Pure random values, no meaningful shrinking pattern
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// ------------------------------------------------------------------------------------------------
/// Builder for creating [`CallNode`] instances.
#[derive(Debug)]
pub struct CallNodeBuilder {
    callee: MastNodeId,
    is_syscall: bool,
    digest: Option<Word>,
}

impl CallNodeBuilder {
    /// Creates a new builder for a CallNode with the specified callee.
    pub fn new(callee: MastNodeId) -> Self {
        Self { callee, is_syscall: false, digest: None }
    }

    /// Creates a new builder for a syscall CallNode with the specified callee.
    pub fn new_syscall(callee: MastNodeId) -> Self {
        Self { callee, is_syscall: true, digest: None }
    }

    /// Builds the CallNode.
    pub fn build(self, mast_forest: &MastForest) -> Result<CallNode, MastForestError> {
        if self.callee.to_usize() >= mast_forest.nodes.len() {
            return Err(MastForestError::NodeIdOverflow(self.callee, mast_forest.nodes.len()));
        }

        // Use the forced digest if provided, otherwise compute the digest
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
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
        })
    }
}

impl MastForestContributor for CallNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        if self.callee.to_usize() >= forest.nodes.len() {
            return Err(MastForestError::NodeIdOverflow(self.callee, forest.nodes.len()));
        }

        // Use the forced digest if provided, otherwise compute the digest directly
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
            let callee_digest = forest[self.callee].digest();
            let domain = if self.is_syscall {
                CallNode::SYSCALL_DOMAIN
            } else {
                CallNode::CALL_DOMAIN
            };

            hasher::merge_in_domain(&[callee_digest, Word::default()], domain)
        };

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate Owned node creation
        let node_id = forest
            .nodes
            .push(
                CallNode {
                    callee: self.callee,
                    is_syscall: self.is_syscall,
                    digest,
                }
                .into(),
            )
            .map_err(|_| MastForestError::TooManyNodes)?;

        Ok(node_id)
    }

    fn fingerprint_for_node(
        &self,
        forest: &MastForest,
        _hash_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
    ) -> Result<Word, MastForestError> {
        Ok(if let Some(forced_digest) = self.digest {
            forced_digest
        } else {
            let callee_digest = forest[self.callee].digest();
            let domain = if self.is_syscall {
                CallNode::SYSCALL_DOMAIN
            } else {
                CallNode::CALL_DOMAIN
            };

            hasher::merge_in_domain(&[callee_digest, Word::default()], domain)
        })
    }

    fn remap_children(self, remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        CallNodeBuilder {
            callee: *remapping.get(self.callee).unwrap_or(&self.callee),
            is_syscall: self.is_syscall,
            digest: self.digest,
        }
    }

    fn with_digest(mut self, digest: Word) -> Self {
        self.digest = Some(digest);
        self
    }
}

impl CallNodeBuilder {
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

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(
                CallNode {
                    callee: self.callee,
                    is_syscall: self.is_syscall,
                    digest,
                }
                .into(),
            )
            .map_err(|_| MastForestError::TooManyNodes)?;

        Ok(node_id)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for CallNodeBuilder {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (any::<MastNodeId>(), any::<bool>())
            .prop_map(|(callee, is_syscall)| {
                if is_syscall {
                    Self::new_syscall(callee)
                } else {
                    Self::new(callee)
                }
            })
            .boxed()
    }
}
