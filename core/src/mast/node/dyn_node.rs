use alloc::{boxed::Box, vec::Vec};
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{MastForestContributor, MastNodeExt};
use crate::{
    Felt, Word,
    mast::{MastForest, MastForestError, MastNodeId},
    operations::opcodes,
    prettier::{Document, PrettyPrint, const_text},
    utils::LookupByIdx,
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
}

/// Constants
impl DynNode {
    /// The domain of the Dyn block (used for control block hashing).
    pub const DYN_DOMAIN: Felt = Felt::new_unchecked(opcodes::DYN as u64);

    /// The domain of the Dyncall block (used for control block hashing).
    pub const DYNCALL_DOMAIN: Felt = Felt::new_unchecked(opcodes::DYNCALL as u64);
}

/// Default digest constants
impl DynNode {
    /// The default digest for a DynNode representing a dyncall operation.
    pub const DYNCALL_DEFAULT_DIGEST: Word = Word::new([
        Felt::new_unchecked(16830415514927835337),
        Felt::new_unchecked(12164645914672292987),
        Felt::new_unchecked(13192574193032437705),
        Felt::new_unchecked(4604554596675732269),
    ]);

    /// The default digest for a DynNode representing a dynexec operation.
    pub const DYN_DEFAULT_DIGEST: Word = Word::new([
        Felt::new_unchecked(16952228088962355159),
        Felt::new_unchecked(5793482471479538911),
        Felt::new_unchecked(14446299416172848527),
        Felt::new_unchecked(13522295374716441620),
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
    pub(super) fn to_display<'a>(&'a self, _mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        self.clone()
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        _mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        self.clone()
    }
}

impl PrettyPrint for DynNode {
    fn render(&self) -> Document {
        if self.is_dyncall() {
            const_text("dyncall")
        } else {
            const_text("dyn")
        }
    }
}

impl fmt::Display for DynNode {
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

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        let builder = if self.is_dyncall {
            DynNodeBuilder::new_dyncall()
        } else {
            DynNodeBuilder::new_dyn()
        };
        builder.with_digest(self.digest)
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
/// Builder for creating [`DynNode`] instances.
#[derive(Debug)]
pub struct DynNodeBuilder {
    is_dyncall: bool,
    digest: Option<Word>,
}

impl DynNodeBuilder {
    /// Creates a new builder for a DynNode representing a dynexec operation.
    pub fn new_dyn() -> Self {
        Self { is_dyncall: false, digest: None }
    }

    /// Creates a new builder for a DynNode representing a dyncall operation.
    pub fn new_dyncall() -> Self {
        Self { is_dyncall: true, digest: None }
    }

    /// Builds the DynNode.
    pub fn build(self) -> DynNode {
        // Use the forced digest if provided, otherwise use the default digest
        let digest = if let Some(forced_digest) = self.digest {
            forced_digest
        } else if self.is_dyncall {
            DynNode::DYNCALL_DEFAULT_DIGEST
        } else {
            DynNode::DYN_DEFAULT_DIGEST
        };

        DynNode { is_dyncall: self.is_dyncall, digest }
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

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(DynNode { is_dyncall: self.is_dyncall, digest }.into())
            .map_err(|_| MastForestError::TooManyNodes)?;

        Ok(node_id)
    }

    fn fingerprint_for_node(
        &self,
        _forest: &MastForest,
        _hash_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
    ) -> Result<Word, MastForestError> {
        Ok(if let Some(forced_digest) = self.digest {
            forced_digest
        } else if self.is_dyncall {
            DynNode::DYNCALL_DEFAULT_DIGEST
        } else {
            DynNode::DYN_DEFAULT_DIGEST
        })
    }

    fn remap_children(self, _remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        // DynNode has no children to remap, but preserve the digest
        self
    }

    fn with_digest(mut self, digest: Word) -> Self {
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

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(DynNode { is_dyncall: self.is_dyncall, digest }.into())
            .map_err(|_| MastForestError::TooManyNodes)?;

        Ok(node_id)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for DynNodeBuilder {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        any::<bool>()
            .prop_map(|is_dyncall| {
                if is_dyncall {
                    Self::new_dyncall()
                } else {
                    Self::new_dyn()
                }
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use miden_crypto::hash::poseidon2::Poseidon2;

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
            Poseidon2::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYN_DOMAIN)
        );

        let dyncall_node_id = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();
        let dyncall_node = forest.get_node_by_id(dyncall_node_id).unwrap().unwrap_dyn();
        assert_eq!(
            dyncall_node.digest(),
            Poseidon2::merge_in_domain(
                &[Word::default(), Word::default()],
                DynNode::DYNCALL_DOMAIN
            )
        );
    }
}
