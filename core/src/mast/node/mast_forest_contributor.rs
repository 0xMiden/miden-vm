use miden_utils_core_derive::MastForestContributor;

use super::{
    BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
    LoopNodeBuilder, SplitNodeBuilder,
};
use crate::{
    Word,
    mast::{MastForest, MastForestError, MastNode, MastNodeId},
    utils::LookupByIdx,
};

pub trait MastForestContributor {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError>;

    /// Returns the fingerprint for this builder without constructing a MastNode.
    ///
    /// This method computes the fingerprint for a node directly from the builder data
    /// without first constructing a MastNode, providing the same result as the
    /// traditional fingerprint computation approach.
    fn fingerprint_for_node(&self, forest: &MastForest) -> Result<Word, MastForestError>;

    /// Remap the node children to their new positions indicated by the given
    /// lookup.
    fn remap_children(self, remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self;

    /// Sets a digest to be forced into the built node.
    ///
    /// When a digest is set, the builder will use this digest instead of computing
    /// the normal digest for the node during the build() operation.
    fn with_digest(self, digest: Word) -> Self;
}

/// Enum of all MAST node builders that can be added to a forest.
/// This allows for generic handling of different builder types through enum dispatch.
#[derive(Debug, MastForestContributor)]
pub enum MastNodeBuilder {
    BasicBlock(BasicBlockNodeBuilder),
    Call(CallNodeBuilder),
    Dyn(DynNodeBuilder),
    External(ExternalNodeBuilder),
    Join(JoinNodeBuilder),
    Loop(LoopNodeBuilder),
    Split(SplitNodeBuilder),
}

impl MastNodeBuilder {
    /// Build the node from this builder.
    ///
    /// For nodes that depend on a MastForest (Call, Join, Loop, Split), the forest is required.
    /// For nodes that don't depend on a MastForest (BasicBlock, Dyn, External), the forest is
    /// ignored.
    pub fn build(self, mast_forest: &MastForest) -> Result<MastNode, MastForestError> {
        match self {
            MastNodeBuilder::BasicBlock(builder) => Ok(builder.build()?.into()),
            MastNodeBuilder::Call(builder) => Ok(builder.build(mast_forest)?.into()),
            MastNodeBuilder::Dyn(builder) => Ok(builder.build().into()),
            MastNodeBuilder::External(builder) => Ok(builder.build().into()),
            MastNodeBuilder::Join(builder) => Ok(builder.build(mast_forest)?.into()),
            MastNodeBuilder::Loop(builder) => Ok(builder.build(mast_forest)?.into()),
            MastNodeBuilder::Split(builder) => Ok(builder.build(mast_forest)?.into()),
        }
    }

    /// Adds the node from this builder to the forest without validation, used during
    /// deserialization.
    ///
    /// This method bypasses normal validation. It should only be used during deserialization where
    /// the forest structure is being reconstructed.
    pub(in crate::mast) fn add_to_forest_relaxed(
        self,
        mast_forest: &mut MastForest,
    ) -> Result<MastNodeId, MastForestError> {
        match self {
            MastNodeBuilder::BasicBlock(builder) => builder.add_to_forest_relaxed(mast_forest),
            MastNodeBuilder::Call(builder) => builder.add_to_forest_relaxed(mast_forest),
            MastNodeBuilder::Dyn(builder) => builder.add_to_forest_relaxed(mast_forest),
            MastNodeBuilder::External(builder) => builder.add_to_forest_relaxed(mast_forest),
            MastNodeBuilder::Join(builder) => builder.add_to_forest_relaxed(mast_forest),
            MastNodeBuilder::Loop(builder) => builder.add_to_forest_relaxed(mast_forest),
            MastNodeBuilder::Split(builder) => builder.add_to_forest_relaxed(mast_forest),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for MastNodeBuilder {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        prop_oneof![
            any::<BasicBlockNodeBuilder>().prop_map(MastNodeBuilder::BasicBlock),
            any::<CallNodeBuilder>().prop_map(MastNodeBuilder::Call),
            any::<DynNodeBuilder>().prop_map(MastNodeBuilder::Dyn),
            any::<ExternalNodeBuilder>().prop_map(MastNodeBuilder::External),
            any::<JoinNodeBuilder>().prop_map(MastNodeBuilder::Join),
            any::<LoopNodeBuilder>().prop_map(MastNodeBuilder::Loop),
            any::<SplitNodeBuilder>().prop_map(MastNodeBuilder::Split),
        ]
        .boxed()
    }
}

#[cfg(test)]
mod fingerprint_invariant_tests {
    use crate::{
        Felt,
        mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor},
        operations::Operation,
    };

    #[test]
    fn basic_block_fingerprint_ignores_assert_error_codes() {
        let forest = MastForest::new();
        let builder_assert_1 =
            BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::new_unchecked(1))]);
        let builder_assert_2 =
            BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::new_unchecked(2))]);

        let fp_assert_1 = builder_assert_1.fingerprint_for_node(&forest).unwrap();
        let fp_assert_2 = builder_assert_2.fingerprint_for_node(&forest).unwrap();

        assert_eq!(
            fp_assert_1, fp_assert_2,
            "assert error codes are debug metadata and should not affect MAST node identity"
        );
    }
}

#[cfg(test)]
mod round_trip_tests {
    use miden_crypto::Felt;

    use crate::{
        Word,
        mast::{
            BasicBlockNodeBuilder, MastForest, MastNodeBuilder, MastNodeExt,
            node::mast_forest_contributor::MastForestContributor,
        },
        operations::Operation,
    };

    #[test]
    fn test_mast_node_builder_enum_digest_forcing() {
        let mut forest = MastForest::new();

        let mast_builder1 =
            MastNodeBuilder::BasicBlock(BasicBlockNodeBuilder::new(vec![Operation::Push(
                Felt::new_unchecked(10),
            )]));
        let mast_node_id1 = mast_builder1
            .add_to_forest(&mut forest)
            .expect("Failed to add mast node1 to forest");
        let mast_node1 = forest.get_node_by_id(mast_node_id1).unwrap().unwrap_basic_block();
        let mast_normal_digest = mast_node1.digest();

        let forced_mast_digest = Word::new([
            Felt::new_unchecked(9),
            Felt::new_unchecked(10),
            Felt::new_unchecked(11),
            Felt::new_unchecked(12),
        ]);
        let mast_builder2 = MastNodeBuilder::BasicBlock(
            BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::new_unchecked(10))])
                .with_digest(forced_mast_digest),
        );
        let mast_node_id2 = mast_builder2
            .add_to_forest(&mut forest)
            .expect("Failed to add mast node with forced digest to forest");
        let mast_node2 = forest.get_node_by_id(mast_node_id2).unwrap().unwrap_basic_block();

        assert_ne!(
            mast_normal_digest, forced_mast_digest,
            "Normal and forced digests should be different"
        );
        assert_eq!(
            mast_node2.digest(),
            forced_mast_digest,
            "Forced digest should be used for mast node builder enum"
        );
    }
}
