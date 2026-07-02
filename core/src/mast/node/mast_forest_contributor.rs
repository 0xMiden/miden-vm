use alloc::vec::Vec;

use miden_utils_core_derive::MastForestContributor;

use super::{
    BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
    LoopNodeBuilder, MastNodeExt, SplitNodeBuilder,
};
use crate::{
    Felt, Word,
    chiplets::hasher,
    mast::{MastForest, MastForestError, MastNode, MastNodeId},
    utils::LookupByIdx,
};

const CHILD_FINGERPRINT_DOMAIN: Felt = Felt::new_unchecked(0x2473_0002);

pub(crate) fn fingerprint_with_child_fingerprints(
    node_digest: Word,
    child_ids: &[MastNodeId],
    context: &impl MastNodeContext,
    fingerprint_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
) -> Result<Word, MastForestError> {
    let mut has_non_digest_child = false;
    let mut elements = Vec::with_capacity(1 + 4 + child_ids.len() * 4);
    elements.push(CHILD_FINGERPRINT_DOMAIN);
    elements.extend_from_slice(node_digest.as_elements());

    for &child_id in child_ids {
        let child = context
            .get_node_by_id(child_id)
            .ok_or_else(|| MastForestError::NodeIdOverflow(child_id, context.node_count()))?;
        let child_digest = child.digest();
        let child_fingerprint = *fingerprint_by_node_id
            .get(child_id)
            .ok_or_else(|| MastForestError::NodeIdOverflow(child_id, context.node_count()))?;
        has_non_digest_child |= child_fingerprint != child_digest;
        elements.extend_from_slice(child_fingerprint.as_elements());
    }

    if has_non_digest_child {
        Ok(hasher::hash_elements(&elements))
    } else {
        Ok(node_digest)
    }
}

pub trait MastNodeContext {
    fn node_count(&self) -> usize;

    fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode>;
}

impl MastNodeContext for MastForest {
    fn node_count(&self) -> usize {
        self.nodes().len()
    }

    fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode> {
        self.get_node_by_id(node_id)
    }
}

pub trait MastForestContributor {
    #[cfg(any(test, feature = "arbitrary"))]
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError>;

    /// Returns the fingerprint for this builder without constructing a MastNode.
    ///
    /// This method computes the fingerprint for a node directly from the builder data
    /// without first constructing a MastNode, providing the same result as the
    /// traditional fingerprint computation approach.
    fn fingerprint_for_node(
        &self,
        context: &impl MastNodeContext,
        hash_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
    ) -> Result<Word, MastForestError>;

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

impl From<BasicBlockNodeBuilder> for MastNodeBuilder {
    fn from(builder: BasicBlockNodeBuilder) -> Self {
        Self::BasicBlock(builder)
    }
}

impl From<CallNodeBuilder> for MastNodeBuilder {
    fn from(builder: CallNodeBuilder) -> Self {
        Self::Call(builder)
    }
}

impl From<DynNodeBuilder> for MastNodeBuilder {
    fn from(builder: DynNodeBuilder) -> Self {
        Self::Dyn(builder)
    }
}

impl From<ExternalNodeBuilder> for MastNodeBuilder {
    fn from(builder: ExternalNodeBuilder) -> Self {
        Self::External(builder)
    }
}

impl From<JoinNodeBuilder> for MastNodeBuilder {
    fn from(builder: JoinNodeBuilder) -> Self {
        Self::Join(builder)
    }
}

impl From<LoopNodeBuilder> for MastNodeBuilder {
    fn from(builder: LoopNodeBuilder) -> Self {
        Self::Loop(builder)
    }
}

impl From<SplitNodeBuilder> for MastNodeBuilder {
    fn from(builder: SplitNodeBuilder) -> Self {
        Self::Split(builder)
    }
}

impl MastNodeBuilder {
    /// Build the node from this builder.
    ///
    /// For nodes that depend on a MastForest (Call, Join, Loop, Split), the forest is required.
    /// For nodes that don't depend on a MastForest (BasicBlock, Dyn, External), the forest is
    /// ignored.
    pub fn build(self, context: &impl MastNodeContext) -> Result<MastNode, MastForestError> {
        match self {
            MastNodeBuilder::BasicBlock(builder) => Ok(builder.build()?.into()),
            MastNodeBuilder::Call(builder) => Ok(builder.build(context)?.into()),
            MastNodeBuilder::Dyn(builder) => Ok(builder.build().into()),
            MastNodeBuilder::External(builder) => Ok(builder.build().into()),
            MastNodeBuilder::Join(builder) => Ok(builder.build(context)?.into()),
            MastNodeBuilder::Loop(builder) => Ok(builder.build(context)?.into()),
            MastNodeBuilder::Split(builder) => Ok(builder.build(context)?.into()),
        }
    }

    /// Build a node whose child IDs have already been remapped into final forest positions.
    ///
    /// This path is used by finalizers that materialize nodes in topological order before a
    /// complete [`MastForest`] exists. Control-node builders must carry their already-computed
    /// digest on this path.
    pub fn build_linked(self) -> Result<MastNode, MastForestError> {
        match self {
            MastNodeBuilder::BasicBlock(builder) => Ok(builder.build()?.into()),
            MastNodeBuilder::Call(builder) => Ok(builder.build_linked()?.into()),
            MastNodeBuilder::Dyn(builder) => Ok(builder.build().into()),
            MastNodeBuilder::External(builder) => Ok(builder.build().into()),
            MastNodeBuilder::Join(builder) => Ok(builder.build_linked()?.into()),
            MastNodeBuilder::Loop(builder) => Ok(builder.build_linked()?.into()),
            MastNodeBuilder::Split(builder) => Ok(builder.build_linked()?.into()),
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
    fn basic_block_fingerprint_preserves_error_code_bearing_operations() {
        let forest = MastForest::new();
        let empty_map = alloc::collections::BTreeMap::new();

        for make_op in [
            Operation::Assert as fn(Felt) -> Operation,
            Operation::U32assert2 as fn(Felt) -> Operation,
            Operation::MpVerify as fn(Felt) -> Operation,
        ] {
            let builder_1 = BasicBlockNodeBuilder::new(vec![make_op(Felt::new_unchecked(1))]);
            let builder_1_dup = BasicBlockNodeBuilder::new(vec![make_op(Felt::new_unchecked(1))]);
            let builder_2 = BasicBlockNodeBuilder::new(vec![make_op(Felt::new_unchecked(2))]);

            let fp_1 = builder_1.fingerprint_for_node(&forest, &empty_map).unwrap();
            let fp_1_dup = builder_1_dup.fingerprint_for_node(&forest, &empty_map).unwrap();
            let fp_2 = builder_2.fingerprint_for_node(&forest, &empty_map).unwrap();

            assert_eq!(fp_1, fp_1_dup);
            assert_ne!(
                fp_1, fp_2,
                "runtime error codes must affect dedup fingerprints without changing MAST digest"
            );
        }
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
