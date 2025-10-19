use alloc::vec::Vec;

use miden_utils_core_derive::MastForestContributor;

use super::{
    BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
    LoopNodeBuilder, SplitNodeBuilder,
};
use crate::{
    LookupByIdx,
    mast::{MastForest, MastForestError, MastNodeId},
};

pub trait MastForestContributor {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError>;

    /// Returns the fingerprint for this builder without constructing a MastNode.
    ///
    /// This method computes the fingerprint for a node directly from the builder data
    /// without first constructing a MastNode, providing the same result as the
    /// traditional fingerprint computation approach.
    fn fingerprint_for_node(
        &self,
        forest: &MastForest,
        hash_by_node_id: &impl crate::LookupByIdx<MastNodeId, crate::mast::MastNodeFingerprint>,
    ) -> Result<crate::mast::MastNodeFingerprint, MastForestError>;

    /// Remap the node children to their new positions indicated by the given
    /// lookup.
    fn remap_children(self, remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self;

    /// Adds decorators to be executed before this node.
    fn with_before_enter(self, _decorators: impl Into<Vec<crate::mast::DecoratorId>>) -> Self;

    /// Adds decorators to be executed after this node.
    fn with_after_exit(self, _decorators: impl Into<Vec<crate::mast::DecoratorId>>) -> Self;

    /// Appends decorators to be executed before this node.
    ///
    /// Unlike `with_before_enter`, this method adds to the existing list of decorators
    /// rather than replacing them.
    fn append_before_enter(
        &mut self,
        decorators: impl IntoIterator<Item = crate::mast::DecoratorId>,
    );

    /// Appends decorators to be executed after this node.
    ///
    /// Unlike `with_after_exit`, this method adds to the existing list of decorators
    /// rather than replacing them.
    fn append_after_exit(&mut self, decorators: impl IntoIterator<Item = crate::mast::DecoratorId>);

    /// Sets a digest to be forced into the built node.
    ///
    /// When a digest is set, the builder will use this digest instead of computing
    /// the normal digest for the node during the build() operation.
    fn with_digest(self, digest: crate::Word) -> Self;
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
    pub fn build(self, mast_forest: &MastForest) -> Result<crate::mast::MastNode, MastForestError> {
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
        match self {
            MastNodeBuilder::BasicBlock(builder) => builder.add_to_forest_relaxed(forest),
            MastNodeBuilder::Call(builder) => builder.add_to_forest_relaxed(forest),
            MastNodeBuilder::Dyn(builder) => builder.add_to_forest_relaxed(forest),
            MastNodeBuilder::External(builder) => builder.add_to_forest_relaxed(forest),
            MastNodeBuilder::Join(builder) => builder.add_to_forest_relaxed(forest),
            MastNodeBuilder::Loop(builder) => builder.add_to_forest_relaxed(forest),
            MastNodeBuilder::Split(builder) => builder.add_to_forest_relaxed(forest),
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
    use alloc::{collections::BTreeMap, vec::Vec};

    use proptest::prelude::*;

    use crate::{
        Decorator, Felt, Operation,
        mast::{
            BasicBlockNodeBuilder, DecoratorId, MastForest, MastForestContributor,
            arbitrary::op_non_control_strategy,
        },
    };

    /// Creates a decorator and returns its ID
    fn add_trace_decorator(forest: &mut MastForest, value: u8) -> DecoratorId {
        forest.add_decorator(Decorator::Trace(value.into())).unwrap()
    }

    #[test]
    fn basic_block_fingerprint_different_before_decorators() {
        let mut forest = MastForest::new();
        let deco1 = add_trace_decorator(&mut forest, 1);
        let deco2 = add_trace_decorator(&mut forest, 2);

        // Create two identical basic blocks with different before_enter decorators using builder
        // pattern
        let builder1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
            .with_before_enter(vec![deco1]);
        let builder2 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
            .with_before_enter(vec![deco2]);

        // Compute fingerprints using fingerprint_for_node
        let empty_map = BTreeMap::new();
        let fp1 = builder1.fingerprint_for_node(&forest, &empty_map).unwrap();
        let fp2 = builder2.fingerprint_for_node(&forest, &empty_map).unwrap();

        // Fingerprints should be different
        assert_ne!(
            fp1, fp2,
            "Basic blocks with different before_enter decorators should have different fingerprints"
        );
    }

    #[test]
    fn basic_block_fingerprint_different_after_decorators() {
        let mut forest = MastForest::new();
        let deco1 = add_trace_decorator(&mut forest, 1);
        let deco2 = add_trace_decorator(&mut forest, 2);

        // Create two identical basic blocks with different after_exit decorators using builder
        // pattern
        let builder1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
            .with_after_exit(vec![deco1]);
        let builder2 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
            .with_after_exit(vec![deco2]);

        // Compute fingerprints using fingerprint_for_node
        let empty_map = BTreeMap::new();
        let fp1 = builder1.fingerprint_for_node(&forest, &empty_map).unwrap();
        let fp2 = builder2.fingerprint_for_node(&forest, &empty_map).unwrap();

        // Fingerprints should be different
        assert_ne!(
            fp1, fp2,
            "Basic blocks with different after_exit decorators should have different fingerprints"
        );
    }

    #[test]
    fn basic_block_fingerprint_different_assert_opcodes_no_decorators() {
        let forest = MastForest::new();
        let error_code = Felt::new(42);

        // Create three basic blocks with different assert opcodes but no decorators using builders
        let builder_assert =
            BasicBlockNodeBuilder::new(vec![Operation::Assert(error_code)], Vec::new());
        let builder_u32assert2 =
            BasicBlockNodeBuilder::new(vec![Operation::U32assert2(error_code)], Vec::new());
        let builder_mpverify =
            BasicBlockNodeBuilder::new(vec![Operation::MpVerify(error_code)], Vec::new());

        // Compute fingerprints using fingerprint_for_node
        let empty_map = BTreeMap::new();
        let fp_assert = builder_assert.fingerprint_for_node(&forest, &empty_map).unwrap();
        let fp_u32assert2 = builder_u32assert2.fingerprint_for_node(&forest, &empty_map).unwrap();
        let fp_mpverify = builder_mpverify.fingerprint_for_node(&forest, &empty_map).unwrap();

        // All fingerprints should be different since the opcodes are different
        assert_ne!(
            fp_assert, fp_u32assert2,
            "Basic blocks with Assert vs U32assert2 should have different fingerprints"
        );
        assert_ne!(
            fp_assert, fp_mpverify,
            "Basic blocks with Assert vs MpVerify should have different fingerprints"
        );
        assert_ne!(
            fp_u32assert2, fp_mpverify,
            "Basic blocks with U32assert2 vs MpVerify should have different fingerprints"
        );
    }

    #[test]
    fn basic_block_fingerprint_different_assert_values_no_decorators() {
        let forest = MastForest::new();
        let error_code_1 = Felt::new(42);
        let error_code_2 = Felt::new(123);

        // Create basic blocks with same assert opcode but different inner values, no decorators
        let builder_assert_1 =
            BasicBlockNodeBuilder::new(vec![Operation::Assert(error_code_1)], Vec::new());
        let builder_assert_2 =
            BasicBlockNodeBuilder::new(vec![Operation::Assert(error_code_2)], Vec::new());

        let builder_u32assert2_1 =
            BasicBlockNodeBuilder::new(vec![Operation::U32assert2(error_code_1)], Vec::new());
        let builder_u32assert2_2 =
            BasicBlockNodeBuilder::new(vec![Operation::U32assert2(error_code_2)], Vec::new());

        let builder_mpverify_1 =
            BasicBlockNodeBuilder::new(vec![Operation::MpVerify(error_code_1)], Vec::new());
        let builder_mpverify_2 =
            BasicBlockNodeBuilder::new(vec![Operation::MpVerify(error_code_2)], Vec::new());

        // Compute fingerprints using fingerprint_for_node
        let empty_map = BTreeMap::new();
        let fp_assert_1 = builder_assert_1.fingerprint_for_node(&forest, &empty_map).unwrap();
        let fp_assert_2 = builder_assert_2.fingerprint_for_node(&forest, &empty_map).unwrap();

        let fp_u32assert2_1 =
            builder_u32assert2_1.fingerprint_for_node(&forest, &empty_map).unwrap();
        let fp_u32assert2_2 =
            builder_u32assert2_2.fingerprint_for_node(&forest, &empty_map).unwrap();

        let fp_mpverify_1 = builder_mpverify_1.fingerprint_for_node(&forest, &empty_map).unwrap();
        let fp_mpverify_2 = builder_mpverify_2.fingerprint_for_node(&forest, &empty_map).unwrap();

        // All fingerprints should be different since the inner values are different
        assert_ne!(
            fp_assert_1, fp_assert_2,
            "Basic blocks with Assert operations with different error codes should have different fingerprints"
        );
        assert_ne!(
            fp_u32assert2_1, fp_u32assert2_2,
            "Basic blocks with U32assert2 operations with different error codes should have different fingerprints"
        );
        assert_ne!(
            fp_mpverify_1, fp_mpverify_2,
            "Basic blocks with MpVerify operations with different error codes should have different fingerprints"
        );
    }

    // Property-based test using proptest to verify fingerprint invariants with random builders
    proptest! {
        #[test]
        fn prop_basic_block_fingerprint_different_before_decorators(
            ops in prop::collection::vec(op_non_control_strategy(), 1..=10),
            deco1_val in any::<u8>(),
            deco2_val in any::<u8>(),
        ) {
            prop_assume!(deco1_val != deco2_val); // Ensure different decorator values

            let mut forest = MastForest::new();
            let deco1 = add_trace_decorator(&mut forest, deco1_val);
            let deco2 = add_trace_decorator(&mut forest, deco2_val);

            let builder1 = BasicBlockNodeBuilder::new(ops.clone(), Vec::new())
                .with_before_enter(vec![deco1]);
            let builder2 = BasicBlockNodeBuilder::new(ops, Vec::new())
                .with_before_enter(vec![deco2]);

            let empty_map = BTreeMap::new();
            let fp1 = builder1.fingerprint_for_node(&forest, &empty_map).unwrap();
            let fp2 = builder2.fingerprint_for_node(&forest, &empty_map).unwrap();

            assert_ne!(fp1, fp2, "Basic blocks with different before_enter decorators should have different fingerprints");
        }

        #[test]
        fn prop_basic_block_fingerprint_different_after_decorators(
            ops in prop::collection::vec(op_non_control_strategy(), 1..=10),
            deco1_val in any::<u8>(),
            deco2_val in any::<u8>(),
        ) {
            prop_assume!(deco1_val != deco2_val); // Ensure different decorator values

            let mut forest = MastForest::new();
            let deco1 = add_trace_decorator(&mut forest, deco1_val);
            let deco2 = add_trace_decorator(&mut forest, deco2_val);

            let builder1 = BasicBlockNodeBuilder::new(ops.clone(), Vec::new())
                .with_after_exit(vec![deco1]);
            let builder2 = BasicBlockNodeBuilder::new(ops, Vec::new())
                .with_after_exit(vec![deco2]);

            let empty_map = BTreeMap::new();
            let fp1 = builder1.fingerprint_for_node(&forest, &empty_map).unwrap();
            let fp2 = builder2.fingerprint_for_node(&forest, &empty_map).unwrap();

            assert_ne!(fp1, fp2, "Basic blocks with different after_exit decorators should have different fingerprints");
        }

        #[test]
        fn prop_basic_block_fingerprint_different_assert_values(
            error_code_1 in any::<u64>(),
            error_code_2 in any::<u64>(),
        ) {
            prop_assume!(error_code_1 != error_code_2); // Ensure different error codes

            let forest = MastForest::new();
            let felt_1 = Felt::new(error_code_1);
            let felt_2 = Felt::new(error_code_2);

            let builder_assert_1 = BasicBlockNodeBuilder::new(vec![Operation::Assert(felt_1)], Vec::new());
            let builder_assert_2 = BasicBlockNodeBuilder::new(vec![Operation::Assert(felt_2)], Vec::new());

            let empty_map = BTreeMap::new();
            let fp_assert_1 = builder_assert_1.fingerprint_for_node(&forest, &empty_map).unwrap();
            let fp_assert_2 = builder_assert_2.fingerprint_for_node(&forest, &empty_map).unwrap();

            assert_ne!(fp_assert_1, fp_assert_2, "Basic blocks with Assert operations with different error codes should have different fingerprints");
        }
    }
}

#[cfg(test)]
mod round_trip_tests {
    use miden_crypto::Felt;

    use crate::{
        Operation, Word,
        mast::{
            BasicBlockNodeBuilder, JoinNodeBuilder, MastForest, MastNodeBuilder, MastNodeExt,
            node::mast_forest_contributor::MastForestContributor,
        },
    };

    #[test]
    fn test_join_node_builder_round_trip_with_digest() {
        let mut forest = MastForest::new();

        // create two basic block nodes to use as children for the join node
        let add_builder = BasicBlockNodeBuilder::new(vec![Operation::Add], vec![]);
        let mul_builder = BasicBlockNodeBuilder::new(vec![Operation::Mul], vec![]);

        // add children to forest and build node
        let child1 = add_builder.add_to_forest(&mut forest).unwrap();
        let child2 = mul_builder.add_to_forest(&mut forest).unwrap();
        let join_builder1 = JoinNodeBuilder::new([child1, child2]);
        let join_id = join_builder1.add_to_forest(&mut forest).unwrap();

        // perform round-trip
        let join_node = forest.get_node_by_id(join_id).unwrap().clone();
        let rebuilt_node = join_node.clone().to_builder().build(&forest).unwrap();

        assert_eq!(join_node, rebuilt_node);

        // Test digest forcing
        let forced_join_digest =
            Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);
        let join_builder2 = JoinNodeBuilder::new([child1, child2]).with_digest(forced_join_digest);
        let join_node2 = join_builder2
            .build(&forest)
            .expect("Failed to build join node with forced digest");

        assert_eq!(
            join_node2.digest(),
            forced_join_digest,
            "Forced digest should be used for join node"
        );
    }

    #[test]
    fn test_mast_node_builder_enum_digest_forcing() {
        let forest = MastForest::new();

        let mast_builder1 = MastNodeBuilder::BasicBlock(BasicBlockNodeBuilder::new(
            vec![Operation::Push(Felt::new(10))],
            vec![],
        ));
        let mast_node1 = mast_builder1.build(&forest).expect("Failed to build mast node1");
        let mast_normal_digest = mast_node1.digest();

        let forced_mast_digest =
            Word::new([Felt::new(9), Felt::new(10), Felt::new(11), Felt::new(12)]);
        let mast_builder2 = MastNodeBuilder::BasicBlock(
            BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::new(10))], vec![])
                .with_digest(forced_mast_digest),
        );
        let mast_node2 = mast_builder2
            .build(&forest)
            .expect("Failed to build mast node with forced digest");

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
