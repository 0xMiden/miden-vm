use alloc::vec::Vec;

use miden_utils_core_derive::MastForestContributor;

use super::{
    BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
    LoopNodeBuilder, SplitNodeBuilder,
};
#[cfg(any(test, feature = "arbitrary", feature = "testing"))]
use crate::utils::Idx;
use crate::{
    Word,
    mast::{DecoratorId, MastForest, MastForestError, MastNode, MastNodeFingerprint, MastNodeId},
    operations::DecoratorList,
    utils::LookupByIdx,
};

pub trait MastForestContributor {
    #[cfg(any(test, feature = "arbitrary", feature = "testing"))]
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError>;

    /// Returns the fingerprint for this builder without constructing a MastNode.
    ///
    /// This method computes the fingerprint for a node directly from the builder data
    /// without first constructing a MastNode, providing the same result as the
    /// traditional fingerprint computation approach.
    fn fingerprint_for_node(
        &self,
        forest: &MastForest,
        hash_by_node_id: &impl LookupByIdx<MastNodeId, MastNodeFingerprint>,
    ) -> Result<MastNodeFingerprint, MastForestError>;

    /// Remap the node children to their new positions indicated by the given
    /// lookup.
    fn remap_children(self, remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self;

    /// Adds decorators to be executed before this node.
    fn with_before_enter(self, _decorators: impl Into<Vec<DecoratorId>>) -> Self;

    /// Adds decorators to be executed after this node.
    fn with_after_exit(self, _decorators: impl Into<Vec<DecoratorId>>) -> Self;

    /// Appends decorators to be executed before this node.
    ///
    /// Unlike `with_before_enter`, this method adds to the existing list of decorators
    /// rather than replacing them.
    fn append_before_enter(&mut self, decorators: impl IntoIterator<Item = DecoratorId>);

    /// Appends decorators to be executed after this node.
    ///
    /// Unlike `with_after_exit`, this method adds to the existing list of decorators
    /// rather than replacing them.
    fn append_after_exit(&mut self, decorators: impl IntoIterator<Item = DecoratorId>);

    /// Sets a digest to be forced into the built node.
    ///
    /// When a digest is set, the builder will use this digest instead of computing
    /// the normal digest for the node during the build() operation.
    fn with_digest(self, digest: Word) -> Self;
}

pub(super) struct NodeBuilderLifecycle<'a> {
    before_enter: &'a [DecoratorId],
    after_exit: &'a [DecoratorId],
    digest: Option<Word>,
}

impl<'a> NodeBuilderLifecycle<'a> {
    pub(super) fn new(
        before_enter: &'a [DecoratorId],
        after_exit: &'a [DecoratorId],
        digest: Option<Word>,
    ) -> Self {
        Self { before_enter, after_exit, digest }
    }

    #[cfg(any(test, feature = "arbitrary", feature = "testing"))]
    pub(super) fn validate_children(
        forest: &MastForest,
        children: &[MastNodeId],
    ) -> Result<(), MastForestError> {
        let forest_len = forest.nodes.len();
        for child in children {
            if child.to_usize() >= forest_len {
                return Err(MastForestError::NodeIdOverflow(*child, forest_len));
            }
        }

        Ok(())
    }

    pub(super) fn digest_or_compute(&self, compute: impl FnOnce() -> Word) -> Word {
        self.digest.unwrap_or_else(compute)
    }

    pub(super) fn forced_digest(&self) -> Result<Word, MastForestError> {
        self.digest.ok_or(MastForestError::DigestRequiredForDeserialization)
    }

    pub(super) fn fingerprint(
        &self,
        forest: &MastForest,
        hash_by_node_id: &impl LookupByIdx<MastNodeId, MastNodeFingerprint>,
        children: &[MastNodeId],
        compute_digest: impl FnOnce() -> Word,
    ) -> Result<MastNodeFingerprint, MastForestError> {
        crate::mast::node_fingerprint::fingerprint_from_parts(
            forest,
            hash_by_node_id,
            self.before_enter,
            self.after_exit,
            children,
            self.digest_or_compute(compute_digest),
        )
    }

    #[cfg(any(test, feature = "arbitrary", feature = "testing"))]
    pub(super) fn add_linked_node(
        &self,
        forest: &mut MastForest,
        make_node: impl FnOnce(MastNodeId) -> MastNode,
    ) -> Result<MastNodeId, MastForestError> {
        let future_node_id = MastNodeId::new_unchecked(forest.nodes.len() as u32);
        forest.register_node_decorators(future_node_id, self.before_enter, self.after_exit);

        forest
            .nodes
            .push(make_node(future_node_id))
            .map_err(|_| MastForestError::TooManyNodes)
    }
}

pub(super) fn remap_child_id(
    child: MastNodeId,
    remapping: &impl LookupByIdx<MastNodeId, MastNodeId>,
) -> MastNodeId {
    *remapping.get(child).unwrap_or(&child)
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

pub(in crate::mast) struct LinkedMastNodeBuild {
    pub node: MastNode,
    pub before_enter: Vec<DecoratorId>,
    pub after_exit: Vec<DecoratorId>,
    pub op_indexed_decorators: DecoratorList,
}

impl MastNodeBuilder {
    #[doc(hidden)]
    pub fn build_linked(self, node_id: MastNodeId) -> Result<MastNode, MastForestError> {
        self.build_linked_with_decorators(node_id).map(|build| build.node)
    }

    pub(in crate::mast) fn build_linked_with_decorators(
        self,
        node_id: MastNodeId,
    ) -> Result<LinkedMastNodeBuild, MastForestError> {
        match self {
            MastNodeBuilder::BasicBlock(builder) => {
                let (node, before_enter, after_exit, op_indexed_decorators) =
                    builder.build_linked_with_decorators(node_id)?;
                Ok(LinkedMastNodeBuild {
                    node: node.into(),
                    before_enter,
                    after_exit,
                    op_indexed_decorators,
                })
            },
            MastNodeBuilder::Call(builder) => {
                let (node, before_enter, after_exit) =
                    builder.build_linked_with_decorators(node_id)?;
                Ok(LinkedMastNodeBuild {
                    node: node.into(),
                    before_enter,
                    after_exit,
                    op_indexed_decorators: DecoratorList::new(),
                })
            },
            MastNodeBuilder::Dyn(builder) => {
                let (node, before_enter, after_exit) =
                    builder.build_linked_with_decorators(node_id);
                Ok(LinkedMastNodeBuild {
                    node: node.into(),
                    before_enter,
                    after_exit,
                    op_indexed_decorators: DecoratorList::new(),
                })
            },
            MastNodeBuilder::External(builder) => {
                let (node, before_enter, after_exit) =
                    builder.build_linked_with_decorators(node_id);
                Ok(LinkedMastNodeBuild {
                    node: node.into(),
                    before_enter,
                    after_exit,
                    op_indexed_decorators: DecoratorList::new(),
                })
            },
            MastNodeBuilder::Join(builder) => {
                let (node, before_enter, after_exit) =
                    builder.build_linked_with_decorators(node_id)?;
                Ok(LinkedMastNodeBuild {
                    node: node.into(),
                    before_enter,
                    after_exit,
                    op_indexed_decorators: DecoratorList::new(),
                })
            },
            MastNodeBuilder::Loop(builder) => {
                let (node, before_enter, after_exit) =
                    builder.build_linked_with_decorators(node_id)?;
                Ok(LinkedMastNodeBuild {
                    node: node.into(),
                    before_enter,
                    after_exit,
                    op_indexed_decorators: DecoratorList::new(),
                })
            },
            MastNodeBuilder::Split(builder) => {
                let (node, before_enter, after_exit) =
                    builder.build_linked_with_decorators(node_id)?;
                Ok(LinkedMastNodeBuild {
                    node: node.into(),
                    before_enter,
                    after_exit,
                    op_indexed_decorators: DecoratorList::new(),
                })
            },
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
        Felt,
        mast::{
            BasicBlockNodeBuilder, DecoratorId, MastForest, MastForestContributor,
            arbitrary::op_non_control_strategy,
        },
        operations::{Decorator, Operation},
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
        let error_code = Felt::new_unchecked(42);

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
        let error_code_1 = Felt::new_unchecked(42);
        let error_code_2 = Felt::new_unchecked(123);

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
            let felt_1 = Felt::new_unchecked(error_code_1);
            let felt_2 = Felt::new_unchecked(error_code_2);

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
    use alloc::collections::BTreeMap;

    use miden_crypto::Felt;

    use crate::{
        Word,
        crypto::hash::Blake3_256,
        mast::{
            BasicBlockNodeBuilder, CallNodeBuilder, DecoratorId, JoinNodeBuilder, LoopNodeBuilder,
            MastForest, MastForestError, MastNode, MastNodeBuilder, MastNodeExt,
            MastNodeFingerprint, MastNodeId, SplitNodeBuilder,
            node::mast_forest_contributor::MastForestContributor,
        },
        operations::{Decorator, Operation},
    };

    fn test_word(value: u64) -> Word {
        Word::new([
            Felt::new_unchecked(value),
            Felt::new_unchecked(value + 1),
            Felt::new_unchecked(value + 2),
            Felt::new_unchecked(value + 3),
        ])
    }

    fn add_block(forest: &mut MastForest, operation: Operation) -> MastNodeId {
        BasicBlockNodeBuilder::new(vec![operation], vec![])
            .add_to_forest(forest)
            .expect("basic block should be added to test forest")
    }

    fn add_trace_decorator(forest: &mut MastForest, value: u8) -> DecoratorId {
        forest.add_decorator(Decorator::Trace(value.into())).unwrap()
    }

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
        let rebuilt_id = join_node.to_builder(&forest).add_to_forest(&mut forest).unwrap();
        let original_node = forest.get_node_by_id(join_id).unwrap();
        let rebuilt_node = forest.get_node_by_id(rebuilt_id).unwrap();

        match (original_node, rebuilt_node) {
            (MastNode::Join(original), MastNode::Join(rebuilt)) => {
                assert_eq!(original.first(), rebuilt.first());
                assert_eq!(original.second(), rebuilt.second());
                assert_eq!(original.digest(), rebuilt.digest());
            },
            _ => panic!("Both nodes should be Join nodes"),
        }

        // Test digest forcing
        let forced_join_digest = Word::new([
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ]);
        let join_builder2 = JoinNodeBuilder::new([child1, child2]).with_digest(forced_join_digest);
        let join_node_id2 = join_builder2
            .add_to_forest(&mut forest)
            .expect("Failed to add join node to forest with forced digest");
        let join_node2 = forest.get_node_by_id(join_node_id2).unwrap().unwrap_join();

        assert_eq!(
            join_node2.digest(),
            forced_join_digest,
            "Forced digest should be used for join node"
        );
    }

    #[test]
    fn test_mast_node_builder_enum_digest_forcing() {
        let mut forest = MastForest::new();

        let mast_builder1 = MastNodeBuilder::BasicBlock(BasicBlockNodeBuilder::new(
            vec![Operation::Push(Felt::new_unchecked(10))],
            vec![],
        ));
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
            BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::new_unchecked(10))], vec![])
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

    #[test]
    fn mast_node_builder_builds_control_flow_with_forced_digest_without_forest() {
        let forced_digest = Word::new([
            Felt::new_unchecked(13),
            Felt::new_unchecked(14),
            Felt::new_unchecked(15),
            Felt::new_unchecked(16),
        ]);
        let children = [MastNodeId::new_unchecked(10), MastNodeId::new_unchecked(11)];
        let node_id = MastNodeId::new_unchecked(0);

        let node = MastNodeBuilder::Join(JoinNodeBuilder::new(children).with_digest(forced_digest))
            .build_linked(node_id)
            .expect("forced-digest join should build without reading a forest");

        let MastNode::Join(node) = node else {
            panic!("expected join node");
        };
        assert_eq!(node.digest(), forced_digest);
        assert_eq!([node.first(), node.second()], children);

        assert!(
            MastNodeBuilder::Join(JoinNodeBuilder::new(children))
                .build_linked(node_id)
                .is_err(),
            "control-flow nodes require a forced digest when built without a forest"
        );
    }

    #[test]
    fn control_node_builders_reject_out_of_range_children() {
        let mut forest = MastForest::new();
        let valid_child = add_block(&mut forest, Operation::Add);
        let missing_child = MastNodeId::new_unchecked(99);

        assert!(matches!(
            LoopNodeBuilder::new(missing_child).add_to_forest(&mut forest),
            Err(MastForestError::NodeIdOverflow(node_id, _)) if node_id == missing_child
        ));
        assert!(matches!(
            CallNodeBuilder::new(missing_child).add_to_forest(&mut forest),
            Err(MastForestError::NodeIdOverflow(node_id, _)) if node_id == missing_child
        ));
        assert!(matches!(
            JoinNodeBuilder::new([valid_child, missing_child]).add_to_forest(&mut forest),
            Err(MastForestError::NodeIdOverflow(node_id, _)) if node_id == missing_child
        ));
        assert!(matches!(
            SplitNodeBuilder::new([missing_child, valid_child]).add_to_forest(&mut forest),
            Err(MastForestError::NodeIdOverflow(node_id, _)) if node_id == missing_child
        ));
    }

    #[test]
    fn add_to_forest_links_decorator_storage_to_inserted_node() {
        let mut forest = MastForest::new();
        let body = add_block(&mut forest, Operation::Mul);
        let before = add_trace_decorator(&mut forest, 7);
        let after = add_trace_decorator(&mut forest, 9);

        let loop_id = LoopNodeBuilder::new(body)
            .with_before_enter([before])
            .with_after_exit([after])
            .add_to_forest(&mut forest)
            .expect("decorated loop should be added to the forest");

        let loop_node = forest[loop_id].unwrap_loop();
        assert_eq!(loop_node.linked_decorator_store_id(), loop_id);
        assert_eq!(loop_node.before_enter(&forest), &[before]);
        assert_eq!(loop_node.after_exit(&forest), &[after]);
    }

    #[test]
    fn remap_children_preserves_digest_and_node_decorators() {
        let forced_digest = test_word(21);
        let before = DecoratorId::new_unchecked(1);
        let after = DecoratorId::new_unchecked(2);
        let first = MastNodeId::new_unchecked(3);
        let second = MastNodeId::new_unchecked(4);
        let remapped_first = MastNodeId::new_unchecked(10);
        let remapped_second = MastNodeId::new_unchecked(11);

        let mut remapping = BTreeMap::new();
        remapping.insert(first, remapped_first);
        remapping.insert(second, remapped_second);

        let builder = JoinNodeBuilder::new([first, second])
            .with_before_enter([before])
            .with_after_exit([after])
            .with_digest(forced_digest)
            .remap_children(&remapping);
        let (node, before_enter, after_exit) = builder
            .build_linked_with_decorators(MastNodeId::new_unchecked(0))
            .expect("forced-digest remapped join should build without a forest");

        assert_eq!(node.first(), remapped_first);
        assert_eq!(node.second(), remapped_second);
        assert_eq!(node.digest(), forced_digest);
        assert_eq!(before_enter, &[before]);
        assert_eq!(after_exit, &[after]);
    }

    #[test]
    fn control_node_fingerprint_is_sensitive_to_child_decorator_fingerprints() {
        let forest = MastForest::new();
        let first = MastNodeId::new_unchecked(0);
        let second = MastNodeId::new_unchecked(1);
        let forced_digest = test_word(41);

        let mut child_fingerprints = BTreeMap::new();
        child_fingerprints.insert(first, MastNodeFingerprint::new(test_word(101)));
        child_fingerprints.insert(
            second,
            MastNodeFingerprint::with_decorator_root(
                test_word(201),
                Blake3_256::hash(b"child-decorator-a"),
            ),
        );

        let baseline = JoinNodeBuilder::new([first, second])
            .with_digest(forced_digest)
            .fingerprint_for_node(&forest, &child_fingerprints)
            .expect("all child fingerprints are present");

        child_fingerprints.insert(
            second,
            MastNodeFingerprint::with_decorator_root(
                test_word(201),
                Blake3_256::hash(b"child-decorator-b"),
            ),
        );
        let changed_child = JoinNodeBuilder::new([first, second])
            .with_digest(forced_digest)
            .fingerprint_for_node(&forest, &child_fingerprints)
            .expect("all child fingerprints are present");

        assert_ne!(
            baseline, changed_child,
            "same node digest must not hide a changed child decorator fingerprint"
        );
    }
}
