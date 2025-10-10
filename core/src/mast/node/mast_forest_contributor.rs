use alloc::vec::Vec;

use miden_utils_core_derive::MastForestContributor;

use super::{
    BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
    LoopNodeBuilder, SplitNodeBuilder,
};
use crate::mast::{MastForest, MastForestError, MastNodeId};

pub trait MastForestContributor {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError>;

    /// Returns the fingerprint for this builder without constructing a MastNode.
    ///
    /// This method computes the same value as `MastNodeFingerprint::from_mast_node`, but
    /// operates directly on the builder data without first constructing a MastNode.
    fn fingerprint_for_node(
        &self,
        forest: &MastForest,
        hash_by_node_id: &impl crate::LookupByIdx<MastNodeId, crate::mast::MastNodeFingerprint>,
    ) -> Result<crate::mast::MastNodeFingerprint, MastForestError>;

    /// Remap the node children to their new positions indicated by the given
    /// [`crate::mast::Remapping`].
    fn remap_children(self, remapping: &crate::mast::Remapping) -> Self;

    /// Adds decorators to be executed before this node.
    fn with_before_enter(self, _decorators: impl Into<Vec<crate::mast::DecoratorId>>) -> Self;

    /// Adds decorators to be executed after this node.
    fn with_after_exit(self, _decorators: impl Into<Vec<crate::mast::DecoratorId>>) -> Self;
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
mod fingerprint_consistency_tests {
    use alloc::vec::Vec;

    use proptest::prelude::*;

    use crate::{
        Operation,
        mast::{
            BasicBlockNodeBuilder, CallNodeBuilder, Decorator, DynNodeBuilder, ExternalNodeBuilder,
            JoinNodeBuilder, LoopNodeBuilder, MastForest, MastForestContributor,
            MastNodeFingerprint, SplitNodeBuilder,
            arbitrary::{decorator_id_strategy, op_non_control_strategy},
        },
    };

    // Test helper to create a test forest with decorators
    fn create_test_forest_with_decorators(decorators: &[Decorator]) -> MastForest {
        let mut forest = MastForest::new();
        for decorator in decorators {
            forest.add_decorator(decorator.clone()).unwrap();
        }
        forest
    }

    // Test BasicBlockNodeBuilder fingerprint consistency
    proptest! {
        #[test]
        fn basic_block_builder_fingerprint_consistency(
            ops in prop::collection::vec(op_non_control_strategy(), 10..=10),
            decorator_pairs in prop::collection::vec(
                (any::<usize>(), decorator_id_strategy(5)),
                0..5
            ),
        ) {
            // Ensure decorator indices are valid (not exceeding operations length) and sorted
            let valid_decorator_pairs: Vec<_> = decorator_pairs
                .into_iter()
                .map(|(idx, decorator_id)| (idx % ops.len(), decorator_id))
                .collect();
            let mut valid_decorator_pairs = valid_decorator_pairs;
            valid_decorator_pairs.sort_by_key(|(idx, _)| *idx);
            let forest = create_test_forest_with_decorators(&[
                Decorator::Trace(1),
                Decorator::Trace(2),
                Decorator::Trace(3),
                Decorator::Trace(4),
                Decorator::Trace(5),
            ]);

            let builder = BasicBlockNodeBuilder::new(ops, valid_decorator_pairs);

            // Get fingerprint from builder
            let fingerprint_from_builder = builder
                .fingerprint_for_node(&forest, &crate::IndexVec::new())
                .unwrap();

            // Build the node and get fingerprint from node
            let node = builder.build().unwrap().into();
            let fingerprint_from_node = MastNodeFingerprint::from_mast_node(&forest, &crate::IndexVec::new(), &node)
                .unwrap();

            // They should be identical
            assert_eq!(fingerprint_from_builder, fingerprint_from_node,
                "BasicBlockNodeBuilder fingerprint should match node fingerprint");
        }
    }

    // Test BasicBlockNodeBuilder fingerprint consistency without decorators
    #[test]
    fn basic_block_builder_fingerprint_consistency_no_decorators() {
        let ops = vec![Operation::Add, Operation::Mul];
        let forest =
            create_test_forest_with_decorators(&[Decorator::Trace(1), Decorator::Trace(2)]);

        let builder = BasicBlockNodeBuilder::new(ops, Vec::new());

        // Get fingerprint from builder
        let fingerprint_from_builder =
            builder.fingerprint_for_node(&forest, &crate::IndexVec::new()).unwrap();

        // Build the node and get fingerprint from node
        let node = builder.build().unwrap().into();
        let fingerprint_from_node =
            MastNodeFingerprint::from_mast_node(&forest, &crate::IndexVec::new(), &node).unwrap();

        // They should be identical
        assert_eq!(
            fingerprint_from_builder, fingerprint_from_node,
            "BasicBlockNodeBuilder fingerprint should match node fingerprint without decorators"
        );
    }

    // Test BasicBlockNodeBuilder fingerprint consistency with single decorator
    #[test]
    fn basic_block_builder_fingerprint_consistency_single_decorator() {
        let ops = vec![Operation::Add, Operation::Mul];
        let mut forest =
            create_test_forest_with_decorators(&[Decorator::Trace(1), Decorator::Trace(2)]);

        let decorator_pairs = vec![(0, forest.add_decorator(Decorator::Trace(3)).unwrap())];
        let builder = BasicBlockNodeBuilder::new(ops, decorator_pairs);

        // Get fingerprint from builder
        let fingerprint_from_builder =
            builder.fingerprint_for_node(&forest, &crate::IndexVec::new()).unwrap();

        // Build the node and get fingerprint from node
        let node = builder.build().unwrap().into();
        let fingerprint_from_node =
            MastNodeFingerprint::from_mast_node(&forest, &crate::IndexVec::new(), &node).unwrap();

        // They should be identical
        assert_eq!(
            fingerprint_from_builder, fingerprint_from_node,
            "BasicBlockNodeBuilder fingerprint should match node fingerprint with single decorator"
        );
    }

    // Test CallNodeBuilder fingerprint consistency
    proptest! {
        #[test]
        fn call_node_builder_fingerprint_consistency(
            callee_id in any::<usize>(),
            is_syscall in any::<bool>(),
            before_enter in prop::collection::vec(decorator_id_strategy(5), 0..5),
            after_exit in prop::collection::vec(decorator_id_strategy(5), 0..5),
        ) {
            let mut forest = create_test_forest_with_decorators(&[
                Decorator::Trace(1),
                Decorator::Trace(2),
                Decorator::Trace(3),
                Decorator::Trace(4),
                Decorator::Trace(5),
            ]);

            // Add some dummy nodes to ensure we have valid node IDs
            let node_ids: Vec<crate::mast::MastNodeId> = (0..5).map(|_| {
                BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
                    .add_to_forest(&mut forest)
                    .unwrap()
            }).collect();

            // Use a valid node ID from the nodes we just created
            let callee = node_ids[callee_id % node_ids.len()];

            let builder = if is_syscall {
                CallNodeBuilder::new_syscall(callee)
            } else {
                CallNodeBuilder::new(callee)
            };
            let builder = builder.with_before_enter(before_enter).with_after_exit(after_exit);

            // Create hash lookup containing all node fingerprints in the forest
            let mut hash_lookup = crate::IndexVec::new();
            for mast_node in forest.nodes.iter() {
                let fingerprint = MastNodeFingerprint::from_mast_node(&forest, &hash_lookup, mast_node).unwrap();
                let _ = hash_lookup.push(fingerprint);
            }

            // Get fingerprint from builder using the populated hash lookup
            let fingerprint_from_builder = builder
                .fingerprint_for_node(&forest, &hash_lookup)
                .unwrap();

            // Build the node and get fingerprint from node
            let node = builder.build(&forest).unwrap().into();
            let fingerprint_from_node = MastNodeFingerprint::from_mast_node(&forest, &hash_lookup, &node)
                .unwrap();

            // They should be identical
            assert_eq!(fingerprint_from_builder, fingerprint_from_node,
                "CallNodeBuilder fingerprint should match node fingerprint");
        }
    }

    // Test JoinNodeBuilder fingerprint consistency
    proptest! {
        #[test]
        fn join_node_builder_fingerprint_consistency(
            child_ids in any::<[usize; 2]>(),
            before_enter in prop::collection::vec(decorator_id_strategy(5), 0..=5),
            after_exit in prop::collection::vec(decorator_id_strategy(5), 0..=5),
        ) {
            let mut forest = create_test_forest_with_decorators(&[
                Decorator::Trace(1),
                Decorator::Trace(2),
                Decorator::Trace(3),
                Decorator::Trace(4),
                Decorator::Trace(5),
            ]);

            // Add some dummy nodes to ensure we have valid node IDs
            let node_ids: Vec<crate::mast::MastNodeId> = (0..5).map(|_| {
                BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
                    .add_to_forest(&mut forest)
                    .unwrap()
            }).collect();

            // Use valid node IDs from the nodes we just created
            let children = [
                node_ids[child_ids[0] % node_ids.len()],
                node_ids[child_ids[1] % node_ids.len()],
            ];

            let builder = JoinNodeBuilder::new(children)
                .with_before_enter(before_enter)
                .with_after_exit(after_exit);

            // Create hash lookup containing all node fingerprints in the forest
            let mut hash_lookup = crate::IndexVec::new();
            for mast_node in forest.nodes.iter() {
                let fingerprint = MastNodeFingerprint::from_mast_node(&forest, &hash_lookup, mast_node).unwrap();
                let _ = hash_lookup.push(fingerprint);
            }

            // Get fingerprint from builder using the populated hash lookup
            let fingerprint_from_builder = builder
                .fingerprint_for_node(&forest, &hash_lookup)
                .unwrap();

            // Build the node and get fingerprint from node
            let node = builder.build(&forest).unwrap().into();
            let fingerprint_from_node = MastNodeFingerprint::from_mast_node(&forest, &hash_lookup, &node)
                .unwrap();

            // They should be identical
            assert_eq!(fingerprint_from_builder, fingerprint_from_node,
                "JoinNodeBuilder fingerprint should match node fingerprint");
        }
    }

    // Test SplitNodeBuilder fingerprint consistency
    proptest! {
        #[test]
        fn split_node_builder_fingerprint_consistency(
            branch_ids in any::<[usize; 2]>(),
            before_enter in prop::collection::vec(decorator_id_strategy(5), 0..=5),
            after_exit in prop::collection::vec(decorator_id_strategy(5), 0..=5),
        ) {
            let mut forest = create_test_forest_with_decorators(&[
                Decorator::Trace(1),
                Decorator::Trace(2),
                Decorator::Trace(3),
                Decorator::Trace(4),
                Decorator::Trace(5),
            ]);

            // Add some dummy nodes to ensure we have valid node IDs
            let node_ids: Vec<crate::mast::MastNodeId> = (0..5).map(|_| {
                BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
                    .add_to_forest(&mut forest)
                    .unwrap()
            }).collect();

            // Use valid node IDs from the nodes we just created
            let branches = [
                node_ids[branch_ids[0] % node_ids.len()],
                node_ids[branch_ids[1] % node_ids.len()],
            ];

            let builder = SplitNodeBuilder::new(branches)
                .with_before_enter(before_enter)
                .with_after_exit(after_exit);

            // Create hash lookup containing all node fingerprints in the forest
            let mut hash_lookup = crate::IndexVec::new();
            for mast_node in forest.nodes.iter() {
                let fingerprint = MastNodeFingerprint::from_mast_node(&forest, &hash_lookup, mast_node).unwrap();
                let _ = hash_lookup.push(fingerprint);
            }

            // Get fingerprint from builder using the populated hash lookup
            let fingerprint_from_builder = builder
                .fingerprint_for_node(&forest, &hash_lookup)
                .unwrap();

            // Build the node and get fingerprint from node
            let node = builder.build(&forest).unwrap().into();
            let fingerprint_from_node = MastNodeFingerprint::from_mast_node(&forest, &hash_lookup, &node)
                .unwrap();

            // They should be identical
            assert_eq!(fingerprint_from_builder, fingerprint_from_node,
                "SplitNodeBuilder fingerprint should match node fingerprint");
        }
    }

    // Test LoopNodeBuilder fingerprint consistency
    proptest! {
        #[test]
        fn loop_node_builder_fingerprint_consistency(
            body_id in any::<usize>(),
            before_enter in prop::collection::vec(decorator_id_strategy(5), 0..=5),
            after_exit in prop::collection::vec(decorator_id_strategy(5), 0..=5),
        ) {
            let mut forest = create_test_forest_with_decorators(&[
                Decorator::Trace(1),
                Decorator::Trace(2),
                Decorator::Trace(3),
                Decorator::Trace(4),
                Decorator::Trace(5),
            ]);

            // Add some dummy nodes to ensure we have valid node IDs
            let node_ids: Vec<crate::mast::MastNodeId> = (0..5).map(|_| {
                BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
                    .add_to_forest(&mut forest)
                    .unwrap()
            }).collect();

            // Use a valid node ID from the nodes we just created
            let body = node_ids[body_id % node_ids.len()];

            let builder = LoopNodeBuilder::new(body)
                .with_before_enter(before_enter)
                .with_after_exit(after_exit);

            // Create hash lookup containing all node fingerprints in the forest
            let mut hash_lookup = crate::IndexVec::new();
            for mast_node in forest.nodes.iter() {
                let fingerprint = MastNodeFingerprint::from_mast_node(&forest, &hash_lookup, mast_node).unwrap();
                let _ = hash_lookup.push(fingerprint);
            }

            // Get fingerprint from builder using the populated hash lookup
            let fingerprint_from_builder = builder
                .fingerprint_for_node(&forest, &hash_lookup)
                .unwrap();

            // Build the node and get fingerprint from node
            let node = builder.build(&forest).unwrap().into();
            let fingerprint_from_node = MastNodeFingerprint::from_mast_node(&forest, &hash_lookup, &node)
                .unwrap();

            // They should be identical
            assert_eq!(fingerprint_from_builder, fingerprint_from_node,
                "LoopNodeBuilder fingerprint should match node fingerprint");
        }
    }

    // Test DynNodeBuilder fingerprint consistency
    proptest! {
        #[test]
        fn dyn_node_builder_fingerprint_consistency(
            is_dyncall in any::<bool>(),
            before_enter in prop::collection::vec(decorator_id_strategy(5), 0..=5),
            after_exit in prop::collection::vec(decorator_id_strategy(5), 0..=5),
        ) {
            let forest = create_test_forest_with_decorators(&[
                Decorator::Trace(1),
                Decorator::Trace(2),
                Decorator::Trace(3),
                Decorator::Trace(4),
                Decorator::Trace(5),
            ]);

            let builder = if is_dyncall {
                DynNodeBuilder::new_dyncall()
            } else {
                DynNodeBuilder::new_dyn()
            };
            let builder = builder.with_before_enter(before_enter).with_after_exit(after_exit);

            // Get fingerprint from builder
            let fingerprint_from_builder = builder
                .fingerprint_for_node(&forest, &crate::IndexVec::new())
                .unwrap();

            // Build the node and get fingerprint from node
            let node = builder.build().into();
            let fingerprint_from_node = MastNodeFingerprint::from_mast_node(&forest, &crate::IndexVec::new(), &node)
                .unwrap();

            // They should be identical
            assert_eq!(fingerprint_from_builder, fingerprint_from_node,
                "DynNodeBuilder fingerprint should match node fingerprint");
        }
    }

    // Test ExternalNodeBuilder fingerprint consistency
    proptest! {
        #[test]
        fn external_node_builder_fingerprint_consistency(
            digest in any::<[u64; 4]>().prop_map(|[a, b, c, d]| {
                crate::Word::new([
                    crate::Felt::new(a),
                    crate::Felt::new(b),
                    crate::Felt::new(c),
                    crate::Felt::new(d),
                ])
            }),
            before_enter in prop::collection::vec(decorator_id_strategy(5), 0..=5),
            after_exit in prop::collection::vec(decorator_id_strategy(5), 0..=5),
        ) {
            let forest = create_test_forest_with_decorators(&[
                Decorator::Trace(1),
                Decorator::Trace(2),
                Decorator::Trace(3),
                Decorator::Trace(4),
                Decorator::Trace(5),
            ]);

            let builder = ExternalNodeBuilder::new(digest)
                .with_before_enter(before_enter)
                .with_after_exit(after_exit);

            // Get fingerprint from builder
            let fingerprint_from_builder = builder
                .fingerprint_for_node(&forest, &crate::IndexVec::new())
                .unwrap();

            // Build the node and get fingerprint from node
            let node = builder.build().into();
            let fingerprint_from_node = MastNodeFingerprint::from_mast_node(&forest, &crate::IndexVec::new(), &node)
                .unwrap();

            // They should be identical
            assert_eq!(fingerprint_from_builder, fingerprint_from_node,
                "ExternalNodeBuilder fingerprint should match node fingerprint");
        }
    }
}

#[cfg(test)]
mod round_trip_tests {
    use crate::{
        Decorator, Felt, Operation,
        mast::{
            BasicBlockNode, CallNode, DynNode, ExternalNode, JoinNode, LoopNode, MastForest,
            MastForestError, MastNode, MastNodeExt, SplitNode,
        },
    };

    /// Helper function to create a test forest with some nodes and decorators
    fn create_test_forest() -> MastForest {
        let mut forest = MastForest::new();

        // Add some decorators
        let trace_decorator = forest.add_decorator(Decorator::Trace(1)).unwrap();
        let _ = forest.add_decorator(Decorator::Trace(2)).unwrap();

        // Add a basic block node
        let basic_block_node =
            BasicBlockNode::new(vec![Operation::Add, Operation::Mul], vec![(0, trace_decorator)])
                .unwrap();
        let _basic_block_id = forest.add_node(MastNode::Block(basic_block_node)).unwrap();

        forest
    }

    #[test]
    fn test_basic_block_node_round_trip() -> Result<(), MastForestError> {
        let mut forest = create_test_forest();
        let decorator_id = forest.add_decorator(Decorator::Trace(42)).unwrap();

        let original = BasicBlockNode::new(
            vec![Operation::Add, Operation::Mul, Operation::Drop],
            vec![(0, decorator_id), (2, decorator_id)],
        )?;

        let round_trip = original.clone().to_builder().build()?.into();

        let round_trip_basic_block = match round_trip {
            MastNode::Block(node) => node,
            _ => panic!("Expected BasicBlockNode"),
        };

        assert_eq!(original, round_trip_basic_block);
        Ok(())
    }

    #[test]
    fn test_join_node_round_trip() -> Result<(), MastForestError> {
        let mut forest = create_test_forest();

        // Add two basic block nodes to use as children
        let child1 = BasicBlockNode::new(vec![Operation::Add], vec![])?;
        let child2 = BasicBlockNode::new(vec![Operation::Mul], vec![])?;
        let child1_id = forest.add_node(MastNode::Block(child1))?;
        let child2_id = forest.add_node(MastNode::Block(child2))?;

        let decorator_id = forest.add_decorator(Decorator::Trace(99)).unwrap();

        let original = JoinNode::new([child1_id, child2_id], &forest)?;

        // Add decorators
        let mut original_with_decorators = original.clone();
        original_with_decorators.append_before_enter(&[decorator_id]);
        original_with_decorators.append_after_exit(&[decorator_id]);

        let round_trip = original_with_decorators.clone().to_builder().build(&forest)?.into();

        let round_trip_join = match round_trip {
            MastNode::Join(node) => node,
            _ => panic!("Expected JoinNode"),
        };

        assert_eq!(original_with_decorators, round_trip_join);
        Ok(())
    }

    #[test]
    fn test_split_node_round_trip() -> Result<(), MastForestError> {
        let mut forest = create_test_forest();

        // Add two basic block nodes to use as branches
        let branch1 = BasicBlockNode::new(vec![Operation::Add], vec![])?;
        let branch2 = BasicBlockNode::new(vec![Operation::Mul], vec![])?;
        let branch1_id = forest.add_node(MastNode::Block(branch1))?;
        let branch2_id = forest.add_node(MastNode::Block(branch2))?;

        let original = SplitNode::new([branch1_id, branch2_id], &forest)?;

        let round_trip = original.clone().to_builder().build(&forest)?.into();

        let round_trip_split = match round_trip {
            MastNode::Split(node) => node,
            _ => panic!("Expected SplitNode"),
        };

        assert_eq!(original, round_trip_split);
        Ok(())
    }

    #[test]
    fn test_loop_node_round_trip() -> Result<(), MastForestError> {
        let mut forest = create_test_forest();

        // Add a basic block node to use as the loop body
        let body = BasicBlockNode::new(vec![Operation::Add, Operation::Add], vec![])?;
        let body_id = forest.add_node(MastNode::Block(body))?;

        let original = LoopNode::new(body_id, &forest)?;

        let round_trip = original.clone().to_builder().build(&forest)?.into();

        let round_trip_loop = match round_trip {
            MastNode::Loop(node) => node,
            _ => panic!("Expected LoopNode"),
        };

        assert_eq!(original, round_trip_loop);
        Ok(())
    }

    #[test]
    fn test_call_node_round_trip() -> Result<(), MastForestError> {
        let mut forest = create_test_forest();

        // Add a basic block node to use as the callee
        let callee = BasicBlockNode::new(vec![Operation::Push(Felt::new(42))], vec![])?;
        let callee_id = forest.add_node(MastNode::Block(callee))?;

        let original_call = CallNode::new(callee_id, &forest)?;
        let original_syscall = CallNode::new_syscall(callee_id, &forest)?;

        let round_trip_call = original_call.clone().to_builder().build(&forest)?.into();
        let round_trip_syscall = original_syscall.clone().to_builder().build(&forest)?.into();

        let round_trip_call_node = match round_trip_call {
            MastNode::Call(node) => node,
            _ => panic!("Expected CallNode"),
        };

        let round_trip_syscall_node = match round_trip_syscall {
            MastNode::Call(node) => node,
            _ => panic!("Expected CallNode"),
        };

        assert_eq!(original_call, round_trip_call_node);
        assert_eq!(original_syscall, round_trip_syscall_node);
        Ok(())
    }

    #[test]
    fn test_dyn_node_round_trip() -> Result<(), MastForestError> {
        let original_dyn = DynNode::new_dyn();
        let original_dyncall = DynNode::new_dyncall();

        let round_trip_dyn = original_dyn.clone().to_builder().build().into();
        let round_trip_dyncall = original_dyncall.clone().to_builder().build().into();

        let round_trip_dyn_node = match round_trip_dyn {
            MastNode::Dyn(node) => node,
            _ => panic!("Expected DynNode"),
        };

        let round_trip_dyncall_node = match round_trip_dyncall {
            MastNode::Dyn(node) => node,
            _ => panic!("Expected DynNode"),
        };

        assert_eq!(original_dyn, round_trip_dyn_node);
        assert_eq!(original_dyncall, round_trip_dyncall_node);
        Ok(())
    }

    #[test]
    fn test_external_node_round_trip() -> Result<(), MastForestError> {
        let digest = crate::Word::default();
        let original = ExternalNode::new(digest);

        let round_trip = original.clone().to_builder().build().into();

        let round_trip_external = match round_trip {
            MastNode::External(node) => node,
            _ => panic!("Expected ExternalNode"),
        };

        assert_eq!(original, round_trip_external);
        Ok(())
    }

    #[test]
    fn test_mast_node_enum_round_trip() -> Result<(), MastForestError> {
        let mut forest = create_test_forest();

        // Test each MastNode variant
        let basic_block = BasicBlockNode::new(vec![Operation::Add], vec![])?;
        let mast_node_basic_block: MastNode = MastNode::Block(basic_block.clone());

        let child = BasicBlockNode::new(vec![Operation::Mul], vec![])?;
        let child_id = forest.add_node(MastNode::Block(child))?;
        let join_node = JoinNode::new([child_id, child_id], &forest)?;
        let mast_node_join: MastNode = MastNode::Join(join_node.clone());

        let external = ExternalNode::new(crate::Word::default());
        let mast_node_external: MastNode = MastNode::External(external.clone());

        // Test round trip for each variant
        let round_trip_basic_block = mast_node_basic_block.clone().to_builder().build(&forest)?;
        let round_trip_join = mast_node_join.clone().to_builder().build(&forest)?;
        let round_trip_external = mast_node_external.clone().to_builder().build(&forest)?;

        assert_eq!(mast_node_basic_block, round_trip_basic_block);
        assert_eq!(mast_node_join, round_trip_join);
        assert_eq!(mast_node_external, round_trip_external);

        Ok(())
    }

    #[test]
    fn test_round_trip_with_complex_decorators() -> Result<(), MastForestError> {
        let mut forest = create_test_forest();

        // Add multiple decorators
        let deco1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
        let deco2 = forest.add_decorator(Decorator::Trace(2)).unwrap();
        let deco3 = forest.add_decorator(Decorator::Trace(3)).unwrap();

        // Create a basic block with multiple decorators
        let original = BasicBlockNode::new(
            vec![Operation::Add, Operation::Mul, Operation::Push(Felt::new(42))],
            vec![(0, deco1), (1, deco2), (2, deco3)],
        )?;

        // Add before/after decorators
        let mut with_extra_decorators = original.clone();
        with_extra_decorators.append_before_enter(&[deco1, deco2]);
        with_extra_decorators.append_after_exit(&[deco3]);

        let round_trip = with_extra_decorators.clone().to_builder().build()?.into();

        let round_trip_basic_block = match round_trip {
            MastNode::Block(node) => node,
            _ => panic!("Expected BasicBlockNode"),
        };

        assert_eq!(with_extra_decorators, round_trip_basic_block);
        Ok(())
    }
}
