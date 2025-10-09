use enum_dispatch::enum_dispatch;

use super::{
    BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
    LoopNodeBuilder, SplitNodeBuilder,
};
use crate::mast::{MastForest, MastForestError, MastNodeId};

#[allow(dead_code)]
#[enum_dispatch]
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
}

/// Enum of all MAST node builders that can be added to a forest.
/// This allows for generic handling of different builder types through enum_dispatch.
#[enum_dispatch(MastForestContributor)]
#[derive(Debug)]
pub enum MastNodeBuilder {
    BasicBlock(BasicBlockNodeBuilder),
    Call(CallNodeBuilder),
    Dyn(DynNodeBuilder),
    External(ExternalNodeBuilder),
    Join(JoinNodeBuilder),
    Loop(LoopNodeBuilder),
    Split(SplitNodeBuilder),
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
