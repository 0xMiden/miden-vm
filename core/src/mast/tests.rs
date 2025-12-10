use alloc::vec::Vec;

use miden_crypto::WORD_SIZE;
use proptest::prelude::*;
use winter_math::FieldElement;
use winter_rand_utils::prng_array;

use crate::{
    AssemblyOp, DebugOptions, Decorator, Felt, Kernel, Operation, ProgramInfo, Word,
    chiplets::hasher,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNode, DynNodeBuilder, ExternalNodeBuilder,
        JoinNodeBuilder, LoopNodeBuilder, MastForest, MastForestContributor, MastNodeExt,
        SplitNodeBuilder,
    },
    utils::{Deserializable, Serializable},
};

#[test]
fn dyn_hash_is_correct() {
    let expected_constant =
        hasher::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYN_DOMAIN);

    let mut forest = MastForest::new();
    let dyn_node_id = DynNodeBuilder::new_dyn().add_to_forest(&mut forest).unwrap();
    let dyn_node = forest.get_node_by_id(dyn_node_id).unwrap().unwrap_dyn();
    assert_eq!(expected_constant, dyn_node.digest());
}

proptest! {
    #[test]
    fn arbitrary_program_info_serialization_works(
        kernel_count in prop::num::u8::ANY,
        ref seed in any::<[u8; 32]>()
    ) {
        let program_hash = digest_from_seed(*seed);
        let kernel: Vec<Word> = (0..kernel_count)
            .scan(*seed, |seed, _| {
                *seed = prng_array(*seed);
                Some(digest_from_seed(*seed))
            })
            .collect();
        let kernel = Kernel::new(&kernel).unwrap();
        let program_info = ProgramInfo::new(program_hash, kernel);
        let bytes = program_info.to_bytes();
        let deser = ProgramInfo::read_from_bytes(&bytes).unwrap();
        assert_eq!(program_info, deser);
    }
}

#[test]
fn test_decorator_storage_consistency_with_block_iterator() {
    let mut forest = MastForest::new();

    // Create decorators
    let deco1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
    let deco2 = forest.add_decorator(Decorator::Trace(2)).unwrap();
    let deco3 = forest.add_decorator(Decorator::Debug(DebugOptions::StackTop(42))).unwrap();

    // Create operations
    let operations = vec![
        Operation::Push(Felt::new(1)),
        Operation::Add,
        Operation::Push(Felt::new(2)),
        Operation::Mul,
    ];

    // Create decorators for specific operations
    let decorators = vec![
        (0, deco1), // Decorator at operation index 0 (first Push)
        (2, deco2), // Decorator at operation index 2 (second Push)
        (3, deco3), // Decorator at operation index 3 (Mul)
    ];

    // Add block to forest using BasicBlockNodeBuilder
    let block_id = BasicBlockNodeBuilder::new(operations.clone(), decorators.clone())
        .add_to_forest(&mut forest)
        .unwrap();

    // Verify the block was created and get the actual block
    let block = if let crate::mast::MastNode::Block(block) = &forest[block_id] {
        block
    } else {
        panic!("Expected a block node");
    };

    // Test 1: Compare decorators from forest storage vs block iterator
    let forest_decorators: Vec<_> = forest
        .debug_info
        .op_decorator_storage()
        .decorator_ids_for_node(block_id)
        .unwrap()
        .flat_map(|(op_idx, decorators)| decorators.iter().map(move |dec_id| (op_idx, *dec_id)))
        .collect();

    let block_decorators: Vec<_> = block.indexed_decorator_iter(&forest).collect();

    assert_eq!(
        forest_decorators, block_decorators,
        "Decorators from forest storage should match block iterator"
    );

    // Test 2: Verify specific operation decorators match
    for (op_idx, expected_decorator_id) in &decorators {
        let forest_decos = forest
            .debug_info
            .op_decorator_storage()
            .decorator_ids_for_operation(block_id, *op_idx)
            .unwrap();
        let block_decos: Vec<_> = block
            .indexed_decorator_iter(&forest)
            .filter(|(idx, _)| *idx == *op_idx)
            .map(|(_, id)| id)
            .collect();

        assert_eq!(forest_decos, block_decos, "Decorators for operation {} should match", op_idx);
        assert_eq!(
            forest_decos,
            &[*expected_decorator_id],
            "Should have correct decorator for operation {}",
            op_idx
        );
    }

    // Test 3: Verify operations without decorators return empty
    let operations_without_decorators = [1]; // Add operation
    for op_idx in operations_without_decorators {
        let forest_decos = forest
            .debug_info
            .op_decorator_storage()
            .decorator_ids_for_operation(block_id, op_idx)
            .unwrap();
        let block_decos: Vec<_> = block
            .indexed_decorator_iter(&forest)
            .filter(|(idx, _)| *idx == op_idx)
            .map(|(_, id)| id)
            .collect();

        assert_eq!(forest_decos, [], "Operation {} should have no decorators", op_idx);
        assert_eq!(block_decos, [], "Operation {} should have no decorators", op_idx);
    }
}

#[test]
fn test_decorator_storage_consistency_with_empty_block() {
    let mut forest = MastForest::new();

    // Create operations without decorators
    let operations = vec![Operation::Push(Felt::new(1)), Operation::Add];

    // Add block to forest using BasicBlockNodeBuilder with no decorators
    let block_id = BasicBlockNodeBuilder::new(operations.clone(), vec![])
        .add_to_forest(&mut forest)
        .unwrap();

    // Verify the block was created
    let block = if let crate::mast::MastNode::Block(block) = &forest[block_id] {
        block
    } else {
        panic!("Expected a block node");
    };

    // Both should have no indexed decorators
    let forest_decorators: Vec<_> = forest
        .debug_info
        .op_decorator_storage()
        .decorator_ids_for_node(block_id)
        .unwrap()
        .collect();

    let block_decorators: Vec<_> = block.indexed_decorator_iter(&forest).collect();

    assert_eq!(forest_decorators, []);
    assert_eq!(block_decorators, []);
}

#[test]
fn test_decorator_storage_consistency_with_multiple_blocks() {
    let mut forest = MastForest::new();

    // Create decorators for first block
    let deco1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
    let deco2 = forest.add_decorator(Decorator::Trace(2)).unwrap();

    // Create first block
    let operations1 = vec![Operation::Push(Felt::new(1)), Operation::Add];
    let decorators1 = vec![(0, deco1), (1, deco2)];
    let block_id1 = BasicBlockNodeBuilder::new(operations1, decorators1)
        .add_to_forest(&mut forest)
        .unwrap();

    // Create decorator for second block
    let deco3 = forest.add_decorator(Decorator::Debug(DebugOptions::StackTop(99))).unwrap();

    // Create second block
    let operations2 = vec![Operation::Push(Felt::new(2)), Operation::Mul];
    let decorators2 = vec![(0, deco3)];
    let block_id2 = BasicBlockNodeBuilder::new(operations2, decorators2)
        .add_to_forest(&mut forest)
        .unwrap();

    // Verify first block consistency
    let forest_decorators1: Vec<_> = forest
        .debug_info
        .op_decorator_storage()
        .decorator_ids_for_node(block_id1)
        .unwrap()
        .flat_map(|(op_idx, decorators)| decorators.iter().map(move |dec_id| (op_idx, *dec_id)))
        .collect();

    let block1 = if let crate::mast::MastNode::Block(block) = &forest[block_id1] {
        block
    } else {
        panic!("Expected a block node");
    };
    let block_decorators1: Vec<_> = block1.indexed_decorator_iter(&forest).collect();

    assert_eq!(forest_decorators1, block_decorators1);

    // Verify second block consistency
    let forest_decorators2: Vec<_> = forest
        .debug_info
        .op_decorator_storage()
        .decorator_ids_for_node(block_id2)
        .unwrap()
        .flat_map(|(op_idx, decorators)| decorators.iter().map(move |dec_id| (op_idx, *dec_id)))
        .collect();

    let block2 = if let crate::mast::MastNode::Block(block) = &forest[block_id2] {
        block
    } else {
        panic!("Expected a block node");
    };
    let block_decorators2: Vec<_> = block2.indexed_decorator_iter(&forest).collect();

    assert_eq!(forest_decorators2, block_decorators2);

    // Verify the decorator storage has the correct number of nodes
    assert_eq!(forest.debug_info.op_decorator_storage().num_nodes(), 2);
}

#[test]
fn test_decorator_storage_after_strip_decorators() {
    let mut forest = MastForest::new();

    // Create decorators
    let deco1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
    let deco2 = forest.add_decorator(Decorator::Trace(2)).unwrap();

    // Create operations and decorators
    let operations = vec![Operation::Push(Felt::new(1)), Operation::Add];
    let decorators = vec![(0, deco1), (1, deco2)];

    // Add block to forest
    let block_id = BasicBlockNodeBuilder::new(operations, decorators)
        .add_to_forest(&mut forest)
        .unwrap();

    // Verify decorators exist initially
    assert!(!forest.debug_info.op_decorator_storage().is_empty());
    assert_eq!(forest.debug_info.op_decorator_storage().num_nodes(), 1);
    assert_eq!(forest.debug_info.op_decorator_storage().num_decorator_ids(), 2);

    // Strip decorators
    forest.strip_decorators();

    // Verify decorators are cleared from storage
    assert!(forest.debug_info.op_decorator_storage().is_empty());
    assert_eq!(forest.debug_info.op_decorator_storage().num_nodes(), 0);
    assert_eq!(forest.debug_info.op_decorator_storage().num_decorator_ids(), 0);

    // Verify block also has no decorators after stripping
    let block = if let crate::mast::MastNode::Block(block) = &forest[block_id] {
        block
    } else {
        panic!("Expected a block node");
    };
    let block_decorators: Vec<_> = block.indexed_decorator_iter(&forest).collect();
    assert_eq!(block_decorators, []);
}

#[test]
fn test_mast_forest_roundtrip_with_basic_blocks_and_decorators() {
    use crate::mast::MastNode;

    // Create a forest with multiple basic blocks and complex decorator arrangements
    let mut original_forest = MastForest::new();

    // Create various decorators
    let trace_deco_0 = original_forest.add_decorator(Decorator::Trace(0)).unwrap();
    let trace_deco_1 = original_forest.add_decorator(Decorator::Trace(1)).unwrap();
    let trace_deco_2 = original_forest.add_decorator(Decorator::Trace(2)).unwrap();
    let trace_deco_3 = original_forest.add_decorator(Decorator::Trace(3)).unwrap();
    let trace_deco_4 = original_forest.add_decorator(Decorator::Trace(4)).unwrap();

    // Block 1: Simple block with decorators at different operation indices
    let operations1 = vec![Operation::Add, Operation::Mul, Operation::Eq];
    let decorators1 = vec![(0, trace_deco_0), (2, trace_deco_1)];
    let block1_id = BasicBlockNodeBuilder::new(operations1, decorators1)
        .with_before_enter(vec![trace_deco_2])
        .with_after_exit(vec![trace_deco_3])
        .add_to_forest(&mut original_forest)
        .unwrap();

    // Block 2: Complex block with multiple decorators at same operation index
    let operations2 = vec![
        Operation::Push(Felt::new(1)),
        Operation::Push(Felt::new(2)),
        Operation::Mul,
        Operation::Drop,
    ];
    let decorators2 = vec![
        (0, trace_deco_0),
        (0, trace_deco_4),
        (3, trace_deco_1),
        (3, trace_deco_2),
        (3, trace_deco_3),
    ];
    let block2_id = BasicBlockNodeBuilder::new(operations2, decorators2)
        .add_to_forest(&mut original_forest)
        .unwrap();

    // Block 3: Block with no decorators
    let operations3 = vec![Operation::Incr, Operation::Neg];
    let decorators3 = vec![];
    let block3_id = BasicBlockNodeBuilder::new(operations3, decorators3)
        .add_to_forest(&mut original_forest)
        .unwrap();

    // Verify original forest structure
    assert_eq!(original_forest.num_nodes(), 3);
    assert_eq!(original_forest.debug_info.op_decorator_storage().num_nodes(), 3);
    // Note: OpToDecoratorIds may deduplicate identical decorators across blocks
    let original_decorator_count =
        original_forest.debug_info.op_decorator_storage().num_decorator_ids();

    // Serialize the forest to bytes
    let original_bytes = original_forest.to_bytes();

    // Deserialize back to a new forest
    let deserialized_forest = MastForest::read_from_bytes(&original_bytes).unwrap();

    // Verify basic forest structure
    assert_eq!(deserialized_forest.num_nodes(), 3);
    assert_eq!(deserialized_forest.debug_info.op_decorator_storage().num_nodes(), 3);
    assert_eq!(
        deserialized_forest.debug_info.op_decorator_storage().num_decorator_ids(),
        original_decorator_count
    );

    // Verify that the reconstructed forest includes the decorators
    // This ensures the OpToDecoratorIds structure in the deserialized forest is not empty
    assert!(
        !deserialized_forest.debug_info.op_decorator_storage().is_empty(),
        "Deserialized forest should have decorator storage"
    );

    // Verify blocks are equivalent (should be equal since both use Linked storage)
    for &block_id in &[block1_id, block2_id, block3_id] {
        let original_block = match &original_forest[block_id] {
            MastNode::Block(block) => block,
            _ => panic!("Expected block node"),
        };
        let deserialized_block = match &deserialized_forest[block_id] {
            MastNode::Block(block) => block,
            _ => panic!("Expected block node"),
        };

        // Blocks should be equal since both are Linked
        assert_eq!(original_block, deserialized_block);

        // Verify decorator consistency
        let original_decorators: Vec<_> =
            original_block.indexed_decorator_iter(&original_forest).collect();
        let deserialized_decorators: Vec<_> =
            deserialized_block.indexed_decorator_iter(&deserialized_forest).collect();
        assert_eq!(original_decorators, deserialized_decorators);

        // Verify before/after decorators
        assert_eq!(
            original_block.before_enter(&original_forest),
            deserialized_block.before_enter(&deserialized_forest)
        );
        assert_eq!(
            original_block.after_exit(&original_forest),
            deserialized_block.after_exit(&deserialized_forest)
        );
    }

    // Test specific decorator arrangements are preserved
    let deserialized_block1 = match &deserialized_forest[block1_id] {
        MastNode::Block(block) => block,
        _ => panic!("Expected block node"),
    };
    let deserialized_block2 = match &deserialized_forest[block2_id] {
        MastNode::Block(block) => block,
        _ => panic!("Expected block node"),
    };

    // Block 1: Should have before_enter and after_exit decorators
    assert_eq!(deserialized_block1.before_enter(&deserialized_forest), &[trace_deco_2]);
    assert_eq!(deserialized_block1.after_exit(&deserialized_forest), &[trace_deco_3]);

    // Block 2: Should have multiple decorators at operation indices 0 and 3
    let block2_decorators: Vec<_> =
        deserialized_block2.indexed_decorator_iter(&deserialized_forest).collect();
    assert_eq!(block2_decorators.len(), 5); // 2 at op 0, 3 at op 3

    // Verify specific decorator positions
    let mut op0_decorators = Vec::new();
    let mut op3_decorators = Vec::new();
    for (op_idx, decorator_id) in block2_decorators {
        match op_idx {
            0 => op0_decorators.push(decorator_id),
            3 => op3_decorators.push(decorator_id),
            _ => panic!("Unexpected decorator at operation index {}", op_idx),
        }
    }
    assert_eq!(op0_decorators.len(), 2);
    assert_eq!(op3_decorators.len(), 3);
}

#[test]
#[cfg(feature = "serde")]
fn test_mast_forest_serde_converts_linked_to_owned_decorators() {
    let mut forest = MastForest::new();

    // Create decorators
    let deco1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
    let deco2 = forest.add_decorator(Decorator::Trace(2)).unwrap();

    // Create operations with decorators
    let operations =
        vec![Operation::Push(Felt::new(1)), Operation::Add, Operation::Push(Felt::new(2))];
    let decorators = vec![(0, deco1), (2, deco2)];

    // Add block to forest - this will create Linked decorators
    let block_id = BasicBlockNodeBuilder::new(operations.clone(), decorators.clone())
        .add_to_forest(&mut forest)
        .unwrap();

    // Verify that the block was created
    let original_block = if let crate::mast::MastNode::Block(block) = &forest[block_id] {
        block
    } else {
        panic!("Expected a block node");
    };

    // Verify that the block is using linked storage correctly
    // In the new architecture, blocks don't hold Arc references but use forest-borrowing
    let original_decorators: Vec<_> = original_block.indexed_decorator_iter(&forest).collect();
    let expected_decorators = vec![(0, deco1), (2, deco2)];
    assert_eq!(
        original_decorators, expected_decorators,
        "Decorators should be correct before serialization"
    );

    // Verify that the block uses linked storage by checking that it needs forest access
    // (i.e., the decorators are stored in the forest, not directly in the block)
    // This is implicit in the fact that indexed_decorator_iter requires &forest

    // Serialize the MastForest using the custom Serializable implementation
    let serialized_bytes = forest.to_bytes();

    // Deserialize the MastForest using the custom Deserializable implementation
    let mut deserialized_forest: MastForest =
        MastForest::read_from_bytes(&serialized_bytes).expect("Failed to deserialize MastForest");

    // Get the deserialized block
    let deserialized_block =
        if let crate::mast::MastNode::Block(block) = &deserialized_forest[block_id] {
            block
        } else {
            panic!("Expected a block node in deserialized forest");
        };

    // Verify that the decorator data is still correct using the deserialized forest
    let deserialized_decorators: Vec<_> =
        deserialized_block.indexed_decorator_iter(&deserialized_forest).collect();
    assert_eq!(
        deserialized_decorators, expected_decorators,
        "Decorator data should be preserved during round-trip"
    );

    // Verify that the deserialized block also uses linked storage correctly
    // The fact that indexed_decorator_iter works with &deserialized_forest confirms this
    let deserialized_via_links = deserialized_block
        .indexed_decorator_iter(&deserialized_forest)
        .collect::<Vec<_>>();
    assert_eq!(
        deserialized_via_links, expected_decorators,
        "Deserialized block should use linked storage via forest borrowing"
    );

    // Additional verification: check that the functionality is identical
    assert_eq!(
        original_block.indexed_decorator_iter(&forest).collect::<Vec<_>>(),
        deserialized_block
            .indexed_decorator_iter(&deserialized_forest)
            .collect::<Vec<_>>(),
        "Decorators should be functionally equal between original and deserialized forests"
    );

    // Final verification: verify that we can add new decorators and they work correctly
    let new_decorator_id = deserialized_forest.add_decorator(Decorator::Trace(99)).unwrap();

    // Verify original decorators remain unchanged and new decorator works
    assert_eq!(deserialized_forest[new_decorator_id], Decorator::Trace(99));
}

#[test]
fn test_mast_forest_serializable_converts_linked_to_owned_decorators() {
    let mut forest = MastForest::new();

    // Create decorators
    let deco1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
    let deco2 = forest.add_decorator(Decorator::Trace(2)).unwrap();

    // Create operations with decorators
    let operations =
        vec![Operation::Push(Felt::new(1)), Operation::Add, Operation::Push(Felt::new(2))];
    let decorators = vec![(0, deco1), (2, deco2)];

    // Add block to forest - this will create Linked decorators
    let block_id = BasicBlockNodeBuilder::new(operations.clone(), decorators.clone())
        .add_to_forest(&mut forest)
        .unwrap();

    // Verify that the block was created
    let original_block = if let crate::mast::MastNode::Block(block) = &forest[block_id] {
        block
    } else {
        panic!("Expected a block node");
    };

    // Before serialization, verify that decorators work correctly through the forest-borrowing API
    // This confirms that the block is using linked storage correctly
    let decorator_count_before = original_block.indexed_decorator_iter(&forest).count();
    assert_eq!(
        decorator_count_before, 2,
        "Block should have 2 decorators accessible through forest borrowing"
    );

    // Verify decorators work correctly before serialization
    let original_decorators: Vec<_> = original_block.indexed_decorator_iter(&forest).collect();
    let expected_decorators = vec![(0, deco1), (2, deco2)];
    assert_eq!(
        original_decorators, expected_decorators,
        "Decorators should be correct before serialization"
    );

    // Serialize the MastForest using Serializable trait
    let serialized = forest.to_bytes();

    // Deserialize the MastForest using Deserializable trait
    let mut deserialized_forest: MastForest =
        MastForest::read_from_bytes(&serialized).expect("Failed to deserialize MastForest");

    // Verify that the decorator data is still correct by collecting data from the deserialized
    // block
    let deserialized_decorators: Vec<_> = {
        let block = if let crate::mast::MastNode::Block(block) = &deserialized_forest[block_id] {
            block
        } else {
            panic!("Expected a block node in deserialized forest");
        };
        block.indexed_decorator_iter(&deserialized_forest).collect()
    };
    assert_eq!(
        deserialized_decorators, expected_decorators,
        "Decorator data should be preserved during round-trip"
    );

    // Additional verification: check that the functionality is identical
    let original_decorators_final =
        original_block.indexed_decorator_iter(&forest).collect::<Vec<_>>();
    assert_eq!(
        original_decorators_final, deserialized_decorators,
        "Decorators should be functionally equal despite different storage representations"
    );

    // Final verification: check that the deserialized forest still works correctly
    // Add a new decorator
    let new_decorator_id = deserialized_forest.add_decorator(Decorator::Trace(99)).unwrap();

    // Verify that original decorators remain unchanged and new decorator works
    let original_after_new = original_block.indexed_decorator_iter(&forest).collect::<Vec<_>>();
    assert_eq!(
        original_after_new, expected_decorators,
        "Original decorators should remain unchanged after adding new decorator"
    );

    // Verify new decorator works
    assert_eq!(deserialized_forest[new_decorator_id], Decorator::Trace(99));
}

#[test]
fn test_forest_borrowing_decorator_access() {
    let mut forest = MastForest::new();

    // Create decorators
    let decorator1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
    let decorator2 = forest.add_decorator(Decorator::Trace(2)).unwrap();
    let decorator3 = forest.add_decorator(Decorator::Trace(3)).unwrap();

    // Create operations with decorators
    let operations =
        vec![Operation::Add, Operation::Mul, Operation::Eq, Operation::Assert(Felt::ZERO)];
    let decorators = vec![(0, decorator1), (1, decorator2), (3, decorator3)];

    // Build and add the basic block to forest
    let builder = BasicBlockNodeBuilder::new(operations, decorators);
    let node_id = builder.add_to_forest(&mut forest).unwrap();

    // Get the block from forest
    let block = &forest[node_id];
    if let crate::mast::MastNode::Block(block_node) = block {
        // Test that forest borrowing methods work correctly

        // Test 1: decorator_indices_for_op
        let op0_decorators = forest.decorator_indices_for_op(node_id, 0);
        assert_eq!(op0_decorators, &[decorator1]);

        let op1_decorators = forest.decorator_indices_for_op(node_id, 1);
        assert_eq!(op1_decorators, &[decorator2]);

        let op2_decorators = forest.decorator_indices_for_op(node_id, 2);
        assert_eq!(op2_decorators, &[]);

        let op3_decorators = forest.decorator_indices_for_op(node_id, 3);
        assert_eq!(op3_decorators, &[decorator3]);

        // Test 2: decorators_for_op (returns actual decorator references)
        let op0_decorator_refs: Vec<_> = forest.decorators_for_op(node_id, 0).collect();
        assert_eq!(op0_decorator_refs, &[&Decorator::Trace(1)]);

        let op1_decorator_refs: Vec<_> = forest.decorators_for_op(node_id, 1).collect();
        assert_eq!(op1_decorator_refs, &[&Decorator::Trace(2)]);

        // Test 3: decorator_links_for_node (flattened view)
        let decorator_links = forest.decorator_links_for_node(node_id).unwrap();
        let collected_links: Vec<_> = decorator_links.into_iter().collect();
        assert_eq!(collected_links, vec![(0, decorator1), (1, decorator2), (3, decorator3)]);

        // Test 4: decorator_links_for_node (Result handling)
        let decorator_ids: Vec<_> =
            forest.decorator_links_for_node(node_id).unwrap().into_iter().collect();
        assert_eq!(decorator_ids, vec![(0, decorator1), (1, decorator2), (3, decorator3)]);

        // Test 5: BasicBlockNode methods with forest borrowing
        let forest_borrowed_iter: Vec<_> = block_node.indexed_decorator_iter(&forest).collect();
        let expected_from_forest = vec![(0, decorator1), (1, decorator2), (3, decorator3)];
        assert_eq!(forest_borrowed_iter, expected_from_forest);

        // Test 6: Raw decorator iterator with forest borrowing
        let raw_forest_iter: Vec<_> = block_node.raw_decorator_iter(&forest).collect();
        // Should include before_enter, op-indexed, and after_exit in order
        assert_eq!(raw_forest_iter.len(), 3); // Only op-indexed decorators in this case

        // Test 7: Raw op indexed decorators with forest borrowing
        let raw_op_decorators = block_node.raw_op_indexed_decorators(&forest);
        assert_eq!(raw_op_decorators, vec![(0, decorator1), (1, decorator2), (3, decorator3)]);

        // Test 8: Count with forest borrowing
        let count_with_forest = block_node.num_operations_and_decorators(&forest);
        let expected_count = 4 + 3; // 4 operations + 3 decorators
        assert_eq!(count_with_forest, expected_count);
    } else {
        panic!("Expected a Block node");
    }

    // Verify decorator storage is properly populated (no Arc wrapping anymore)
    assert!(
        !forest.debug_info.op_decorator_storage().is_empty(),
        "Decorator storage should be populated"
    );
    assert_eq!(
        forest.debug_info.op_decorator_storage().num_nodes(),
        1,
        "Should have 1 node with decorators"
    );
}

// MAST FOREST COMPACTION TESTS
// ================================================================================================

/// Tests comprehensive mast forest compaction across all node types and decorator categories.
///
/// This test creates pairs of identical nodes for each of the 7 MAST node types, where each pair
/// differs only by decorators (operation-indexed, before-enter, or after-exit). After compaction,
/// each pair should be merged into a single node, demonstrating that the compaction correctly
/// identifies identical nodes regardless of decorator differences.
#[test]
fn test_mast_forest_compaction_comprehensive() {
    let mut forest = MastForest::new();

    // Create common decorators
    let trace_deco = forest.add_decorator(Decorator::Trace(42)).unwrap();
    let debug_deco = forest.add_decorator(Decorator::Debug(DebugOptions::StackTop(10))).unwrap();

    // === BasicBlock nodes with operation-indexed decorators ===
    let bb_no_deco = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let bb_with_op_deco =
        BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], vec![(0, trace_deco)])
            .add_to_forest(&mut forest)
            .unwrap();
    forest.make_root(bb_no_deco);
    forest.make_root(bb_with_op_deco);

    // === Join nodes with before-enter decorators ===
    let child1 = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::new(1))], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let child2 = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::new(2))], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let join_no_deco = crate::mast::JoinNodeBuilder::new([child1, child2])
        .add_to_forest(&mut forest)
        .unwrap();
    let join_with_before_deco = crate::mast::JoinNodeBuilder::new([child1, child2])
        .with_before_enter(vec![debug_deco])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(join_no_deco);
    forest.make_root(join_with_before_deco);

    // === Split nodes with after-exit decorators ===
    let split_child1 = BasicBlockNodeBuilder::new(vec![Operation::Eq], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let split_child2 =
        BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::new(1))], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
    let split_no_deco = crate::mast::SplitNodeBuilder::new([split_child1, split_child2])
        .add_to_forest(&mut forest)
        .unwrap();
    let split_with_after_deco = crate::mast::SplitNodeBuilder::new([split_child1, split_child2])
        .with_after_exit(vec![trace_deco])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(split_no_deco);
    forest.make_root(split_with_after_deco);

    // === Loop nodes with before-enter decorators ===
    let loop_body = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let loop_no_deco =
        crate::mast::LoopNodeBuilder::new(loop_body).add_to_forest(&mut forest).unwrap();
    let loop_with_before_deco = crate::mast::LoopNodeBuilder::new(loop_body)
        .with_before_enter(vec![debug_deco])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(loop_no_deco);
    forest.make_root(loop_with_before_deco);

    // === Call nodes with after-exit decorators ===
    let call_target = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let call_no_deco = crate::mast::CallNodeBuilder::new(call_target)
        .add_to_forest(&mut forest)
        .unwrap();
    let call_with_after_deco = crate::mast::CallNodeBuilder::new(call_target)
        .with_after_exit(vec![trace_deco])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(call_no_deco);
    forest.make_root(call_with_after_deco);

    // === Dyn nodes with before-enter decorators ===
    let dyn_no_deco = crate::mast::DynNodeBuilder::new_dyn().add_to_forest(&mut forest).unwrap();
    let dyn_with_before_deco = crate::mast::DynNodeBuilder::new_dyn()
        .with_before_enter(vec![debug_deco])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(dyn_no_deco);
    forest.make_root(dyn_with_before_deco);

    // === External nodes with after-exit decorators ===
    let external_digest = BasicBlockNodeBuilder::new(vec![Operation::Neg], Vec::new())
        .build()
        .unwrap()
        .digest();
    let external_no_deco = crate::mast::ExternalNodeBuilder::new(external_digest)
        .add_to_forest(&mut forest)
        .unwrap();
    let external_with_after_deco = crate::mast::ExternalNodeBuilder::new(external_digest)
        .with_after_exit(vec![trace_deco])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(external_no_deco);
    forest.make_root(external_with_after_deco);

    // Verify initial state: 14 root nodes (7 pairs) plus supporting nodes
    assert_eq!(forest.num_procedures(), 14);
    assert!(forest.num_nodes() > 14); // Supporting nodes (children) increase total count
    assert!(!forest.debug_info.is_empty());

    // Action: Strip decorators first, then compact
    forest.strip_decorators();
    let (forest, _root_map) = forest.compact();

    // Verify compaction results:
    // - 7 node pairs merged into 7 single nodes
    // - Supporting nodes preserved as they're reachable
    // - All decorators removed
    // - Roots preserved (at least 7, possibly more due to deduplication)
    assert_eq!(forest.num_nodes(), 13); // 7 main nodes + 6 supporting nodes (children)
    assert!(forest.num_procedures() >= 7);
    assert!(forest.debug_info.is_empty());
}

#[test]
fn test_mast_forest_get_assembly_op_basic_block() {
    let mut forest = MastForest::new();

    // Add a decorator with assembly op
    let assembly_op = AssemblyOp::new(None, "test_context".into(), 1, "add".into(), false);
    let decorator_id = forest.add_decorator(Decorator::AsmOp(assembly_op.clone())).unwrap();

    // Add a basic block node with decorators
    let operations = vec![Operation::Push(Felt::new(1)), Operation::Add];
    let decorators = vec![(0, decorator_id)]; // Decorator at operation index 0
    let node_id = BasicBlockNodeBuilder::new(operations, decorators)
        .add_to_forest(&mut forest)
        .unwrap();

    // Test getting first assembly op
    let result = forest.get_assembly_op(node_id, None);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), &assembly_op);
}

#[test]
fn test_mast_forest_get_assembly_op_with_target_index() {
    let mut forest = MastForest::new();

    // Test with target operation index - create assembly op with multiple cycles
    let assembly_op = AssemblyOp::new(
        None,
        "test_context".into(),
        3, // 3 cycles
        "complex_op".into(),
        false,
    );
    let decorator_id = forest.add_decorator(Decorator::AsmOp(assembly_op.clone())).unwrap();

    // Add a basic block node with the decorator at index 2
    let operations = vec![
        Operation::Push(Felt::new(1)),
        Operation::Push(Felt::new(2)),
        Operation::Mul,
        Operation::Add,
    ];
    let decorators = vec![(2, decorator_id)]; // Decorator at operation index 2
    let node_id = BasicBlockNodeBuilder::new(operations, decorators)
        .add_to_forest(&mut forest)
        .unwrap();

    // Test getting assembly op at different target indices
    // Should find it at index 2, 3, 4 (since assembly_op has 3 cycles starting at index 2)
    let result2 = forest.get_assembly_op(node_id, Some(2));
    assert!(result2.is_some());
    assert_eq!(result2.unwrap(), &assembly_op);

    let result3 = forest.get_assembly_op(node_id, Some(3));
    assert!(result3.is_some());
    assert_eq!(result3.unwrap(), &assembly_op);

    let result4 = forest.get_assembly_op(node_id, Some(4));
    assert!(result4.is_some());
    assert_eq!(result4.unwrap(), &assembly_op);

    // Should not find it at index 5 (beyond the 3 cycles)
    let result5 = forest.get_assembly_op(node_id, Some(5));
    assert!(result5.is_none());
}

#[test]
fn test_mast_forest_get_assembly_op_all_node_types() {
    let mut forest = MastForest::new();
    let assembly_op = AssemblyOp::new(None, "test_context".into(), 1, "test_op".into(), false);
    let decorator_id = forest.add_decorator(Decorator::AsmOp(assembly_op.clone())).unwrap();

    // Create some basic operations for building nodes
    let operations = vec![Operation::Push(Felt::new(1)), Operation::Add];

    // Test Call node
    let call_node = CallNodeBuilder::new(
        BasicBlockNodeBuilder::new(operations.clone(), vec![])
            .add_to_forest(&mut forest)
            .unwrap(),
    )
    .with_before_enter(vec![decorator_id])
    .add_to_forest(&mut forest)
    .unwrap();
    let call_result = forest.get_assembly_op(call_node, None);
    assert!(call_result.is_some());
    assert_eq!(call_result.unwrap(), &assembly_op);

    // Test Join node
    let child1 = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::new(1))], vec![])
        .add_to_forest(&mut forest)
        .unwrap();
    let child2 = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::new(2))], vec![])
        .add_to_forest(&mut forest)
        .unwrap();
    let join_node = JoinNodeBuilder::new([child1, child2])
        .with_after_exit(vec![decorator_id])
        .add_to_forest(&mut forest)
        .unwrap();
    let join_result = forest.get_assembly_op(join_node, None);
    assert!(join_result.is_some());
    assert_eq!(join_result.unwrap(), &assembly_op);

    // Test Split node
    let split_child1 = BasicBlockNodeBuilder::new(vec![Operation::Eq], vec![])
        .add_to_forest(&mut forest)
        .unwrap();
    let split_child2 = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::new(1))], vec![])
        .add_to_forest(&mut forest)
        .unwrap();
    let split_node = SplitNodeBuilder::new([split_child1, split_child2])
        .with_before_enter(vec![decorator_id])
        .add_to_forest(&mut forest)
        .unwrap();
    let split_result = forest.get_assembly_op(split_node, None);
    assert!(split_result.is_some());
    assert_eq!(split_result.unwrap(), &assembly_op);

    // Test Loop node
    let loop_body = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Add], vec![])
        .add_to_forest(&mut forest)
        .unwrap();
    let loop_node = LoopNodeBuilder::new(loop_body)
        .with_after_exit(vec![decorator_id])
        .add_to_forest(&mut forest)
        .unwrap();
    let loop_result = forest.get_assembly_op(loop_node, None);
    assert!(loop_result.is_some());
    assert_eq!(loop_result.unwrap(), &assembly_op);

    // Test Dyn node
    let dyn_node = DynNodeBuilder::new_dyn()
        .with_before_enter(vec![decorator_id])
        .add_to_forest(&mut forest)
        .unwrap();
    let dyn_result = forest.get_assembly_op(dyn_node, None);
    assert!(dyn_result.is_some());
    assert_eq!(dyn_result.unwrap(), &assembly_op);

    // Test External node
    let external_digest = BasicBlockNodeBuilder::new(vec![Operation::Neg], vec![])
        .build()
        .unwrap()
        .digest();
    let external_node = ExternalNodeBuilder::new(external_digest)
        .with_after_exit(vec![decorator_id])
        .add_to_forest(&mut forest)
        .unwrap();
    let external_result = forest.get_assembly_op(external_node, None);
    assert!(external_result.is_some());
    assert_eq!(external_result.unwrap(), &assembly_op);
}

#[test]
fn test_mast_forest_get_assembly_comprehensive_edge_cases() {
    let mut forest = MastForest::new();

    // Test 1: Node with no assembly decorators should return None
    let trace_deco = forest.add_decorator(Decorator::Trace(42)).unwrap();
    let debug_deco = forest.add_decorator(Decorator::Debug(DebugOptions::StackTop(10))).unwrap();

    let operations = vec![Operation::Push(Felt::new(1)), Operation::Add];
    let decorators = vec![(0, trace_deco), (1, debug_deco)];
    let node_id = BasicBlockNodeBuilder::new(operations, decorators)
        .add_to_forest(&mut forest)
        .unwrap();

    let result = forest.get_assembly_op(node_id, None);
    assert!(result.is_none(), "Node with no AssemblyOp decorators should return None");

    // Test 2: BasicBlock with before_enter AssemblyOp decorator
    let asm_op_before =
        AssemblyOp::new(None, "before_context".into(), 1, "before_op".into(), false);
    let asm_before_id = forest.add_decorator(Decorator::AsmOp(asm_op_before.clone())).unwrap();

    let bb_before = BasicBlockNodeBuilder::new(vec![Operation::Mul], vec![])
        .with_before_enter(vec![asm_before_id])
        .add_to_forest(&mut forest)
        .unwrap();

    let result_before = forest.get_assembly_op(bb_before, None);
    assert!(result_before.is_some());
    assert_eq!(result_before.unwrap(), &asm_op_before);

    // Test 3: BasicBlock with after_exit AssemblyOp decorator
    let asm_op_after = AssemblyOp::new(
        None,
        "after_context".into(),
        2, // 2 cycles
        "after_op".into(),
        false,
    );
    let asm_after_id = forest.add_decorator(Decorator::AsmOp(asm_op_after.clone())).unwrap();

    let bb_after = BasicBlockNodeBuilder::new(vec![Operation::Neg], vec![])
        .with_after_exit(vec![asm_after_id])
        .add_to_forest(&mut forest)
        .unwrap();

    let result_after = forest.get_assembly_op(bb_after, None);
    assert!(result_after.is_some());
    assert_eq!(result_after.unwrap(), &asm_op_after);

    // Test 4: BasicBlock with both before_enter and after_exit AssemblyOp decorators
    // Should return the first one found (before_enter in this case)
    let asm_op_first = AssemblyOp::new(None, "first_context".into(), 1, "first_op".into(), false);
    let asm_op_second =
        AssemblyOp::new(None, "second_context".into(), 1, "second_op".into(), false);
    let asm_first_id = forest.add_decorator(Decorator::AsmOp(asm_op_first.clone())).unwrap();
    let asm_second_id = forest.add_decorator(Decorator::AsmOp(asm_op_second.clone())).unwrap();

    let bb_both = BasicBlockNodeBuilder::new(vec![Operation::Eq], vec![])
        .with_before_enter(vec![asm_first_id])
        .with_after_exit(vec![asm_second_id])
        .add_to_forest(&mut forest)
        .unwrap();

    let result_both = forest.get_assembly_op(bb_both, None);
    assert!(result_both.is_some());
    assert_eq!(result_both.unwrap(), &asm_op_first, "Should return first AssemblyOp found");

    // Test 5: Multiple AssemblyOp decorators - should still return the first one
    let asm_op1 = AssemblyOp::new(None, "op1".into(), 1, "op1_name".into(), false);
    let asm_op2 = AssemblyOp::new(None, "op2".into(), 1, "op2_name".into(), false);
    let asm_op3 = AssemblyOp::new(None, "op3".into(), 1, "op3_name".into(), false);
    let asm1_id = forest.add_decorator(Decorator::AsmOp(asm_op1.clone())).unwrap();
    let asm2_id = forest.add_decorator(Decorator::AsmOp(asm_op2.clone())).unwrap();
    let asm3_id = forest.add_decorator(Decorator::AsmOp(asm_op3.clone())).unwrap();

    let bb_multiple = BasicBlockNodeBuilder::new(
        vec![Operation::Push(Felt::new(1)), Operation::Add, Operation::Mul],
        vec![(0, asm2_id), (2, asm3_id)],
    )
    .with_before_enter(vec![asm1_id])
    .with_after_exit(vec![asm3_id])
    .add_to_forest(&mut forest)
    .unwrap();

    let result_multiple = forest.get_assembly_op(bb_multiple, None);
    assert!(result_multiple.is_some());
    assert_eq!(result_multiple.unwrap(), &asm_op1, "Should return first AssemblyOp encountered");

    // Test 6: Verify that target index None works with before/after decorators
    let result_with_none = forest.get_assembly_op(bb_before, None);
    assert!(result_with_none.is_some());
    assert_eq!(result_with_none.unwrap(), &asm_op_before);

    // Test 7: Verify that target index with operation-indexed decorators still works alongside
    // before/after
    let operations_with_target = vec![Operation::Push(Felt::new(5)), Operation::Add];
    let op_indexed_asm =
        AssemblyOp::new(None, "op_indexed".into(), 1, "op_indexed_name".into(), false);
    let op_indexed_id = forest.add_decorator(Decorator::AsmOp(op_indexed_asm.clone())).unwrap();

    // Create a BasicBlock with only operation-indexed decorator (no before/after)
    let bb_op_only =
        BasicBlockNodeBuilder::new(operations_with_target.clone(), vec![(1, op_indexed_id)])
            .add_to_forest(&mut forest)
            .unwrap();

    // With no target, should still find the operation-indexed assembly op (since it's the only one)
    let result_op_only_none = forest.get_assembly_op(bb_op_only, None);
    assert!(result_op_only_none.is_some());
    assert_eq!(result_op_only_none.unwrap(), &op_indexed_asm);

    // With target index 1, should find the operation-indexed assembly op
    let result_op_only_target = forest.get_assembly_op(bb_op_only, Some(1));
    assert!(result_op_only_target.is_some());
    assert_eq!(result_op_only_target.unwrap(), &op_indexed_asm);

    // With target index 0, should find none (no operation-indexed decorator at index 0)
    let result_op_only_no_target = forest.get_assembly_op(bb_op_only, Some(0));
    assert!(result_op_only_no_target.is_none());

    // Test 8: Mixed decorators - BasicBlock with both before and operation-indexed
    let bb_mixed =
        BasicBlockNodeBuilder::new(operations_with_target.clone(), vec![(1, op_indexed_id)])
            .with_before_enter(vec![asm_before_id])
            .add_to_forest(&mut forest)
            .unwrap();

    // With no target, should find the first assembly op (before_enter since it's checked first)
    let result_mixed_none = forest.get_assembly_op(bb_mixed, None);
    assert!(result_mixed_none.is_some());
    assert_eq!(result_mixed_none.unwrap(), &asm_op_before);

    // With target index 1, should find the operation-indexed assembly op
    let result_mixed_target = forest.get_assembly_op(bb_mixed, Some(1));
    assert!(result_mixed_target.is_some());
    assert_eq!(result_mixed_target.unwrap(), &op_indexed_asm);
}

#[test]
fn test_decorator_stripping_independent() {
    let mut forest = MastForest::new();

    // Add some nodes with decorators
    let decorator = forest.add_decorator(Decorator::Trace(42)).unwrap();
    let node_with_deco = BasicBlockNodeBuilder::new(vec![Operation::Add], vec![(0, decorator)])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(node_with_deco);

    // Verify initial state has decorators
    assert!(!forest.debug_info.is_empty());
    assert_eq!(forest.decorators().len(), 1);

    // Strip decorators only
    forest.strip_decorators();

    // Verify decorators are removed but structure remains
    assert!(forest.debug_info.is_empty());
    assert_eq!(forest.num_nodes(), 1);
    assert_eq!(forest.num_procedures(), 1);
}

#[test]
fn test_compaction_independent() {
    let mut forest = MastForest::new();

    // Create two identical nodes without decorators
    let node1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let node2 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(node1);
    forest.make_root(node2);

    // Verify initial state has duplicate nodes
    assert_eq!(forest.num_nodes(), 2);
    assert_eq!(forest.num_procedures(), 2);
    assert!(forest.debug_info.is_empty()); // No decorators from start

    // Compact only (should merge the two identical nodes)
    let (forest, _root_map) = forest.compact();

    // Verify nodes were merged
    assert_eq!(forest.num_nodes(), 1);
    assert_eq!(forest.num_procedures(), 1);
    assert!(forest.debug_info.is_empty());
}

#[test]
fn test_commitment_caching() {
    use crate::Operation;

    let mut forest = MastForest::new();

    // Create some nodes
    let node1 = BasicBlockNodeBuilder::new(vec![Operation::Add], vec![])
        .add_to_forest(&mut forest)
        .unwrap();
    let node2 = BasicBlockNodeBuilder::new(vec![Operation::Mul], vec![])
        .add_to_forest(&mut forest)
        .unwrap();

    forest.make_root(node1);

    // First access: commitment is computed and cached
    let commitment1 = forest.commitment();
    assert_ne!(commitment1, Word::from([Felt::ZERO; 4]));

    // Second access: same commitment should be returned (from cache)
    let commitment2 = forest.commitment();
    assert_eq!(commitment1, commitment2);

    // Mutate the forest by adding a new root
    forest.make_root(node2);

    // After mutation, commitment should be different (cache was invalidated and recomputed)
    let commitment3 = forest.commitment();
    assert_ne!(commitment1, commitment3);

    // Accessing again should return the same cached value
    let commitment4 = forest.commitment();
    assert_eq!(commitment3, commitment4);

    // Test that advice_map mutations don't invalidate the cache
    forest.advice_map_mut().insert(Word::from([Felt::ZERO; 4]), vec![]);
    let commitment5 = forest.commitment();
    assert_eq!(
        commitment3, commitment5,
        "advice_map mutation should not invalidate commitment cache"
    );

    // Test that strip_decorators doesn't invalidate the cache
    forest.strip_decorators();
    let commitment6 = forest.commitment();
    assert_eq!(
        commitment3, commitment6,
        "strip_decorators should not invalidate commitment cache"
    );

    // Test that remove_nodes invalidates the cache
    let nodes_to_remove = alloc::collections::BTreeSet::new();
    forest.remove_nodes(&nodes_to_remove); // Empty set, but still calls the method
    let commitment7 = forest.commitment();
    // Since we didn't actually remove anything, commitment should still be the same
    assert_eq!(commitment3, commitment7);
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn digest_from_seed(seed: [u8; 32]) -> Word {
    let mut digest = [Felt::ZERO; WORD_SIZE];
    digest.iter_mut().enumerate().for_each(|(i, d)| {
        *d = <[u8; 8]>::try_from(&seed[i * 8..(i + 1) * 8])
            .map(u64::from_le_bytes)
            .map(Felt::new)
            .unwrap()
    });
    digest.into()
}
