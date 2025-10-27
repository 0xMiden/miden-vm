use alloc::vec::Vec;

use miden_crypto::WORD_SIZE;
use proptest::prelude::*;
use winter_math::FieldElement;
use winter_rand_utils::prng_array;

use crate::{
    DebugOptions, Decorator, Felt, Kernel, Operation, ProgramInfo, Word,
    chiplets::hasher,
    mast::{
        BasicBlockNodeBuilder, DynNode, DynNodeBuilder, MastForest, MastForestContributor,
        MastNodeExt,
    },
    utils::{Deserializable, Serializable},
};

#[test]
fn dyn_hash_is_correct() {
    let expected_constant =
        hasher::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYN_DOMAIN);
    assert_eq!(expected_constant, DynNodeBuilder::new_dyn().build().digest());
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
        .decorator_storage
        .decorator_ids_for_node(block_id)
        .unwrap()
        .flat_map(|(op_idx, decorators)| decorators.iter().map(move |dec_id| (op_idx, *dec_id)))
        .collect();

    let block_decorators: Vec<_> = block.indexed_decorator_iter().collect();

    assert_eq!(
        forest_decorators, block_decorators,
        "Decorators from forest storage should match block iterator"
    );

    // Test 2: Verify specific operation decorators match
    for (op_idx, expected_decorator_id) in &decorators {
        let forest_decos =
            forest.decorator_storage.decorator_ids_for_operation(block_id, *op_idx).unwrap();
        let block_decos: Vec<_> = block
            .indexed_decorator_iter()
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
        let forest_decos =
            forest.decorator_storage.decorator_ids_for_operation(block_id, op_idx).unwrap();
        let block_decos: Vec<_> = block
            .indexed_decorator_iter()
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
    let forest_decorators: Vec<_> =
        forest.decorator_storage.decorator_ids_for_node(block_id).unwrap().collect();

    let block_decorators: Vec<_> = block.indexed_decorator_iter().collect();

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
        .decorator_storage
        .decorator_ids_for_node(block_id1)
        .unwrap()
        .flat_map(|(op_idx, decorators)| decorators.iter().map(move |dec_id| (op_idx, *dec_id)))
        .collect();

    let block1 = if let crate::mast::MastNode::Block(block) = &forest[block_id1] {
        block
    } else {
        panic!("Expected a block node");
    };
    let block_decorators1: Vec<_> = block1.indexed_decorator_iter().collect();

    assert_eq!(forest_decorators1, block_decorators1);

    // Verify second block consistency
    let forest_decorators2: Vec<_> = forest
        .decorator_storage
        .decorator_ids_for_node(block_id2)
        .unwrap()
        .flat_map(|(op_idx, decorators)| decorators.iter().map(move |dec_id| (op_idx, *dec_id)))
        .collect();

    let block2 = if let crate::mast::MastNode::Block(block) = &forest[block_id2] {
        block
    } else {
        panic!("Expected a block node");
    };
    let block_decorators2: Vec<_> = block2.indexed_decorator_iter().collect();

    assert_eq!(forest_decorators2, block_decorators2);

    // Verify the decorator storage has the correct number of nodes
    assert_eq!(forest.decorator_storage.num_nodes(), 2);
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
    assert!(!forest.decorator_storage.is_empty());
    assert_eq!(forest.decorator_storage.num_nodes(), 1);
    assert_eq!(forest.decorator_storage.num_decorator_ids(), 2);

    // Strip decorators
    forest.strip_decorators();

    // Verify decorators are cleared from storage
    assert!(forest.decorator_storage.is_empty());
    assert_eq!(forest.decorator_storage.num_nodes(), 0);
    assert_eq!(forest.decorator_storage.num_decorator_ids(), 0);

    // Verify block also has no decorators after stripping
    let block = if let crate::mast::MastNode::Block(block) = &forest[block_id] {
        block
    } else {
        panic!("Expected a block node");
    };
    let block_decorators: Vec<_> = block.indexed_decorator_iter().collect();
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
    assert_eq!(original_forest.decorator_storage.num_nodes(), 3);
    // Note: DecoratorIndexMapping may deduplicate identical decorators across blocks
    let original_decorator_count = original_forest.decorator_storage.num_decorator_ids();

    // Serialize the forest to bytes
    let original_bytes = original_forest.to_bytes();

    // Deserialize back to a new forest
    let deserialized_forest = MastForest::read_from_bytes(&original_bytes).unwrap();

    // Verify basic forest structure
    assert_eq!(deserialized_forest.num_nodes(), 3);
    assert_eq!(deserialized_forest.decorator_storage.num_nodes(), 3);
    assert_eq!(
        deserialized_forest.decorator_storage.num_decorator_ids(),
        original_decorator_count
    );

    // Verify that the reconstructed forest includes the decorators
    // This ensures the DecoratorIndexMapping structure in the deserialized forest is not empty
    assert!(
        !deserialized_forest.decorator_storage.is_empty(),
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
        let original_decorators: Vec<_> = original_block.indexed_decorator_iter().collect();
        let deserialized_decorators: Vec<_> = deserialized_block.indexed_decorator_iter().collect();
        assert_eq!(original_decorators, deserialized_decorators);

        // Verify before/after decorators
        assert_eq!(original_block.before_enter(), deserialized_block.before_enter());
        assert_eq!(original_block.after_exit(), deserialized_block.after_exit());
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
    assert_eq!(deserialized_block1.before_enter(), &[trace_deco_2]);
    assert_eq!(deserialized_block1.after_exit(), &[trace_deco_3]);

    // Block 2: Should have multiple decorators at operation indices 0 and 3
    let block2_decorators: Vec<_> = deserialized_block2.indexed_decorator_iter().collect();
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
    use alloc::sync::Arc;

    use serde_json;

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

    // Before serialization, check that the forest's decorator_storage is being used
    // The Arc should have a strong count > 1 because:
    // 1. The forest holds one reference
    // 2. The BasicBlockNode holds another reference via DecoratorStore::Linked
    let arc_count_before = Arc::strong_count(&forest.decorator_storage);
    assert!(
        arc_count_before > 1,
        "Decorator storage should be shared between forest and block before serialization"
    );

    // Verify decorators work correctly before serialization
    let original_decorators: Vec<_> = original_block.indexed_decorator_iter().collect();
    let expected_decorators = vec![(0, deco1), (2, deco2)];
    assert_eq!(
        original_decorators, expected_decorators,
        "Decorators should be correct before serialization"
    );

    // Serialize the MastForest
    let serialized = serde_json::to_string(&forest).expect("Failed to serialize MastForest");

    // Deserialize the MastForest
    let mut deserialized_forest: MastForest =
        serde_json::from_str(&serialized).expect("Failed to deserialize MastForest");

    // Get the deserialized block
    let deserialized_block =
        if let crate::mast::MastNode::Block(block) = &deserialized_forest[block_id] {
            block
        } else {
            panic!("Expected a block node in deserialized forest");
        };

    // After deserialization, the Arc count should now be 2 because:
    // The custom Deserialize implementation converts Owned back to Linked decorators
    // 1. Forest holds one reference
    // 2. BasicBlockNode holds another reference via DecoratorStore::Linked
    let arc_count_after = Arc::strong_count(&deserialized_forest.decorator_storage);
    assert_eq!(
        arc_count_after, 2,
        "Decorator storage should be shared between forest and block after custom serde deserialization (Linked representation restored)"
    );

    // Verify that the decorator data is still correct
    let deserialized_decorators: Vec<_> = deserialized_block.indexed_decorator_iter().collect();
    assert_eq!(
        deserialized_decorators, expected_decorators,
        "Decorator data should be preserved during round-trip"
    );

    // Additional verification: check that the functionality is identical
    assert_eq!(
        original_block.indexed_decorator_iter().collect::<Vec<_>>(),
        deserialized_block.indexed_decorator_iter().collect::<Vec<_>>(),
        "Decorators should be functionally equal despite storage representation changes"
    );

    // Final verification: check that the deserialized forest still has nodes referencing the shared
    // storage
    let new_decorator_id = deserialized_forest.add_decorator(Decorator::Trace(99)).unwrap();
    let arc_count_after_new_decorator = Arc::strong_count(&deserialized_forest.decorator_storage);
    assert_eq!(
        arc_count_after_new_decorator, 2,
        "Adding new decorator should not change Arc count if blocks use Linked storage"
    );

    // Verify new decorator works
    assert_eq!(deserialized_forest[new_decorator_id], Decorator::Trace(99));
}

#[test]
fn test_mast_forest_serializable_converts_linked_to_owned_decorators() {
    use alloc::sync::Arc;

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

    // Before serialization, check that the forest's decorator_storage is being used
    // The Arc should have a strong count > 1 because both forest and block reference it
    let arc_count_before = Arc::strong_count(&forest.decorator_storage);
    assert!(
        arc_count_before > 1,
        "Decorator storage should be shared between forest and block before serialization"
    );

    // Verify decorators work correctly before serialization
    let original_decorators: Vec<_> = original_block.indexed_decorator_iter().collect();
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

    // Get the deserialized block
    let deserialized_block =
        if let crate::mast::MastNode::Block(block) = &deserialized_forest[block_id] {
            block
        } else {
            panic!("Expected a block node in deserialized forest");
        };

    // After deserialization, the Arc count should be 2 because:
    // The Serializable/Deserializable round-trip preserves the Linked representation!
    // 1. Forest holds one reference
    // 2. BasicBlockNode holds another reference via DecoratorStore::Linked
    let arc_count_after = Arc::strong_count(&deserialized_forest.decorator_storage);
    assert_eq!(
        arc_count_after, 2,
        "Decorator storage should be shared between forest and block after Serializable round-trip (Linked representation preserved)"
    );

    // Verify that the decorator data is still correct
    let deserialized_decorators: Vec<_> = deserialized_block.indexed_decorator_iter().collect();
    assert_eq!(
        deserialized_decorators, expected_decorators,
        "Decorator data should be preserved during round-trip"
    );

    // Additional verification: check that the functionality is identical
    assert_eq!(
        original_block.indexed_decorator_iter().collect::<Vec<_>>(),
        deserialized_block.indexed_decorator_iter().collect::<Vec<_>>(),
        "Decorators should be functionally equal despite different storage representations"
    );

    // Final verification: check that the deserialized forest still has nodes referencing the shared
    // storage
    let new_decorator_id = deserialized_forest.add_decorator(Decorator::Trace(99)).unwrap();
    let arc_count_after_new_decorator = Arc::strong_count(&deserialized_forest.decorator_storage);
    assert_eq!(
        arc_count_after_new_decorator, 2,
        "Adding new decorator should not change Arc count if blocks use Linked storage"
    );

    // Verify new decorator works
    assert_eq!(deserialized_forest[new_decorator_id], Decorator::Trace(99));
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
