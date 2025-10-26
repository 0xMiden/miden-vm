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
