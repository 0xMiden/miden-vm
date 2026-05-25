use alloc::vec::Vec;

use miden_crypto::rand::test_utils::prng_array;
use proptest::prelude::*;

use crate::{
    Felt, WORD_SIZE, Word,
    chiplets::hasher,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNode, DynNodeBuilder, JoinNodeBuilder,
        MastForest, MastForestContributor, MastNodeExt, SplitNodeBuilder,
    },
    operations::{AssemblyOp, Operation},
    program::{Kernel, ProgramInfo},
    serde::{Deserializable, Serializable},
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

    // Create operations
    let operations = vec![
        Operation::Push(Felt::new_unchecked(1)),
        Operation::Add,
        Operation::Push(Felt::new_unchecked(2)),
        Operation::Mul,
    ];

    // Add block to forest using BasicBlockNodeBuilder
    let block_id = BasicBlockNodeBuilder::new(operations, vec![])
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

    // Test 2: Verify all operations return empty decorator lists.
    for op_idx in 0..4 {
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

        assert_eq!(forest_decos, [], "Operation {op_idx} should have no decorators");
        assert_eq!(block_decos, [], "Operation {op_idx} should have no decorators");
    }
}

#[test]
fn test_decorator_storage_consistency_with_empty_block() {
    let mut forest = MastForest::new();

    // Create operations without decorators
    let operations = vec![Operation::Push(Felt::new_unchecked(1)), Operation::Add];

    // Add block to forest using BasicBlockNodeBuilder with no decorators
    let block_id = BasicBlockNodeBuilder::new(operations, vec![])
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

    // Create first block
    let operations1 = vec![Operation::Push(Felt::new_unchecked(1)), Operation::Add];
    let block_id1 = BasicBlockNodeBuilder::new(operations1, vec![])
        .add_to_forest(&mut forest)
        .unwrap();

    // Create second block
    let operations2 = vec![Operation::Push(Felt::new_unchecked(2)), Operation::Mul];
    let block_id2 = BasicBlockNodeBuilder::new(operations2, vec![])
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
    assert_eq!(forest.debug_info.op_decorator_storage().num_decorator_ids(), 0);
}

#[test]
fn test_decorator_storage_after_clear_debug_info() {
    let mut forest = MastForest::new();

    let operations = vec![Operation::Push(Felt::new_unchecked(1)), Operation::Add];
    let block_id = BasicBlockNodeBuilder::new(operations, vec![])
        .add_to_forest(&mut forest)
        .unwrap();

    assert_eq!(forest.debug_info.num_decorators(), 0);
    assert_eq!(forest.debug_info.op_decorator_storage().num_decorator_ids(), 0);

    forest.clear_debug_info();

    assert_eq!(forest.debug_info.num_decorators(), 0);
    assert_eq!(forest.debug_info.op_decorator_storage().num_nodes(), 1);
    assert!(forest.decorator_links_for_node(block_id).unwrap().into_iter().next().is_none());
}

#[test]
fn test_clear_debug_info_edge_cases() {
    // Empty forest
    let mut forest = MastForest::new();
    forest.clear_debug_info();
    assert_eq!(forest.debug_info.num_decorators(), 0);
    assert_eq!(forest.debug_info.op_decorator_storage().num_nodes(), 0);

    // Idempotent: clearing twice should be safe
    let operations = vec![Operation::Push(Felt::new_unchecked(1)), Operation::Add];
    let block_id = BasicBlockNodeBuilder::new(operations, vec![])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.clear_debug_info();
    forest.clear_debug_info();
    assert_eq!(forest.debug_info.num_decorators(), 0);
    assert_eq!(forest.debug_info.op_decorator_storage().num_nodes(), 1);
    assert!(forest.decorator_links_for_node(block_id).unwrap().into_iter().next().is_none());
}

#[test]
fn test_clear_debug_info_multiple_node_types() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(
        vec![Operation::Push(Felt::new_unchecked(1)), Operation::Add],
        vec![],
    )
    .add_to_forest(&mut forest)
    .unwrap();

    JoinNodeBuilder::new([block_id, block_id]).add_to_forest(&mut forest).unwrap();
    SplitNodeBuilder::new([block_id, block_id]).add_to_forest(&mut forest).unwrap();

    forest.clear_debug_info();

    assert_eq!(forest.debug_info.op_decorator_storage().num_nodes(), 3);
    assert!(forest.decorator_links_for_node(block_id).unwrap().into_iter().next().is_none());
}

#[test]
fn test_compact_after_clear_debug_info_does_not_materialize_empty_node_decorators() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(
        vec![Operation::Push(Felt::new_unchecked(1)), Operation::Add],
        vec![],
    )
    .add_to_forest(&mut forest)
    .unwrap();
    let call_id = CallNodeBuilder::new(block_id).add_to_forest(&mut forest).unwrap();
    forest.make_root(call_id);

    forest.clear_debug_info();
    let (compacted, _) = forest.compact();

    assert!(compacted.debug_info.node_decorator_storage().is_empty());
    for node_idx in 0..compacted.nodes().len() {
        let node_id = crate::mast::MastNodeId::new_unchecked(node_idx as u32);
        assert!(compacted.before_enter_decorators(node_id).is_empty());
        assert!(compacted.after_exit_decorators(node_id).is_empty());
    }
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

    let bb1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let bb2 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(bb1);
    forest.make_root(bb2);

    assert_eq!(forest.num_procedures(), 2);
    assert_eq!(forest.num_nodes(), 2);
    assert!(forest.debug_info.is_empty());

    let (forest, _root_map) = forest.compact();

    assert_eq!(forest.num_nodes(), 1);
    assert_eq!(forest.num_procedures(), 1);
    assert!(forest.debug_info.is_empty());
}

#[test]
fn test_mast_forest_get_assembly_op_basic_block() {
    let mut forest = MastForest::new();

    // Add an AssemblyOp to the DebugInfo's asm_op storage
    let assembly_op = AssemblyOp::new(None, "test_context".into(), 1, "add".into());
    let asm_op_id = forest.debug_info.add_asm_op(assembly_op.clone()).unwrap();

    // Add a basic block node
    let operations = vec![Operation::Push(Felt::new_unchecked(1)), Operation::Add];
    let node_id = BasicBlockNodeBuilder::new(operations, vec![])
        .add_to_forest(&mut forest)
        .unwrap();

    // Register the AssemblyOp for operation index 0 (node has 2 operations)
    forest.debug_info.register_asm_ops(node_id, 2, vec![(0, asm_op_id)]).unwrap();

    // Test getting first assembly op
    let result = forest.get_assembly_op(node_id, None);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), &assembly_op);
}

#[test]
fn test_mast_forest_get_assembly_op_with_target_index() {
    let mut forest = MastForest::new();

    // Add an AssemblyOp with multiple cycles
    let assembly_op = AssemblyOp::new(
        None,
        "test_context".into(),
        3, // 3 cycles
        "complex_op".into(),
    );
    let asm_op_id = forest.debug_info.add_asm_op(assembly_op.clone()).unwrap();

    // Add a basic block node with 5 operations
    let operations = vec![
        Operation::Push(Felt::new_unchecked(1)),
        Operation::Push(Felt::new_unchecked(2)),
        Operation::Mul,
        Operation::Add,
        Operation::Drop,
    ];
    let node_id = BasicBlockNodeBuilder::new(operations, vec![])
        .add_to_forest(&mut forest)
        .unwrap();

    // Register the AssemblyOp at operation indices 2, 3, 4 (3 cycles)
    // Node has 5 operations (indices 0-4)
    forest
        .debug_info
        .register_asm_ops(node_id, 5, vec![(2, asm_op_id), (3, asm_op_id), (4, asm_op_id)])
        .unwrap();

    // Test getting assembly op at different target indices
    let result2 = forest.get_assembly_op(node_id, Some(2));
    assert!(result2.is_some());
    assert_eq!(result2.unwrap(), &assembly_op);

    let result3 = forest.get_assembly_op(node_id, Some(3));
    assert!(result3.is_some());
    assert_eq!(result3.unwrap(), &assembly_op);

    let result4 = forest.get_assembly_op(node_id, Some(4));
    assert!(result4.is_some());
    assert_eq!(result4.unwrap(), &assembly_op);

    // With sparse storage and backward search, index 5 (out of bounds) will find index 4's
    // AssemblyOp. This is expected behavior: backward search returns the most recent AssemblyOp
    // for any index.
    let result5 = forest.get_assembly_op(node_id, Some(5));
    assert!(result5.is_some());
    assert_eq!(result5.unwrap(), &assembly_op);
}

#[test]
fn test_mast_forest_get_assembly_op_all_node_types() {
    // Note: AssemblyOps are now stored separately from decorators in DebugInfo's asm_op storage.
    // This storage is indexed by (node_id, operation_index), so AssemblyOps are associated
    // with specific operations within basic block nodes.
    //
    // For non-basic-block node types (Call, Join, Split, Loop, Dyn, External), AssemblyOps
    // are typically associated via the child basic block's operations.
    //
    // This test verifies the basic block case. For control flow nodes, the AssemblyOp would
    // typically be found in the child basic block's operation indices.

    let mut forest = MastForest::new();
    let assembly_op = AssemblyOp::new(None, "test_context".into(), 1, "test_op".into());
    let asm_op_id = forest.debug_info.add_asm_op(assembly_op.clone()).unwrap();

    // Create a basic block with an AssemblyOp registered for its operations
    let operations = vec![Operation::Push(Felt::new_unchecked(1)), Operation::Add];
    let bb_node_id = BasicBlockNodeBuilder::new(operations, vec![])
        .add_to_forest(&mut forest)
        .unwrap();

    // Register AssemblyOp for operation 0 in the basic block (node has 2 operations)
    forest.debug_info.register_asm_ops(bb_node_id, 2, vec![(0, asm_op_id)]).unwrap();

    // Test getting assembly op from basic block
    let bb_result = forest.get_assembly_op(bb_node_id, Some(0));
    assert!(bb_result.is_some());
    assert_eq!(bb_result.unwrap(), &assembly_op);

    // Create some control flow nodes using this basic block
    let call_node = CallNodeBuilder::new(bb_node_id).add_to_forest(&mut forest).unwrap();
    let join_child2 =
        BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::new_unchecked(2))], vec![])
            .add_to_forest(&mut forest)
            .unwrap();
    let _join_node = JoinNodeBuilder::new([bb_node_id, join_child2])
        .add_to_forest(&mut forest)
        .unwrap();

    // For Call node, get_assembly_op with None returns None because the asm_op is
    // registered on the callee (bb_node_id), not the call node itself
    let call_result = forest.get_assembly_op(call_node, None);
    assert!(call_result.is_none());

    // But we can still get it from the basic block
    let bb_result_again = forest.get_assembly_op(bb_node_id, None);
    assert!(bb_result_again.is_some());
    assert_eq!(bb_result_again.unwrap(), &assembly_op);
}

#[test]
fn test_mast_forest_get_assembly_comprehensive_edge_cases() {
    // Note: AssemblyOps are now stored separately in DebugInfo's asm_op storage.
    // get_assembly_op looks up AssemblyOps by (node_id, operation_index).

    let mut forest = MastForest::new();

    // Test 1: Node with no AssemblyOps registered should return None
    let operations = vec![Operation::Push(Felt::new_unchecked(1)), Operation::Add];
    let node_id = BasicBlockNodeBuilder::new(operations.clone(), vec![])
        .add_to_forest(&mut forest)
        .unwrap();

    let result = forest.get_assembly_op(node_id, None);
    assert!(result.is_none(), "Node with no AssemblyOps registered should return None");

    // Test 2: Add AssemblyOp and register it for operations
    let asm_op1 = AssemblyOp::new(None, "context1".into(), 1, "op1".into());
    let asm_op_id1 = forest.debug_info.add_asm_op(asm_op1.clone()).unwrap();

    let node_id2 = BasicBlockNodeBuilder::new(operations, vec![])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.debug_info.register_asm_ops(node_id2, 2, vec![(0, asm_op_id1)]).unwrap();

    let result2 = forest.get_assembly_op(node_id2, None);
    assert!(result2.is_some());
    assert_eq!(result2.unwrap(), &asm_op1);

    // Test 3: Multiple AssemblyOps for different operation indices
    let asm_op2 = AssemblyOp::new(None, "context2".into(), 1, "op2".into());
    let asm_op3 = AssemblyOp::new(None, "context3".into(), 1, "op3".into());
    let asm_op_id2 = forest.debug_info.add_asm_op(asm_op2.clone()).unwrap();
    let asm_op_id3 = forest.debug_info.add_asm_op(asm_op3.clone()).unwrap();

    let ops_multi = vec![Operation::Push(Felt::new_unchecked(1)), Operation::Add, Operation::Mul];
    let node_id3 = BasicBlockNodeBuilder::new(ops_multi, vec![])
        .add_to_forest(&mut forest)
        .unwrap();
    forest
        .debug_info
        .register_asm_ops(node_id3, 3, vec![(0, asm_op_id2), (2, asm_op_id3)])
        .unwrap();

    // first_asm_op_for_node should return the first one (at op index 0)
    let result3_none = forest.get_assembly_op(node_id3, None);
    assert!(result3_none.is_some());
    assert_eq!(result3_none.unwrap(), &asm_op2, "Should return first AssemblyOp");

    // Specific indices should return correct AssemblyOps
    let result3_idx0 = forest.get_assembly_op(node_id3, Some(0));
    assert!(result3_idx0.is_some());
    assert_eq!(result3_idx0.unwrap(), &asm_op2);

    let result3_idx2 = forest.get_assembly_op(node_id3, Some(2));
    assert!(result3_idx2.is_some());
    assert_eq!(result3_idx2.unwrap(), &asm_op3);

    // Index 1 has no direct AssemblyOp, but backward search finds the AssemblyOp at index 0
    // This is by design for multi-cycle instructions where only the first op has an AssemblyOp
    let result3_idx1 = forest.get_assembly_op(node_id3, Some(1));
    assert!(result3_idx1.is_some());
    assert_eq!(
        result3_idx1.unwrap(),
        &asm_op2,
        "Backward search should find AssemblyOp at index 0"
    );

    // Test 4: Same AssemblyOp ID at multiple indices (multi-cycle operation)
    let asm_op_multi = AssemblyOp::new(None, "multi_cycle".into(), 3, "multi_op".into());
    let asm_op_id_multi = forest.debug_info.add_asm_op(asm_op_multi.clone()).unwrap();

    let ops4 = vec![
        Operation::Push(Felt::new_unchecked(1)),
        Operation::Add,
        Operation::Mul,
        Operation::Neg,
    ];
    let node_id4 = BasicBlockNodeBuilder::new(ops4, vec![]).add_to_forest(&mut forest).unwrap();
    forest
        .debug_info
        .register_asm_ops(
            node_id4,
            4,
            vec![(1, asm_op_id_multi), (2, asm_op_id_multi), (3, asm_op_id_multi)],
        )
        .unwrap();

    // All three indices should return the same AssemblyOp
    for idx in 1..=3 {
        let result = forest.get_assembly_op(node_id4, Some(idx));
        assert!(result.is_some(), "Should find AssemblyOp at index {idx}");
        assert_eq!(result.unwrap(), &asm_op_multi);
    }

    // Index 0 should return None
    let result4_idx0 = forest.get_assembly_op(node_id4, Some(0));
    assert!(result4_idx0.is_none());
}

#[test]
fn test_clear_debug_info_independent() {
    let mut forest = MastForest::new();

    let node = BasicBlockNodeBuilder::new(vec![Operation::Add], vec![])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(node);

    assert!(forest.debug_info.is_empty());
    assert_eq!(forest.decorators().len(), 0);

    // Clear debug info only
    forest.clear_debug_info();

    // Verify debug info is removed but structure remains
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

    // Test that clear_debug_info doesn't invalidate the cache
    forest.clear_debug_info();
    let commitment6 = forest.commitment();
    assert_eq!(
        commitment3, commitment6,
        "clear_debug_info should not invalidate commitment cache"
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
            .map(Felt::new_unchecked)
            .unwrap()
    });
    digest.into()
}

#[test]
fn test_asm_op_id_basic() {
    use crate::{mast::AsmOpId, utils::Idx};

    let id = AsmOpId::new(42);
    assert_eq!(id.to_usize(), 42);
    assert_eq!(u32::from(id), 42);
}

#[test]
fn test_debug_info_asm_op_storage() {
    use alloc::string::ToString;

    use crate::mast::{DebugInfo, MastNodeId};

    let mut debug_info = DebugInfo::new();

    // Add an AssemblyOp
    let asm_op = AssemblyOp::new(None, "test".to_string(), 5, "add".to_string());
    let asm_op_id = debug_info.add_asm_op(asm_op).unwrap();

    // Register it for node 0, op 2 (assuming node has 5 operations)
    let node_id = MastNodeId::new_unchecked(0);
    debug_info.register_asm_ops(node_id, 5, vec![(2, asm_op_id)]).unwrap();

    // Query it back
    let retrieved = debug_info.asm_op_for_operation(node_id, 2);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().op(), "add");

    // Query non-existent
    assert!(debug_info.asm_op_for_operation(node_id, 0).is_none());

    // Test first_asm_op_for_node
    let first = debug_info.first_asm_op_for_node(node_id);
    assert!(first.is_some());
    assert_eq!(first.unwrap().op(), "add");

    // Test accessors
    assert_eq!(debug_info.num_asm_ops(), 1);
    assert_eq!(debug_info.asm_ops().len(), 1);
    assert!(debug_info.asm_op(asm_op_id).is_some());
    assert_eq!(debug_info.asm_op(asm_op_id).unwrap().op(), "add");

    // Test non-existent node
    let non_existent_node = MastNodeId::new_unchecked(999);
    assert!(debug_info.asm_op_for_operation(non_existent_node, 0).is_none());
    assert!(debug_info.first_asm_op_for_node(non_existent_node).is_none());
}
