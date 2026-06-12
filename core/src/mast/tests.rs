use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};

use miden_crypto::rand::test_utils::prng_array;
use proptest::prelude::*;

use crate::{
    Felt, WORD_SIZE, Word,
    chiplets::hasher,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNode, DynNodeBuilder, JoinNodeBuilder,
        MastForest, MastForestContributor, MastNodeExt,
    },
    operations::{AssemblyOp, DebugVarInfo, DebugVarLocation, Operation},
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

// MAST FOREST COMPACTION TESTS
// ================================================================================================

/// Tests comprehensive mast forest compaction across duplicate nodes.
#[test]
fn test_mast_forest_compaction_comprehensive() {
    let mut forest = MastForest::new();

    let bb1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    let bb2 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
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
    let node_id = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest).unwrap();

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
    let node_id = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest).unwrap();

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
    // This storage is indexed by (node_id, operation_index), so AssemblyOps are associated with
    // specific operations within basic block nodes.
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
    let bb_node_id = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest).unwrap();

    // Register AssemblyOp for operation 0 in the basic block (node has 2 operations)
    forest.debug_info.register_asm_ops(bb_node_id, 2, vec![(0, asm_op_id)]).unwrap();

    // Test getting assembly op from basic block
    let bb_result = forest.get_assembly_op(bb_node_id, Some(0));
    assert!(bb_result.is_some());
    assert_eq!(bb_result.unwrap(), &assembly_op);

    // Create some control flow nodes using this basic block
    let call_node = CallNodeBuilder::new(bb_node_id).add_to_forest(&mut forest).unwrap();
    let join_child2 = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::new_unchecked(2))])
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
    let node_id = BasicBlockNodeBuilder::new(operations.clone())
        .add_to_forest(&mut forest)
        .unwrap();

    let result = forest.get_assembly_op(node_id, None);
    assert!(result.is_none(), "Node with no AssemblyOps registered should return None");

    // Test 2: Add AssemblyOp and register it for operations
    let asm_op1 = AssemblyOp::new(None, "context1".into(), 1, "op1".into());
    let asm_op_id1 = forest.debug_info.add_asm_op(asm_op1.clone()).unwrap();

    let node_id2 = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest).unwrap();
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
    let node_id3 = BasicBlockNodeBuilder::new(ops_multi).add_to_forest(&mut forest).unwrap();
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
    let node_id4 = BasicBlockNodeBuilder::new(ops4).add_to_forest(&mut forest).unwrap();
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

    let node = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(node);

    assert!(forest.debug_info.is_empty());

    // Strip debug info only
    let forest = forest.without_debug_info();

    // Verify debug info is removed but structure remains
    assert!(forest.debug_info.is_empty());
    assert_eq!(forest.num_nodes(), 1);
    assert_eq!(forest.num_procedures(), 1);
}

#[test]
fn test_compaction_independent() {
    let mut forest = MastForest::new();

    // Create two identical nodes.
    let node1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    let node2 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(node1);
    forest.make_root(node2);

    // Verify initial state has duplicate nodes
    assert_eq!(forest.num_nodes(), 2);
    assert_eq!(forest.num_procedures(), 2);
    assert!(forest.debug_info.is_empty());

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
    let node1 = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let node2 = BasicBlockNodeBuilder::new(vec![Operation::Mul])
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

    // Test that stripping debug info doesn't invalidate the cache
    forest = forest.without_debug_info();
    let commitment6 = forest.commitment();
    assert_eq!(
        commitment3, commitment6,
        "stripping debug info should not invalidate commitment cache"
    );

    // Test that remove_nodes invalidates the cache
    let nodes_to_remove = BTreeSet::new();
    forest.remove_nodes(&nodes_to_remove); // Empty set, but still calls the method
    let commitment7 = forest.commitment();
    // Since we didn't actually remove anything, commitment should still be the same
    assert_eq!(commitment3, commitment7);
}

#[test]
fn remove_nodes_remaps_debug_vars_for_retained_nodes() {
    let mut forest = MastForest::new();
    let removed = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let retained = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(retained);

    let debug_var_id = forest
        .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
        .unwrap();
    forest
        .debug_info_mut()
        .register_op_indexed_debug_vars(retained, vec![(0, debug_var_id)])
        .unwrap();

    let mut nodes_to_remove = BTreeSet::new();
    nodes_to_remove.insert(removed);
    let id_remappings = forest.remove_nodes(&nodes_to_remove);
    let retained = id_remappings[&retained];

    assert_eq!(forest.debug_vars_for_operation(retained, 0), &[debug_var_id]);
    assert_eq!(forest.debug_info().debug_vars_for_node(retained), vec![(0, debug_var_id)]);
}

#[test]
fn remove_nodes_skips_removed_procedure_roots() {
    let mut forest = MastForest::new();
    let removed_root = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let retained_root = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(removed_root);
    forest.make_root(retained_root);

    let mut nodes_to_remove = BTreeSet::new();
    nodes_to_remove.insert(removed_root);
    let id_remappings = forest.remove_nodes(&nodes_to_remove);
    let retained_root = id_remappings[&retained_root];

    assert_eq!(forest.procedure_roots(), &[retained_root]);
}

#[test]
fn remove_nodes_prunes_removed_procedure_names() {
    let mut forest = MastForest::new();
    let removed_root = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let retained_root = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(removed_root);
    forest.make_root(retained_root);

    let removed_digest = forest[removed_root].digest();
    let retained_digest = forest[retained_root].digest();
    forest.insert_procedure_name(removed_digest, Arc::from("removed"));
    forest.insert_procedure_name(retained_digest, Arc::from("retained"));

    let mut nodes_to_remove = BTreeSet::new();
    nodes_to_remove.insert(removed_root);
    forest.remove_nodes(&nodes_to_remove);

    assert_eq!(forest.procedure_name(&removed_digest), None);
    assert_eq!(forest.procedure_name(&retained_digest), Some("retained"));
}

#[test]
#[should_panic(expected = "cannot remove node")]
fn remove_nodes_rejects_nodes_referenced_by_retained_parents() {
    let mut forest = MastForest::new();
    let child = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let parent = CallNodeBuilder::new(child).add_to_forest(&mut forest).unwrap();
    forest.make_root(parent);

    let mut nodes_to_remove = BTreeSet::new();
    nodes_to_remove.insert(child);
    forest.remove_nodes(&nodes_to_remove);
}

#[test]
fn remove_nodes_clears_node_metadata_when_all_nodes_are_removed() {
    let mut forest = MastForest::new();
    let node = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(node);

    let asm_op_id = forest
        .debug_info_mut()
        .add_asm_op(AssemblyOp::new(None, "test".into(), 1, "add".into()))
        .unwrap();
    let debug_var_id = forest
        .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
        .unwrap();
    forest.debug_info_mut().register_asm_ops(node, 1, vec![(0, asm_op_id)]).unwrap();
    forest
        .debug_info_mut()
        .register_op_indexed_debug_vars(node, vec![(0, debug_var_id)])
        .unwrap();

    let mut nodes_to_remove = BTreeSet::new();
    nodes_to_remove.insert(node);
    forest.remove_nodes(&nodes_to_remove);

    assert_eq!(forest.num_nodes(), 0);
    assert!(forest.procedure_roots().is_empty());
    assert!(forest.debug_info().asm_ops().is_empty());
    assert!(forest.debug_info().debug_vars().is_empty());
    assert!(forest.debug_info().asm_ops_for_node(node).is_empty());
    assert!(forest.debug_vars_for_operation(node, 0).is_empty());
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
