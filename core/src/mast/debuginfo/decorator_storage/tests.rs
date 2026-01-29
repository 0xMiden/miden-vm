use miden_utils_indexing::IndexVec;

use super::*;

/// Helper function to create a test DecoratorId
fn test_decorator_id(value: u32) -> DecoratorId {
    DecoratorId(value)
}

/// Helper function to create a test MastNodeId
fn test_node_id(value: u32) -> MastNodeId {
    MastNodeId::new_unchecked(value)
}

/// Helper to create standard test storage with 2 nodes, 3 operations, 6 decorator IDs
/// Structure: Node 0: Op 0 -> [0, 1], Op 1 -> [2]; Node 1: Op 0 -> [3, 4, 5]
fn create_standard_test_storage() -> OpToDecoratorIds {
    let decorator_ids = vec![
        test_decorator_id(0),
        test_decorator_id(1),
        test_decorator_id(2),
        test_decorator_id(3),
        test_decorator_id(4),
        test_decorator_id(5),
    ];
    let op_indptr_for_dec_ids = vec![0, 2, 3, 6];
    let mut node_indptr_for_op_idx = IndexVec::new();
    node_indptr_for_op_idx.push(0).expect("test setup: IndexVec capacity exceeded");
    node_indptr_for_op_idx.push(2).expect("test setup: IndexVec capacity exceeded");
    node_indptr_for_op_idx.push(3).expect("test setup: IndexVec capacity exceeded");

    OpToDecoratorIds::from_components(decorator_ids, op_indptr_for_dec_ids, node_indptr_for_op_idx)
        .unwrap()
}

#[test]
fn test_constructors() {
    // Test new()
    let storage = OpToDecoratorIds::new();
    assert_eq!(storage.num_nodes(), 0);
    assert_eq!(storage.num_decorator_ids(), 0);

    // Test with_capacity()
    let storage = OpToDecoratorIds::with_capacity(10, 20, 30);
    assert_eq!(storage.num_nodes(), 0);
    assert_eq!(storage.num_decorator_ids(), 0);

    // Test default()
    let storage = OpToDecoratorIds::default();
    assert_eq!(storage.num_nodes(), 0);
    assert_eq!(storage.num_decorator_ids(), 0);
}

#[test]
fn test_from_components_simple() {
    // Create a simple structure:
    // Node 0: Op 0 -> [0, 1], Op 1 -> [2]
    // Node 1: Op 0 -> [3, 4, 5]
    let storage = create_standard_test_storage();

    assert_eq!(storage.num_nodes(), 2);
    assert_eq!(storage.num_decorator_ids(), 6);
}

#[test]
fn test_from_components_invalid_structure() {
    // Empty structures are valid
    let result = OpToDecoratorIds::from_components(vec![], vec![], IndexVec::new());
    assert!(result.is_ok());

    // Test with operation pointer exceeding decorator indices
    let result = OpToDecoratorIds::from_components(
        vec![test_decorator_id(0)],
        vec![0, 2], // Points to index 2 but we only have 1 decorator
        IndexVec::new(),
    );
    assert_eq!(result, Err(DecoratorIndexError::InternalStructure));

    // Test with non-monotonic operation pointers
    let result = OpToDecoratorIds::from_components(
        vec![test_decorator_id(0), test_decorator_id(1)],
        vec![0, 2, 1], // 2 > 1, should be monotonic
        IndexVec::new(),
    );
    assert_eq!(result, Err(DecoratorIndexError::InternalStructure));
}

#[test]
fn test_data_access_methods() {
    let storage = create_standard_test_storage();

    // Test decorator_ids_for_operation
    let decorators = storage.decorator_ids_for_operation(test_node_id(0), 0).unwrap();
    assert_eq!(decorators, &[test_decorator_id(0), test_decorator_id(1)]);

    let decorators = storage.decorator_ids_for_operation(test_node_id(0), 1).unwrap();
    assert_eq!(decorators, &[test_decorator_id(2)]);

    let decorators = storage.decorator_ids_for_operation(test_node_id(1), 0).unwrap();
    assert_eq!(decorators, &[test_decorator_id(3), test_decorator_id(4), test_decorator_id(5)]);

    // Test decorator_ids_for_node
    let decorators: Vec<_> = storage.decorator_ids_for_node(test_node_id(0)).unwrap().collect();
    assert_eq!(decorators.len(), 2);
    assert_eq!(decorators[0], (0, &[test_decorator_id(0), test_decorator_id(1)][..]));
    assert_eq!(decorators[1], (1, &[test_decorator_id(2)][..]));

    let decorators: Vec<_> = storage.decorator_ids_for_node(test_node_id(1)).unwrap().collect();
    assert_eq!(decorators.len(), 1);
    assert_eq!(
        decorators[0],
        (0, &[test_decorator_id(3), test_decorator_id(4), test_decorator_id(5)][..])
    );

    // Test operation_has_decorator_ids
    assert!(storage.operation_has_decorator_ids(test_node_id(0), 0).unwrap());
    assert!(storage.operation_has_decorator_ids(test_node_id(0), 1).unwrap());
    assert!(storage.operation_has_decorator_ids(test_node_id(1), 0).unwrap());
    assert!(!storage.operation_has_decorator_ids(test_node_id(0), 2).unwrap());

    // Test num_decorator_ids_for_operation
    assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(0), 0).unwrap(), 2);
    assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(0), 1).unwrap(), 1);
    assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(1), 0).unwrap(), 3);
    assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(0), 2).unwrap(), 0);

    // Test invalid operation returns empty slice
    let decorators = storage.decorator_ids_for_operation(test_node_id(0), 2).unwrap();
    assert_eq!(decorators, &[]);
}

#[test]
fn test_empty_nodes_basic_functionality() {
    // Test 1: Empty nodes created via from_components (original
    // test_empty_nodes_and_operations)
    {
        // Create a structure with empty nodes/operations
        let decorator_indices = vec![];
        let op_indptr_for_dec_idx = vec![0, 0, 0]; // 2 operations, both empty
        let mut node_indptr_for_op_idx = IndexVec::new();
        node_indptr_for_op_idx.push(0).expect("test setup: IndexVec capacity exceeded");
        node_indptr_for_op_idx.push(2).expect("test setup: IndexVec capacity exceeded");

        let storage = OpToDecoratorIds::from_components(
            decorator_indices,
            op_indptr_for_dec_idx,
            node_indptr_for_op_idx,
        )
        .unwrap();

        assert_eq!(storage.num_nodes(), 1);
        assert_eq!(storage.num_decorator_ids(), 0);

        // Empty decorators
        let decorators = storage.decorator_ids_for_operation(test_node_id(0), 0).unwrap();
        assert_eq!(decorators, &[]);

        // Operation has no decorators
        assert!(!storage.operation_has_decorator_ids(test_node_id(0), 0).unwrap());
    }

    // Test 2: Empty nodes created via add_decorator_info_for_node (original
    // test_decorator_ids_for_node_with_empty_nodes)
    {
        let mut storage = OpToDecoratorIds::new();

        // Add node 0 with no decorators (empty node)
        storage.add_decorator_info_for_node(test_node_id(0), vec![]).unwrap();

        // Test 2a: operation_range_for_node should be empty for node with no decorators
        let range = storage.operation_range_for_node(test_node_id(0));
        assert!(range.is_ok(), "operation_range_for_node should return Ok for empty node");
        let range = range.unwrap();
        assert_eq!(range, 0..0, "Empty node should have empty operations range");

        // Test 2b: decorator_ids_for_node should return an empty iterator
        let result = storage.decorator_ids_for_node(test_node_id(0));
        assert!(result.is_ok(), "decorator_ids_for_node should return Ok for empty node");
        // The iterator should be empty
        let decorators: Vec<_> = result.unwrap().collect();
        assert_eq!(decorators, Vec::<(usize, &[DecoratorId])>::new());

        // Test 2c: decorator_links_for_node should return an empty iterator
        let result = storage.decorator_links_for_node(test_node_id(0));
        assert!(result.is_ok(), "decorator_links_for_node should return Ok for empty node");
        let links: Vec<_> = result.unwrap().into_iter().collect();
        assert_eq!(links, Vec::<(usize, DecoratorId)>::new());

        // Test 2d: Basic access methods on empty node
        assert_eq!(storage.num_nodes(), 1);
        assert_eq!(storage.num_decorator_ids(), 0);
    }
}

#[test]
fn test_debug_impl() {
    let storage = OpToDecoratorIds::new();
    let debug_str = format!("{:?}", storage);
    assert!(debug_str.contains("OpToDecoratorIds"));
}

#[test]
fn test_clone_and_equality() {
    let decorator_indices = vec![
        test_decorator_id(0),
        test_decorator_id(1),
        test_decorator_id(2),
        test_decorator_id(3),
        test_decorator_id(4),
        test_decorator_id(5),
    ];
    let op_indptr_for_dec_idx = vec![0, 2, 3, 6];
    let mut node_indptr_for_op_idx = IndexVec::new();
    node_indptr_for_op_idx.push(0).expect("test setup: IndexVec capacity exceeded");
    node_indptr_for_op_idx.push(2).expect("test setup: IndexVec capacity exceeded");
    node_indptr_for_op_idx.push(3).expect("test setup: IndexVec capacity exceeded");

    let storage1 = OpToDecoratorIds::from_components(
        decorator_indices.clone(),
        op_indptr_for_dec_idx.clone(),
        node_indptr_for_op_idx.clone(),
    )
    .unwrap();

    let storage2 = storage1.clone();
    assert_eq!(storage1, storage2);

    // Modify one and ensure they're no longer equal
    let different_decorators = vec![test_decorator_id(10)];
    let mut different_node_indptr = IndexVec::new();
    different_node_indptr.push(0).expect("test setup: IndexVec capacity exceeded");
    different_node_indptr.push(1).expect("test setup: IndexVec capacity exceeded");

    let storage3 =
        OpToDecoratorIds::from_components(different_decorators, vec![0, 1], different_node_indptr)
            .unwrap();

    assert_ne!(storage1, storage3);
}

#[test]
fn test_add_decorator_info_functionality() {
    // Test 1: Basic multi-node functionality
    let mut storage = OpToDecoratorIds::new();

    // Add decorators for node 0
    let decorators_info = vec![
        (0, test_decorator_id(10)),
        (0, test_decorator_id(11)),
        (2, test_decorator_id(12)),
    ];
    storage.add_decorator_info_for_node(test_node_id(0), decorators_info).unwrap();

    assert_eq!(storage.num_nodes(), 1);
    assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(0), 0).unwrap(), 2);
    assert_eq!(storage.num_decorator_ids_for_operation(test_node_id(0), 2).unwrap(), 1);

    // Add node 1 with simple decorators
    storage
        .add_decorator_info_for_node(test_node_id(1), vec![(0, test_decorator_id(20))])
        .unwrap();
    assert_eq!(storage.num_nodes(), 2);

    let node1_op0 = storage.decorator_ids_for_operation(test_node_id(1), 0).unwrap();
    assert_eq!(node1_op0, &[test_decorator_id(20)]);

    // Test 2: Sequential constraint validation
    let mut storage2 = OpToDecoratorIds::new();
    storage2
        .add_decorator_info_for_node(test_node_id(0), vec![(0, test_decorator_id(10))])
        .unwrap();

    // Adding node 1 should succeed
    storage2
        .add_decorator_info_for_node(test_node_id(1), vec![(0, test_decorator_id(30))])
        .unwrap();
    assert_eq!(storage2.num_nodes(), 2);

    // Try to add node 0 again - should fail
    let result =
        storage2.add_decorator_info_for_node(test_node_id(0), vec![(0, test_decorator_id(40))]);
    assert_eq!(result, Err(DecoratorIndexError::NodeIndex(test_node_id(0))));

    // Test 3: Empty input handling (creates empty nodes with no operations)
    let mut storage3 = OpToDecoratorIds::new();
    let result = storage3.add_decorator_info_for_node(test_node_id(0), vec![]);
    assert_eq!(result, Ok(()));
    assert_eq!(storage3.num_nodes(), 1); // Should create empty node

    // Empty node should have no operations (accessing any operation should return empty)
    let decorators = storage3.decorator_ids_for_operation(test_node_id(0), 0).unwrap();
    assert_eq!(decorators, &[]);

    // Should be able to add next node after empty node
    storage3
        .add_decorator_info_for_node(test_node_id(1), vec![(0, test_decorator_id(100))])
        .unwrap();
    assert_eq!(storage3.num_nodes(), 2);

    // Test 4: Operations with gaps
    let mut storage4 = OpToDecoratorIds::new();
    let gap_decorators = vec![
        (0, test_decorator_id(10)),
        (0, test_decorator_id(11)), // operation 0 has 2 decorators
        (3, test_decorator_id(12)), // operation 3 has 1 decorator
        (4, test_decorator_id(13)), // operation 4 has 1 decorator
    ];
    storage4.add_decorator_info_for_node(test_node_id(0), gap_decorators).unwrap();

    assert_eq!(storage4.num_decorator_ids_for_operation(test_node_id(0), 0).unwrap(), 2);
    assert_eq!(storage4.num_decorator_ids_for_operation(test_node_id(0), 1).unwrap(), 0);
    assert_eq!(storage4.num_decorator_ids_for_operation(test_node_id(0), 2).unwrap(), 0);
    assert_eq!(storage4.num_decorator_ids_for_operation(test_node_id(0), 3).unwrap(), 1);
    assert_eq!(storage4.num_decorator_ids_for_operation(test_node_id(0), 4).unwrap(), 1);

    // Test accessing operations without decorators returns empty slice
    let op1_decorators = storage4.decorator_ids_for_operation(test_node_id(0), 1).unwrap();
    assert_eq!(op1_decorators, &[]);

    // Test 5: Your specific use case - mixed empty and non-empty nodes
    let mut storage5 = OpToDecoratorIds::new();

    // node 0 with decorators
    storage5
        .add_decorator_info_for_node(
            test_node_id(0),
            vec![(0, test_decorator_id(1)), (1, test_decorator_id(0))],
        )
        .unwrap();

    // node 1 with no decorators (empty)
    storage5.add_decorator_info_for_node(test_node_id(1), vec![]).unwrap();

    // node 2 with decorators
    storage5
        .add_decorator_info_for_node(
            test_node_id(2),
            vec![(1, test_decorator_id(1)), (2, test_decorator_id(2))],
        )
        .unwrap();

    assert_eq!(storage5.num_nodes(), 3);

    // Verify node 0: op 0 has [1], op 1 has [0]
    assert_eq!(
        storage5.decorator_ids_for_operation(test_node_id(0), 0).unwrap(),
        &[test_decorator_id(1)]
    );
    assert_eq!(
        storage5.decorator_ids_for_operation(test_node_id(0), 1).unwrap(),
        &[test_decorator_id(0)]
    );

    // Verify node 1: has no operations at all, any operation access returns empty
    assert_eq!(storage5.decorator_ids_for_operation(test_node_id(1), 0).unwrap(), &[]);

    // Verify node 2: op 0 has [], op 1 has [1], op 2 has [2]
    assert_eq!(storage5.decorator_ids_for_operation(test_node_id(2), 0).unwrap(), &[]);
    assert_eq!(
        storage5.decorator_ids_for_operation(test_node_id(2), 1).unwrap(),
        &[test_decorator_id(1)]
    );
    assert_eq!(
        storage5.decorator_ids_for_operation(test_node_id(2), 2).unwrap(),
        &[test_decorator_id(2)]
    );
}

#[test]
fn test_empty_nodes_edge_cases() {
    // Test edge cases with empty nodes (nodes with no decorators)
    // This consolidates test_decorator_ids_for_node_mixed_scenario and
    // test_decorated_links_overflow_bug

    let mut storage = OpToDecoratorIds::new();

    // Set up mixed scenario: some nodes have decorators, some don't
    // Node 0: Has decorators
    storage
        .add_decorator_info_for_node(
            test_node_id(0),
            vec![(0, test_decorator_id(10)), (2, test_decorator_id(20))],
        )
        .unwrap();

    // Node 1: Has decorators
    storage
        .add_decorator_info_for_node(
            test_node_id(1),
            vec![
                (0, test_decorator_id(30)),
                (0, test_decorator_id(31)),
                (3, test_decorator_id(32)),
            ],
        )
        .unwrap();

    // Node 2: No decorators (empty node) - this is the edge case we're testing
    storage.add_decorator_info_for_node(test_node_id(2), vec![]).unwrap();

    // Test 1: Verify range handling for empty nodes
    let range0 = storage.operation_range_for_node(test_node_id(0)).unwrap();
    let range1 = storage.operation_range_for_node(test_node_id(1)).unwrap();
    let range2 = storage.operation_range_for_node(test_node_id(2)).unwrap();

    // Nodes with decorators should have non-empty ranges
    assert!(range0.end > range0.start, "Node with decorators should have non-empty range");
    assert!(range1.end > range1.start, "Node with decorators should have non-empty range");

    // Empty node should have range pointing to a sentinel that was added when the empty node
    // was created. The sentinel is added at the position that would have been "past the end"
    // before the empty node was added, making the empty node's range valid.
    let op_indptr_len = storage.op_indptr_for_dec_ids.len();
    // The empty node should point to the sentinel (which is now at len()-1 after being added)
    let expected_empty_pos = op_indptr_len - 1;
    assert_eq!(
        range2.start, expected_empty_pos,
        "Empty node should point to the sentinel that was added for it"
    );
    assert_eq!(
        range2.end, expected_empty_pos,
        "Empty node should have empty range at the sentinel"
    );

    // Test 2: decorator_ids_for_node() should work for empty nodes
    // This should not panic - the iterator should be empty even though the range points to
    // array end
    let result = storage.decorator_ids_for_node(test_node_id(2));
    assert!(result.is_ok(), "decorator_ids_for_node should work for node with no decorators");
    let decorators: Vec<_> = result.unwrap().collect();
    assert_eq!(decorators, Vec::<(usize, &[DecoratorId])>::new());

    // Test 3: decorator_links_for_node() should work for empty nodes (tests overflow bug)
    // This tests the specific overflow bug in DecoratedLinks iterator
    let result = storage.decorator_links_for_node(test_node_id(2));
    assert!(result.is_ok(), "decorator_links_for_node should return Ok for empty node");

    let links = result.unwrap();
    // This should not panic, even when iterating
    let collected: Vec<_> = links.into_iter().collect();
    assert_eq!(collected, Vec::<(usize, DecoratorId)>::new());

    // Test 4: Multiple iterations should work (regression test for iterator reuse)
    let result2 = storage.decorator_links_for_node(test_node_id(2));
    assert!(
        result2.is_ok(),
        "decorator_links_for_node should work repeatedly for empty node"
    );
    let links2 = result2.unwrap();
    let collected2: Vec<_> = links2.into_iter().collect();
    assert_eq!(collected2, Vec::<(usize, DecoratorId)>::new());

    // Test 5: Multiple iterations of decorator_ids_for_node should also work
    let result3 = storage.decorator_ids_for_node(test_node_id(2));
    assert!(result3.is_ok(), "decorator_ids_for_node should work repeatedly for empty node");
    let decorators2: Vec<_> = result3.unwrap().collect();
    assert_eq!(decorators2, Vec::<(usize, &[DecoratorId])>::new());
}

#[test]
fn test_decorator_links_for_node_flattened() {
    let storage = create_standard_test_storage();
    let n0 = MastNodeId::new_unchecked(0);
    let flat: Vec<_> = storage.decorator_links_for_node(n0).unwrap().into_iter().collect();
    // Node 0: Op0 -> [0,1], Op1 -> [2]
    assert_eq!(flat, vec![(0, DecoratorId(0)), (0, DecoratorId(1)), (1, DecoratorId(2)),]);

    let n1 = MastNodeId::new_unchecked(1);
    let flat1: Vec<_> = storage.decorator_links_for_node(n1).unwrap().into_iter().collect();
    // Node 1: Op0 -> [3,4,5]
    assert_eq!(flat1, vec![(0, DecoratorId(3)), (0, DecoratorId(4)), (0, DecoratorId(5)),]);
}

#[test]
/// This test verifies that the CSR encoding described in the OpToDecoratorIds struct
/// documentation correctly represents COO data. It also validates all accessor methods
/// work as expected. Keep this test in sync with the documentation example (adding nodes
/// to this test if you add nodes to the documentation example, and vice versa).
fn test_csr_and_coo_produce_same_elements() {
    // Build a COO representation manually
    let coo_data = vec![
        // Node 0
        (MastNodeId::new_unchecked(0), 0, DecoratorId(10)),
        (MastNodeId::new_unchecked(0), 0, DecoratorId(11)),
        (MastNodeId::new_unchecked(0), 1, DecoratorId(12)),
        (MastNodeId::new_unchecked(0), 2, DecoratorId(13)),
        // Node 1
        (MastNodeId::new_unchecked(1), 0, DecoratorId(20)),
        (MastNodeId::new_unchecked(1), 2, DecoratorId(21)),
        (MastNodeId::new_unchecked(1), 2, DecoratorId(22)),
        // Node 2 (empty node, should still work)
        // Node 3
        (MastNodeId::new_unchecked(3), 0, DecoratorId(30)),
    ];

    // Build COO representation as a HashMap for easy lookup during verification
    let mut coo_map: alloc::collections::BTreeMap<(MastNodeId, usize), Vec<DecoratorId>> =
        alloc::collections::BTreeMap::new();
    for (node, op_idx, decorator_id) in &coo_data {
        coo_map.entry((*node, *op_idx)).or_default().push(*decorator_id);
    }

    // Build CSR representation using the builder API
    let mut csr_storage = OpToDecoratorIds::new();

    // Node 0: Op0 -> [10,11], Op1 -> [12], Op2 -> [13]
    csr_storage
        .add_decorator_info_for_node(
            MastNodeId::new_unchecked(0),
            vec![
                (0, DecoratorId(10)),
                (0, DecoratorId(11)),
                (1, DecoratorId(12)),
                (2, DecoratorId(13)),
            ],
        )
        .unwrap();

    // Node 1: Op0 -> [20], Op2 -> [21,22]
    csr_storage
        .add_decorator_info_for_node(
            MastNodeId::new_unchecked(1),
            vec![(0, DecoratorId(20)), (2, DecoratorId(21)), (2, DecoratorId(22))],
        )
        .unwrap();

    // Node 2: empty
    csr_storage
        .add_decorator_info_for_node(MastNodeId::new_unchecked(2), vec![])
        .unwrap();

    // Node 3: Op0 -> [30]
    csr_storage
        .add_decorator_info_for_node(MastNodeId::new_unchecked(3), vec![(0, DecoratorId(30))])
        .unwrap();

    // Verify that CSR and COO produce the same elements
    for node_idx in 0..4 {
        let node_id = MastNodeId::new_unchecked(node_idx);

        // Get all operations for this node from CSR
        let op_range = csr_storage.operation_range_for_node(node_id).unwrap();
        let num_ops = op_range.len();

        // For each operation in this node
        for op_idx in 0..num_ops {
            // Get decorator IDs from CSR
            let csr_decorator_ids =
                csr_storage.decorator_ids_for_operation(node_id, op_idx).unwrap();

            // Get decorator IDs from COO map
            let coo_key = (node_id, op_idx);
            let coo_decorator_ids =
                coo_map.get(&coo_key).map_or(&[] as &[DecoratorId], |v| v.as_slice());

            // They should be the same
            assert_eq!(
                csr_decorator_ids, coo_decorator_ids,
                "CSR and COO should produce the same decorator IDs for node {:?}, op {}",
                node_id, op_idx
            );
        }
    }

    // Also verify using the flattened iterator approach
    for node_idx in 0..4 {
        let node_id = MastNodeId::new_unchecked(node_idx);

        // Get flattened view from CSR
        let csr_flat: Vec<(usize, DecoratorId)> =
            csr_storage.decorator_links_for_node(node_id).unwrap().into_iter().collect();

        // Build expected from COO map
        let mut expected_flat = Vec::new();
        for ((node, op_idx), decorator_ids) in &coo_map {
            if *node == node_id {
                for decorator_id in decorator_ids {
                    expected_flat.push((*op_idx, *decorator_id));
                }
            }
        }
        // Sort by operation index then decorator ID for consistent comparison
        expected_flat.sort_by_key(|(op_idx, dec_id)| (*op_idx, u32::from(*dec_id)));

        assert_eq!(
            csr_flat, expected_flat,
            "Flattened CSR and COO should produce the same elements for node {:?}",
            node_id
        );
    }
}

#[test]
fn test_validate_csr_valid() {
    let storage = create_standard_test_storage();
    assert!(storage.validate_csr(6).is_ok());
}

#[test]
fn test_validate_csr_invalid_decorator_id() {
    let storage = create_standard_test_storage();
    // decorator_count=3 but storage has IDs up to 5
    let result = storage.validate_csr(3);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Invalid decorator ID"));
}

#[test]
fn test_validate_csr_not_monotonic() {
    let decorator_ids = vec![test_decorator_id(0), test_decorator_id(1)];
    let op_indptr_for_dec_ids = vec![0, 2, 1]; // Not monotonic!
    let mut node_indptr_for_op_idx = IndexVec::new();
    node_indptr_for_op_idx.push(0).unwrap();
    node_indptr_for_op_idx.push(2).unwrap();

    let storage = OpToDecoratorIds::from_components(
        decorator_ids,
        op_indptr_for_dec_ids,
        node_indptr_for_op_idx,
    );

    // from_components should catch this
    assert!(storage.is_err());
}

#[test]
fn test_validate_csr_wrong_start() {
    let decorator_ids = vec![test_decorator_id(0)];
    let op_indptr_for_dec_ids = vec![1, 1]; // Should start at 0!
    let mut node_indptr_for_op_idx = IndexVec::new();
    node_indptr_for_op_idx.push(0).unwrap();
    node_indptr_for_op_idx.push(1).unwrap();

    let storage = OpToDecoratorIds::from_components(
        decorator_ids,
        op_indptr_for_dec_ids,
        node_indptr_for_op_idx,
    );

    assert!(storage.is_err());
}

#[cfg(feature = "arbitrary")]
proptest! {
    /// Property test that verifies decorator_links_for_node always produces a valid iterator
    /// that can be fully consumed without panicking for any OpToDecoratorIds.
    #[test]
    fn decorator_links_for_node_always_iterates_complete(
        mapping in any::<OpToDecoratorIds>()
    ) {
        // Skip empty mappings since they have no nodes to test
        if mapping.num_nodes() == 0 {
            return Ok(());
        }

        // Test every valid node in the mapping
        for node_idx in 0..mapping.num_nodes() {
            let node_id = MastNodeId::new_unchecked(node_idx as u32);

            // Call decorator_links_for_node - this should never return an error for valid nodes
            let result = mapping.decorator_links_for_node(node_id);

            // The result should always be Ok for valid node indices
            prop_assume!(result.is_ok(), "decorator_links_for_node should succeed for valid node");

            let decorated_links = result.unwrap();

            // Convert to iterator and collect all items - this should complete without panicking
            let collected: Vec<(usize, DecoratorId)> = decorated_links.into_iter().collect();

            // The collected items should match what we get from decorator_ids_for_node
            let expected_items: Vec<(usize, DecoratorId)> = mapping
                .decorator_ids_for_node(node_id)
                .unwrap()
                .flat_map(|(op_idx, decorator_ids)| {
                    decorator_ids.iter().map(move |&decorator_id| (op_idx, decorator_id))
                })
                .collect();

            prop_assert_eq!(collected, expected_items);
        }
    }
}

// Sparse debug tests
use alloc::vec;

#[test]
fn test_sparse_case_manual() {
    // Manually create what should be produced by sparse decorator case:
    // 10 nodes, decorators only at nodes 0 and 5

    // Just node 0 with decorator at op 0
    let decorator_ids = vec![test_decorator_id(0)];
    let op_indptr_for_dec_ids = vec![0, 1, 1]; // op 0: [0,1), sentinel
    let mut node_indptr = IndexVec::new();
    node_indptr.push(0).unwrap(); // node 0 starts at op index 0
    node_indptr.push(2).unwrap(); // node 0 ends at op index 2 (sentinel)

    // Validate this structure
    let result =
        OpToDecoratorIds::from_components(decorator_ids, op_indptr_for_dec_ids, node_indptr);

    assert!(result.is_ok(), "Single node with decorator should validate: {:?}", result);
}

#[test]
fn test_sparse_case_two_nodes() {
    // Two nodes: node 0 with decorator, node 1 empty
    let decorator_ids = vec![test_decorator_id(0)];
    let op_indptr_for_dec_ids = vec![0, 1, 1]; // op 0: [0,1), sentinel at 1
    let mut node_indptr = IndexVec::new();
    node_indptr.push(0).unwrap(); // node 0 starts at op index 0
    node_indptr.push(2).unwrap(); // node 0 ends at op index 2
    node_indptr.push(2).unwrap(); // node 1 (empty) points to same location

    let result =
        OpToDecoratorIds::from_components(decorator_ids, op_indptr_for_dec_ids, node_indptr);

    assert!(
        result.is_ok(),
        "Two nodes (one with decorator, one empty) should validate: {:?}",
        result
    );
}

#[test]
fn test_sparse_debuginfo_round_trip() {
    use alloc::collections::BTreeMap;

    use crate::{
        Decorator,
        mast::debuginfo::{DebugInfo, NodeToDecoratorIds},
        utils::{Deserializable, Serializable},
    };

    // Create a sparse CSR structure like we'd see with 10 nodes where only 0 and 5 have
    // decorators
    let decorator_ids = vec![test_decorator_id(0), test_decorator_id(1)];

    // Node 0: op 0 has decorator 0
    // Nodes 1-4: empty
    // Node 5: op 0 has decorator 1
    let op_indptr_for_dec_ids = vec![0, 1, 1, 1, 2, 2]; // ops with their decorator ranges
    let mut node_indptr_for_op_idx = IndexVec::new();
    node_indptr_for_op_idx.push(0).unwrap(); // node 0
    node_indptr_for_op_idx.push(2).unwrap(); // node 0 end
    node_indptr_for_op_idx.push(2).unwrap(); // node 1 (empty)
    node_indptr_for_op_idx.push(2).unwrap(); // node 2 (empty)
    node_indptr_for_op_idx.push(2).unwrap(); // node 3 (empty)
    node_indptr_for_op_idx.push(2).unwrap(); // node 4 (empty)
    node_indptr_for_op_idx.push(4).unwrap(); // node 5

    let op_storage = OpToDecoratorIds::from_components(
        decorator_ids.clone(),
        op_indptr_for_dec_ids,
        node_indptr_for_op_idx,
    )
    .expect("CSR structure should be valid");

    // Create a minimal DebugInfo
    let mut decorators = crate::mast::debuginfo::IndexVec::new();
    decorators.push(Decorator::Trace(0)).unwrap();
    decorators.push(Decorator::Trace(5)).unwrap();

    let node_storage = NodeToDecoratorIds::new();
    let error_codes = BTreeMap::new();

    let debug_info = DebugInfo {
        decorators,
        op_decorator_storage: op_storage,
        node_decorator_storage: node_storage,
        error_codes,
        procedure_names: BTreeMap::new(),
    };

    // Serialize and deserialize
    let bytes = debug_info.to_bytes();
    let deserialized = DebugInfo::read_from_bytes(&bytes).expect("Should deserialize successfully");

    // Verify
    assert_eq!(debug_info.num_decorators(), deserialized.num_decorators());
}
