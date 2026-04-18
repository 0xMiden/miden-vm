use alloc::vec::Vec;

use super::{
    EmptySubtreeRoots, InnerNode, NodeIndex, NodeMutation, SMT_DEPTH, SUBTREE_DEPTH, Subtree,
};
use crate::Word;

#[test]
fn test_initial_state() {
    let root_index = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();
    let subtree = Subtree::new(root_index);

    assert_eq!(subtree.root_index(), root_index, "Root index should match the provided index");
    assert_eq!(subtree.len(), 0, "New subtree should be empty");
    assert!(subtree.is_empty(), "New subtree should report as empty");
}

#[test]
fn test_node_operations() {
    let subtree_root_idx = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();
    let mut subtree = Subtree::new(subtree_root_idx);

    // Create test nodes and indices
    let node1_idx = NodeIndex::new(SUBTREE_DEPTH + 1, 0).unwrap();
    let node1 = InnerNode {
        left: Word::default(),
        right: Word::default(),
    };

    let node2_idx = NodeIndex::new(SUBTREE_DEPTH + 2, 3).unwrap();
    let node2 = InnerNode {
        left: Word::from([1u32; 4]),
        right: Word::from([2u32; 4]),
    };

    // Test insertion into empty subtree
    assert_eq!(subtree.len(), 0, "Subtree should be empty");

    let old_node = subtree.insert_inner_node(node1_idx, node1.clone());
    assert!(old_node.is_none(), "Old node should be empty");
    assert_eq!(subtree.len(), 1, "Subtree should have one node");

    let old_node = subtree.insert_inner_node(node2_idx, node2.clone());
    assert!(old_node.is_none(), "Old node should be empty");
    assert_eq!(subtree.len(), 2, "Subtree should have two nodes");

    // Test node retrieval
    assert_eq!(
        subtree.get_inner_node(node1_idx),
        Some(node1.clone()),
        "Should match the first node"
    );
    assert_eq!(
        subtree.get_inner_node(node2_idx),
        Some(node2.clone()),
        "Should match the second node"
    );

    let non_existent_idx = NodeIndex::new(SUBTREE_DEPTH + 3, 0).unwrap();
    assert!(
        subtree.get_inner_node(non_existent_idx).is_none(),
        "Should return None for non-existent node"
    );

    // Test node overwriting
    let node1_updated = InnerNode {
        left: Word::from([3u32; 4]),
        right: Word::from([4u32; 4]),
    };
    let previous_node = subtree.insert_inner_node(node1_idx, node1_updated.clone());
    assert_eq!(previous_node, Some(node1), "Overwriting should return the previous node");
    assert_eq!(subtree.len(), 2, "Length should not change on overwrite");
    assert_eq!(
        subtree.get_inner_node(node1_idx),
        Some(node1_updated.clone()),
        "Should retrieve the updated node"
    );

    // Test node removal
    let removed_node = subtree.remove_inner_node(node1_idx);
    assert_eq!(removed_node, Some(node1_updated), "Removing should return the removed node");
    assert_eq!(subtree.len(), 1, "Length should decrease after removal");
    assert!(
        subtree.get_inner_node(node1_idx).is_none(),
        "Removed node should no longer be retrievable"
    );

    // Test removing non-existent node
    let remove_result = subtree.remove_inner_node(node1_idx);
    assert!(remove_result.is_none(), "Removing non-existent node should return None");
    assert_eq!(subtree.len(), 1, "Length should not change when removing non-existent node");

    // Remove final node to test empty state
    let removed_node = subtree.remove_inner_node(node2_idx);
    assert_eq!(removed_node, Some(node2), "Should remove the final node");
    assert_eq!(subtree.len(), 0, "Subtree should be empty after removing all nodes");
    assert!(subtree.is_empty(), "Subtree should report as empty");

    // Test removing from empty subtree
    let remove_result = subtree.remove_inner_node(node1_idx);
    assert!(remove_result.is_none(), "Removing from empty subtree should return None");
    assert_eq!(subtree.len(), 0, "Length should remain zero");
}

#[test]
fn test_serialize_deserialize_empty_subtree() {
    let root_index = NodeIndex::new(SUBTREE_DEPTH, 1).unwrap();
    let subtree = Subtree::new(root_index);

    let serialized = subtree.to_vec();

    // Should only contain magic + version + bitmask (all zeros) and no node data
    assert_eq!(
        serialized.len(),
        5 + Subtree::BITMASK_SIZE,
        "Empty subtree serialization should only contain bitmask"
    );
    assert!(
        serialized[..4] == *b"SMT1"
            && serialized[4] == 1
            && serialized[5..].iter().all(|&byte| byte == 0),
        "Magic + version should be set and all bitmask bytes should be zero"
    );

    let deserialized = Subtree::from_vec(root_index, &serialized)
        .expect("Deserialization of empty subtree should succeed");

    assert_eq!(deserialized.root_index(), root_index, "Deserialized root index should match");
    assert!(deserialized.is_empty(), "Deserialized subtree should be empty");
    assert_eq!(deserialized.len(), 0, "Deserialized subtree should have length 0");
}

#[test]
fn test_serialize_deserialize_subtree_with_nodes() {
    let subtree_root_idx = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();
    let mut subtree = Subtree::new(subtree_root_idx);

    // Add nodes at positions: root (local index 0), first child (local index 1),
    // and last possible position (local index 254)
    let node0_idx_global = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();
    let node1_idx_global = NodeIndex::new(SUBTREE_DEPTH + 1, 0).unwrap();
    let node254_idx_global = NodeIndex::new(SUBTREE_DEPTH + 7, 127).unwrap();

    let node0 = InnerNode {
        left: Word::from([1u32; 4]),
        right: Word::from([2u32; 4]),
    };
    let node1 = InnerNode {
        left: Word::from([3u32; 4]),
        right: Word::from([4u32; 4]),
    };
    let node254 = InnerNode {
        left: Word::from([5u32; 4]),
        right: Word::from([6u32; 4]),
    };

    subtree.insert_inner_node(node0_idx_global, node0.clone());
    subtree.insert_inner_node(node1_idx_global, node1.clone());
    subtree.insert_inner_node(node254_idx_global, node254.clone());

    assert_eq!(subtree.len(), 3, "Subtree should contain 3 nodes");

    // Test serialization
    let serialized = subtree.to_vec();
    let expected_size = 5 + Subtree::BITMASK_SIZE + 6 * Subtree::HASH_SIZE;
    assert_eq!(serialized.len(), expected_size, "Serialized size should be bitmask + 3 nodes");

    // Test deserialization
    let deserialized =
        Subtree::from_vec(subtree_root_idx, &serialized).expect("Deserialization should succeed");

    assert_eq!(deserialized.root_index(), subtree_root_idx, "Root index should match");
    assert_eq!(deserialized.len(), 3, "Deserialized subtree should have 3 nodes");
    assert!(!deserialized.is_empty(), "Deserialized subtree should not be empty");

    // Verify all nodes are correctly deserialized
    assert_eq!(
        deserialized.get_inner_node(node0_idx_global),
        Some(node0),
        "First node should be correctly deserialized"
    );
    assert_eq!(
        deserialized.get_inner_node(node1_idx_global),
        Some(node1),
        "Second node should be correctly deserialized"
    );
    assert_eq!(
        deserialized.get_inner_node(node254_idx_global),
        Some(node254),
        "Third node should be correctly deserialized"
    );

    // Verify bitmask correctness
    let (bitmask_bytes, _node_data) = serialized[5..].split_at(Subtree::BITMASK_SIZE);

    // byte 0: bits 0-3 must be set
    assert_eq!(bitmask_bytes[0], 0x0f, "byte 0 must have bits 0-3 set");

    // bytes 1‥=62 must be zero
    assert!(bitmask_bytes[1..63].iter().all(|&b| b == 0), "bytes 1‥62 must be zero");

    // byte 63: bits 4 & 5 must be set
    assert_eq!(bitmask_bytes[63], 0x30, "byte 63 must have bits 4 & 5 set");
}

/// Tests global to local index conversion with zero-based subtree root
#[test]
fn global_to_local_index_conversion_zero_base() {
    let base_idx = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();

    // Test various depth and value combinations
    let test_cases = [
        // (depth, value, expected_local_index, description)
        (SUBTREE_DEPTH, 0, 0, "root node"),
        (SUBTREE_DEPTH + 1, 0, 1, "left child"),
        (SUBTREE_DEPTH + 1, 1, 2, "right child"),
        (SUBTREE_DEPTH + 2, 0, 3, "left grandchild"),
        (SUBTREE_DEPTH + 2, 3, 6, "right grandchild at position 3"),
        (SUBTREE_DEPTH + 7, 0, 127, "deepest left node"),
        (SUBTREE_DEPTH + 7, 127, 254, "deepest right node"),
    ];

    for (depth, value, expected_local, description) in test_cases {
        let global_idx = NodeIndex::new(depth, value).unwrap();
        let local_idx = Subtree::global_to_local(global_idx, base_idx);
        assert_eq!(
            local_idx, expected_local,
            "Failed for {description}: depth={depth}, value={value}"
        );
    }
}

/// Tests global to local index conversion with non-zero subtree root
#[test]
fn global_to_local_index_conversion_nonzero_base() {
    let base_idx = NodeIndex::new(SUBTREE_DEPTH * 2, 1).unwrap();

    let test_cases = [
        // (depth, value, expected_local_index, description)
        (SUBTREE_DEPTH * 2, 1, 0, "subtree root itself"),
        (SUBTREE_DEPTH * 2 + 1, 2, 1, "left child (2 = 1<<1 | 0)"),
        (SUBTREE_DEPTH * 2 + 1, 3, 2, "right child (3 = 1<<1 | 1)"),
    ];

    for (depth, value, expected_local, description) in test_cases {
        let global_idx = NodeIndex::new(depth, value).unwrap();
        let local_idx = Subtree::global_to_local(global_idx, base_idx);
        assert_eq!(
            local_idx, expected_local,
            "Failed for {description}: depth={depth}, value={value}"
        );
    }
}

/// Tests that global_to_local panics when global depth is less than base depth
#[test]
#[should_panic(expected = "Global depth is less than base depth")]
fn global_to_local_panics_on_invalid_depth() {
    let base_idx = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();
    let invalid_global_idx = NodeIndex::new(SUBTREE_DEPTH - 1, 0).unwrap();

    // This should panic because global depth cannot be less than base depth
    Subtree::global_to_local(invalid_global_idx, base_idx);
}

/// Tests finding subtree roots for nodes at various positions in the tree
#[test]
fn find_subtree_root_for_various_nodes() {
    // Test nodes within the first possible subtree (rooted at depth 0)
    let shallow_nodes =
        [NodeIndex::new(0, 0).unwrap(), NodeIndex::new(SUBTREE_DEPTH - 1, 0).unwrap()];

    for node_idx in shallow_nodes {
        assert_eq!(
            Subtree::find_subtree_root(node_idx),
            NodeIndex::root(),
            "Node at depth {} should belong to root subtree",
            node_idx.depth()
        );
    }

    // Test nodes in subtree rooted at (depth=SUBTREE_DEPTH, value=0)
    let subtree_0_root = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();
    let subtree_0_nodes = [
        NodeIndex::new(SUBTREE_DEPTH, 0).unwrap(),
        NodeIndex::new(SUBTREE_DEPTH + 1, 0).unwrap(),
        NodeIndex::new(SUBTREE_DEPTH + 1, 1).unwrap(),
        NodeIndex::new(SUBTREE_DEPTH * 2 - 1, (1 << (SUBTREE_DEPTH - 1)) - 1).unwrap(),
    ];

    for node_idx in subtree_0_nodes {
        assert_eq!(
            Subtree::find_subtree_root(node_idx),
            subtree_0_root,
            "Node at depth {}, value {} should belong to subtree rooted at depth {}, value 0",
            node_idx.depth(),
            node_idx.position(),
            SUBTREE_DEPTH
        );
    }

    // Test nodes in subtree rooted at (depth=SUBTREE_DEPTH, value=1)
    let subtree_1_root = NodeIndex::new(SUBTREE_DEPTH, 1).unwrap();
    let subtree_1_nodes = [
        NodeIndex::new(SUBTREE_DEPTH, 1).unwrap(),
        NodeIndex::new(SUBTREE_DEPTH + 1, 2).unwrap(),
        NodeIndex::new(SUBTREE_DEPTH + 1, 3).unwrap(),
    ];

    for node_idx in subtree_1_nodes {
        assert_eq!(
            Subtree::find_subtree_root(node_idx),
            subtree_1_root,
            "Node at depth {}, value {} should belong to subtree rooted at depth {}, value 1",
            node_idx.depth(),
            node_idx.position(),
            SUBTREE_DEPTH
        );
    }

    // Test nodes in subtree rooted at (depth=SUBTREE_DEPTH*2, value=3)
    let deep_subtree_root = NodeIndex::new(SUBTREE_DEPTH * 2, 3).unwrap();
    let deep_subtree_nodes = [
        NodeIndex::new(SUBTREE_DEPTH * 2, 3).unwrap(),
        NodeIndex::new(SUBTREE_DEPTH * 2 + 5, (3 << 5) | 17).unwrap(),
    ];

    for node_idx in deep_subtree_nodes {
        assert_eq!(
            Subtree::find_subtree_root(node_idx),
            deep_subtree_root,
            "Node at depth {}, value {} should belong to deep subtree",
            node_idx.depth(),
            node_idx.position()
        );
    }
}

#[test]
fn test_from_vec_rejects_unused_bitmask_bits() {
    let root_index = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();

    // Bits 510 and 511 are unused (only 255 nodes x 2 bits = 510 bits). Corrupted storage
    // could set these; from_vec should reject them.
    for bit in [510, 511] {
        let mut data = Vec::from(&b"SMT1"[..]);
        data.push(1);
        data.extend_from_slice(&[0u8; Subtree::BITMASK_SIZE]);
        data[5 + (bit / 8)] |= 1 << (bit % 8);

        assert!(
            matches!(
                Subtree::from_vec(root_index, &data),
                Err(super::SubtreeError::InvalidBitmask)
            ),
            "bit {bit} should be rejected"
        );
    }

    // Bit 509 is the last valid bit (node 254, right child) — should be accepted.
    let mut data = Vec::from(&b"SMT1"[..]);
    data.push(1);
    data.extend_from_slice(&[0u8; Subtree::BITMASK_SIZE]);
    data[5 + (509 / 8)] |= 1 << (509 % 8);
    data.extend_from_slice(&Word::from([99u32; 4]).as_bytes());

    assert!(Subtree::from_vec(root_index, &data).is_ok(), "bit 509 is valid");
}

#[test]
fn test_from_vec_rejects_invalid_field_element() {
    let root_index = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();

    // One hash slot with a limb >= the Goldilocks prime.
    let mut data = Vec::from(&b"SMT1"[..]);
    data.push(1);
    data.extend_from_slice(&[0u8; Subtree::BITMASK_SIZE]);
    data[5] |= 1;
    data.extend_from_slice(&u64::MAX.to_le_bytes());
    data.extend_from_slice(&[0u8; 24]);

    assert!(matches!(
        Subtree::from_vec(root_index, &data),
        Err(super::SubtreeError::InvalidHashData)
    ));
}

#[test]
fn test_from_vec_rejects_missing_magic() {
    let root_index = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();

    // Missing magic/version prefix should always be rejected.
    let mut data = vec![0u8; Subtree::BITMASK_SIZE];
    data[0] |= 1;
    data.extend_from_slice(&Word::from([42u32; 4]).as_bytes());

    assert!(matches!(
        Subtree::from_vec(root_index, &data),
        Err(super::SubtreeError::MissingFormatMagic)
    ));
}

#[test]
fn test_from_vec_rejects_unknown_version() {
    let root_index = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();

    let mut data = Vec::from(&b"SMT1"[..]);
    data.push(Subtree::FORMAT_VERSION + 1);
    data.extend_from_slice(&[0u8; Subtree::BITMASK_SIZE]);

    assert!(matches!(
        Subtree::from_vec(root_index, &data),
        Err(super::SubtreeError::UnsupportedVersion { .. })
    ));
}

#[test]
fn test_from_vec_rejects_unknown_version_with_extra_payload() {
    let root_index = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();

    let mut data = Vec::from(&b"SMT1"[..]);
    data.push(Subtree::FORMAT_VERSION + 1);
    data.extend_from_slice(&[0u8; Subtree::BITMASK_SIZE]);
    data.extend_from_slice(&Word::default().as_bytes());

    assert!(matches!(
        Subtree::from_vec(root_index, &data),
        Err(super::SubtreeError::UnsupportedVersion { .. })
    ));
}

#[test]
fn test_apply_mutations() {
    let root_index = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();
    let mut subtree = Subtree::new(root_index);

    let idx1 = NodeIndex::new(SUBTREE_DEPTH + 1, 0).unwrap();
    let idx2 = NodeIndex::new(SUBTREE_DEPTH + 1, 1).unwrap();
    let node1 = InnerNode {
        left: Word::from([1u32; 4]),
        right: Word::from([2u32; 4]),
    };
    let node2 = InnerNode {
        left: Word::from([3u32; 4]),
        right: Word::from([4u32; 4]),
    };
    subtree.insert_inner_node(idx1, node1);
    subtree.insert_inner_node(idx2, node2.clone());
    assert_eq!(subtree.len(), 2);

    // Empty batch should be a no-op
    let empty: [(&NodeIndex, &NodeMutation); 0] = [];
    assert_eq!(subtree.would_patch_in_place(empty), None);
    subtree.apply_mutations(empty);
    assert_eq!(subtree.len(), 2);

    // Update node1 with different hashes but same structure (both children still non-empty).
    // This should take the patch-in-place path.
    let node1_updated = InnerNode {
        left: Word::from([10u32; 4]),
        right: Word::from([20u32; 4]),
    };
    let mutation = NodeMutation::Addition(node1_updated.clone());
    assert_eq!(subtree.would_patch_in_place([(&idx1, &mutation)]), Some(true));
    subtree.apply_mutations([(&idx1, &mutation)]);

    assert_eq!(subtree.len(), 2);
    assert_eq!(subtree.get_inner_node(idx1), Some(node1_updated));
    assert_eq!(subtree.get_inner_node(idx2), Some(node2.clone()));

    // Mixed batch: remove node1, add node3. This changes structure, triggering a rebuild.
    let idx3 = NodeIndex::new(SUBTREE_DEPTH + 2, 2).unwrap();
    let node3 = InnerNode {
        left: Word::from([5u32; 4]),
        right: Word::from([6u32; 4]),
    };
    let removal = NodeMutation::Removal;
    let addition = NodeMutation::Addition(node3.clone());
    assert_eq!(
        subtree.would_patch_in_place([(&idx1, &removal), (&idx3, &addition)]),
        Some(false)
    );
    subtree.apply_mutations([(&idx1, &removal), (&idx3, &addition)]);

    assert!(subtree.get_inner_node(idx1).is_none(), "node1 should be removed");
    assert_eq!(subtree.get_inner_node(idx2), Some(node2), "node2 should be unchanged");
    assert_eq!(subtree.get_inner_node(idx3), Some(node3));
    assert_eq!(subtree.len(), 2);

    // Remove remaining nodes to verify we get back to empty
    let r1 = NodeMutation::Removal;
    let r2 = NodeMutation::Removal;
    subtree.apply_mutations([(&idx2, &r1), (&idx3, &r2)]);
    assert!(subtree.is_empty());

    // Verify round-trip serialization on the emptied subtree
    let serialized = subtree.to_vec();
    let deserialized = Subtree::from_vec(root_index, &serialized).unwrap();
    assert!(deserialized.is_empty());
}

#[test]
fn test_apply_mutations_dedupes_duplicate_indices() {
    let root_index = NodeIndex::new(SUBTREE_DEPTH, 0).unwrap();
    let mut subtree = Subtree::new(root_index);

    let idx1 = NodeIndex::new(SUBTREE_DEPTH + 1, 0).unwrap();
    let idx2 = NodeIndex::new(SUBTREE_DEPTH + 1, 1).unwrap();
    let node1 = InnerNode {
        left: Word::from([1u32; 4]),
        right: Word::from([2u32; 4]),
    };
    let node2 = InnerNode {
        left: Word::from([3u32; 4]),
        right: Word::from([4u32; 4]),
    };
    subtree.insert_inner_node(idx1, node1);
    subtree.insert_inner_node(idx2, node2.clone());

    let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, idx1.depth() + 1);
    let left_only = InnerNode {
        left: Word::from([10u32; 4]),
        right: empty_hash,
    };
    let right_only = InnerNode {
        left: empty_hash,
        right: Word::from([20u32; 4]),
    };

    let m1 = NodeMutation::Addition(left_only);
    let m2 = NodeMutation::Addition(right_only.clone());
    subtree.apply_mutations([(&idx1, &m1), (&idx1, &m2)]);

    assert_eq!(subtree.get_inner_node(idx1), Some(right_only));
    assert_eq!(subtree.get_inner_node(idx2), Some(node2));
    assert_eq!(subtree.len(), 2);
}
