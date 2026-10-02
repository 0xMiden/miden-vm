#![cfg(test)]
//! Handwritten tests for partial SMT serialization.

use alloc::{collections::BTreeMap, vec::Vec};

use miden_field::{Felt, Word};
use miden_serde_utils::{ByteWriter, Deserializable, Serializable};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::merkle::{
    EmptySubtreeRoots, NodeIndex,
    smt::{LeafIndex, SMT_DEPTH, SmtLeaf, UniqueNodes},
};

fn write_unique_nodes_payload(
    levels: &[(u8, &[(u64, Word)])],
    leaves: &[(u64, SmtLeaf)],
    value_only_leaves: &[(u64, Word)],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    Word::default().write_into(&mut bytes);

    bytes.write_u64(levels.len() as u64);
    for (depth, nodes) in levels {
        bytes.write_u8(*depth);
        bytes.write_u64(nodes.len() as u64);
        for (position, value) in *nodes {
            bytes.write_u64(*position);
            value.write_into(&mut bytes);
        }
    }

    bytes.write_u64(leaves.len() as u64);
    for (position, leaf) in leaves {
        bytes.write_u64(*position);
        leaf.write_into(&mut bytes);
    }

    bytes.write_u64(value_only_leaves.len() as u64);
    for (position, value) in value_only_leaves {
        bytes.write_u64(*position);
        value.write_into(&mut bytes);
    }

    bytes
}

#[test]
fn empty_unique_nodes_roundtrips() {
    let value = UniqueNodes::empty();
    assert_eq!(UniqueNodes::read_from_bytes(&value.to_bytes()), Ok(value));
}

#[test]
fn unique_nodes_roundtrips() {
    let mut rng = ChaCha20Rng::from_seed([0x67; 32]);
    let nodes = [
        (NodeIndex::new(6, 8).unwrap(), rng.random()),
        (NodeIndex::new(6, 63).unwrap(), rng.random()),
        (NodeIndex::new(61, 2u64.pow(58) + 31).unwrap(), rng.random()),
    ]
    .into_iter()
    .collect();

    let leaf_1_index = u64::MAX;
    let leaf_1_value = SmtLeaf::new_empty(LeafIndex::new_max_depth(leaf_1_index));
    let leaf_2_value = SmtLeaf::new_single(rng.random(), rng.random());
    let leaf_2_index = leaf_2_value.index().position();
    let leaf_index: Felt = rng.random();
    let leaf_3_value = SmtLeaf::new_multiple(vec![
        (Word::new([rng.random(), rng.random(), rng.random(), leaf_index]), rng.random()),
        (Word::new([rng.random(), rng.random(), rng.random(), leaf_index]), rng.random()),
    ])
    .unwrap();
    let leaf_3_index = leaf_3_value.index().position();

    let mut value = UniqueNodes::empty();
    value.root = rng.random();
    value.nodes = nodes;
    value.leaves = [
        (leaf_1_index, leaf_1_value),
        (leaf_2_index, leaf_2_value),
        (leaf_3_index, leaf_3_value),
    ]
    .into_iter()
    .collect();

    assert_eq!(UniqueNodes::read_from_bytes(&value.to_bytes()), Ok(value));
}

#[test]
fn unique_nodes_rejects_mismatched_leaf_position() {
    let leaf = SmtLeaf::new_empty(LeafIndex::new_max_depth(7));
    let mut value = UniqueNodes::empty();
    value.leaves.insert(8, leaf);

    assert!(UniqueNodes::read_from_bytes(&value.to_bytes()).is_err());
}

#[test]
fn unique_nodes_rejects_duplicate_node_positions() {
    let nodes = [(1, Word::default()), (1, Word::from([1, 2, 3, 4u32]))];
    let bytes = write_unique_nodes_payload(&[(2, &nodes)], &[], &[]);

    assert!(UniqueNodes::read_from_bytes(&bytes).is_err());
}

#[test]
fn unique_nodes_rejects_non_ascending_node_positions() {
    let nodes = [(2, Word::default()), (1, Word::default())];
    let bytes = write_unique_nodes_payload(&[(3, &nodes)], &[], &[]);

    assert!(UniqueNodes::read_from_bytes(&bytes).is_err());
}

#[test]
fn unique_nodes_rejects_non_ascending_levels() {
    let first_level = [(0, Word::default())];
    let second_level = [(0, Word::default())];
    let bytes = write_unique_nodes_payload(&[(3, &first_level), (2, &second_level)], &[], &[]);

    assert!(UniqueNodes::read_from_bytes(&bytes).is_err());
}

#[test]
fn unique_nodes_rejects_empty_levels() {
    let empty_level: [(u64, Word); 0] = [];
    let bytes = write_unique_nodes_payload(&[(1, &empty_level)], &[], &[]);

    assert!(UniqueNodes::read_from_bytes(&bytes).is_err());
}

#[test]
fn unique_nodes_rejects_non_ascending_leaf_positions() {
    let leaves = [
        (8, SmtLeaf::new_empty(LeafIndex::new_max_depth(8))),
        (7, SmtLeaf::new_empty(LeafIndex::new_max_depth(7))),
    ];
    let bytes = write_unique_nodes_payload(&[], &leaves, &[]);

    assert!(UniqueNodes::read_from_bytes(&bytes).is_err());
}

#[test]
fn unique_nodes_rejects_non_ascending_value_only_leaf_positions() {
    let value_only_leaves = [(8, Word::default()), (7, Word::default())];
    let bytes = write_unique_nodes_payload(&[], &[], &value_only_leaves);

    assert!(UniqueNodes::read_from_bytes(&bytes).is_err());
}

#[test]
fn unique_nodes_rejects_overlapping_leaf_representations() {
    let position = 7;
    let leaves = [(position, SmtLeaf::new_empty(LeafIndex::new_max_depth(position)))];
    let value_only_leaves = [(position, Word::default())];
    let bytes = write_unique_nodes_payload(&[], &leaves, &value_only_leaves);

    assert!(UniqueNodes::read_from_bytes(&bytes).is_err());
}

#[test]
fn missing_entries_return_canonical_empty_hashes() {
    let value = UniqueNodes::empty();
    let leaf_position = 42;
    let node_index = NodeIndex::new(12, 3).unwrap();

    assert_eq!(
        value.get_leaf_hash(leaf_position),
        SmtLeaf::new_empty(LeafIndex::new_max_depth(leaf_position)).hash()
    );
    assert_eq!(
        value.get_node_hash(node_index),
        *EmptySubtreeRoots::entry(SMT_DEPTH, node_index.depth())
    );
}

#[test]
fn serialization_is_independent_of_insertion_order() {
    let entries = [
        (NodeIndex::new(8, 4).unwrap(), Word::from([1, 2, 3, 4u32])),
        (NodeIndex::new(3, 1).unwrap(), Word::from([5, 6, 7, 8u32])),
    ];
    let forward = entries.into_iter().collect::<BTreeMap<_, _>>();
    let reverse = entries.into_iter().rev().collect::<BTreeMap<_, _>>();

    let mut left = UniqueNodes::empty();
    left.nodes = forward;
    let mut right = UniqueNodes::empty();
    right.nodes = reverse;

    assert_eq!(left.to_bytes(), right.to_bytes());
}
