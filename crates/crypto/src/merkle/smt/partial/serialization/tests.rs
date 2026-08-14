#![cfg(test)]
//! Handwritten tests for partial SMT serialization.

use alloc::collections::BTreeMap;

use miden_field::{Felt, Word};
use miden_serde_utils::{Deserializable, Serializable};

use crate::{
    merkle::{
        EmptySubtreeRoots, NodeIndex,
        smt::{LeafIndex, SMT_DEPTH, SmtLeaf, UniqueNodes},
    },
    rand::test_utils::ContinuousRng,
};

#[test]
fn empty_unique_nodes_roundtrips() {
    let value = UniqueNodes::empty();
    assert_eq!(UniqueNodes::read_from_bytes(&value.to_bytes()), Ok(value));
}

#[test]
fn unique_nodes_roundtrips() {
    let mut rng = ContinuousRng::new([0x67; 32]);
    let nodes = [
        (NodeIndex::new(6, 8).unwrap(), rng.value()),
        (NodeIndex::new(6, 63).unwrap(), rng.value()),
        (NodeIndex::new(61, 2u64.pow(58) + 31).unwrap(), rng.value()),
    ]
    .into_iter()
    .collect();

    let leaf_1_index = u64::MAX;
    let leaf_1_value = SmtLeaf::new_empty(LeafIndex::new_max_depth(leaf_1_index));
    let leaf_2_value = SmtLeaf::new_single(rng.value(), rng.value());
    let leaf_2_index = leaf_2_value.index().position();
    let leaf_index: Felt = rng.value();
    let leaf_3_value = SmtLeaf::new_multiple(vec![
        (Word::new([rng.value(), rng.value(), rng.value(), leaf_index]), rng.value()),
        (Word::new([rng.value(), rng.value(), rng.value(), leaf_index]), rng.value()),
    ])
    .unwrap();
    let leaf_3_index = leaf_3_value.index().position();

    let mut value = UniqueNodes::empty();
    value.root = rng.value();
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
