#![cfg(test)]
//! Handwritten tests for partial SMT serialization.

use alloc::collections::BTreeMap;

use miden_field::{Felt, Word};
use miden_serde_utils::{Deserializable, Serializable};

use crate::merkle::{
    EmptySubtreeRoots, NodeIndex,
    smt::{LeafIndex, SMT_DEPTH, SmtLeaf, UniqueNodes},
};

/// Hand-writes a UniqueNodes payload: root, then `levels` as (depth, [(position, value)])
/// with an explicit depth per level and per-node values, then an empty leaf section and
/// an empty value-only section.
fn write_nodes_payload(levels: &[(u8, &[(u64, Word)])], target: &mut alloc::vec::Vec<u8>) {
    use miden_serde_utils::ByteWriter;

    Word::default().write_into(target); // expected root
    target.write_u64(levels.len() as u64);
    for (depth, nodes) in levels {
        target.write_u8(*depth);
        target.write_u64(nodes.len() as u64);
        for (position, value) in nodes.iter().copied() {
            target.write_u64(position);
            value.write_into(target);
        }
    }
    target.write_u64(0); // leaf count
    target.write_u64(0); // value-only leaf count
}

/// Reported decoder gap (partial-SMT UniqueNodes wire format), part 1: a node position repeated
/// WITHIN one level is silently overwritten (last value wins) instead of rejected — the same
/// hand-written-payload class upstream #3900 fixed for AdviceMap. The two entries carry
/// DISTINCT nonzero values so the assertion distinguishes overwrite from keep-first and
/// from zeroing. `write_into` can never produce this payload (the BTreeMap source cannot
/// hold duplicate keys). This fixture pins the defect's observable; it flips to a
/// rejection assertion when the fix lands.
#[test]
fn duplicate_node_position_in_a_level_is_silently_overwritten() {
    let first_value = Word::new([Felt::new_unchecked(0x6700_0000_0000_0001); 4]);
    let second_value = Word::new([Felt::new_unchecked(0x6700_0000_0000_0002); 4]);
    let mut bytes = alloc::vec::Vec::new();
    write_nodes_payload(&[(1, &[(1, first_value), (1, second_value)])], &mut bytes);

    let decoded = UniqueNodes::read_from_bytes(&bytes)
        .expect("the reported defect: a repeated node position decodes successfully");
    let node = decoded.nodes.get(&NodeIndex::new(1, 1).unwrap()).unwrap();
    assert_eq!(node, &second_value, "the LAST duplicate wins");
    assert_ne!(node, &first_value, "keep-first must not pass");
}

/// Reported decoder gap (partial-SMT UniqueNodes wire format), part 2: the reader does not require
/// the wire's levels to be in ascending depth order (the writer's BTreeMap order), so the same
/// node set has MULTIPLE valid byte encodings — the wire form is not uniquely decodable
/// and the decoder accepts reorderings the writer can never produce.
#[test]
fn levels_in_descending_order_are_accepted() {
    let mut bytes = alloc::vec::Vec::new();
    // The writer emits ascending depths; this payload is the reverse.
    let word_at = |i: u64| Word::new([Felt::new_unchecked(0x6700_0000_0000_0000 + i); 4]);
    write_nodes_payload(&[(2, &[(1, word_at(1))]), (1, &[(1, word_at(2))])], &mut bytes);

    UniqueNodes::read_from_bytes(&bytes)
        .expect("the reported defect: descending depth levels decode successfully");
}

/// Reported decoder gap (partial-SMT UniqueNodes wire format), part 3 (CONFIRMED): a position
/// present in BOTH `leaves` and `value_only_leaves` decodes successfully, and `get_leaf_hash`
/// silently shadows the value-only entry with the leaf's hash (leaves take priority via
/// `.or_else`). The construction path can never produce the overlap — a position becomes
/// either a leaf or a value-only entry, exclusively — so the ambiguity is
/// writer-unproducible but decoder-accepted. Flips to a rejection assertion when the fix
/// lands.
#[test]
fn position_in_leaves_and_value_only_leaves_is_accepted_and_shadowed() {
    use miden_serde_utils::ByteWriter;

    // A POPULATED leaf: its hash differs from EMPTY_WORD (the missing-leaf fallback), so
    // the shadowing assertion cannot pass under a get_leaf_hash that ignores both maps.
    let key = Word::new([Felt::new_unchecked(0x6700_0000_0000_0009); 4]);
    let leaf_value = Word::new([Felt::new_unchecked(0x6700_0000_0000_000a); 4]);
    let leaf_index = LeafIndex::<SMT_DEPTH>::from(key);
    let leaf = SmtLeaf::new(vec![(key, leaf_value)], leaf_index).expect("populated leaf is valid");
    let position = leaf_index.position();
    let shadowed_value = Word::new([Felt::new_unchecked(0x6700_0000_0000_0003); 4]);

    let mut bytes = alloc::vec::Vec::new();
    Word::default().write_into(&mut bytes); // expected root
    bytes.write_u64(0); // level count
    bytes.write_u64(1); // leaf count
    position.write_into(&mut bytes); // the leaf section's position field
    leaf.write_into(&mut bytes); // num_entries + embedded leaf index + entries
    bytes.write_u64(1); // value-only leaf count
    position.write_into(&mut bytes);
    shadowed_value.write_into(&mut bytes);

    let decoded = UniqueNodes::read_from_bytes(&bytes)
        .expect("the reported defect: an overlapped position decodes successfully");

    // The exact decoded state in both maps.
    assert_eq!(decoded.leaves.get(&position), Some(&leaf), "leaf present verbatim");
    assert_eq!(
        decoded.value_only_leaves.get(&position),
        Some(&shadowed_value),
        "value-only entry present for the SAME position",
    );

    // leaves take priority: the lookup returns the POPULATED leaf's hash, which differs
    // from both EMPTY_WORD (the missing-leaf fallback) and the shadowed value — so this
    // assertion establishes leaves-first selection, not just overlap acceptance.
    assert_ne!(leaf.hash(), Word::default(), "populated leaf must not hash to EMPTY_WORD");
    assert_eq!(
        decoded.get_leaf_hash(position),
        leaf.hash(),
        "the leaf silently shadows the value-only entry",
    );
    assert_ne!(decoded.get_leaf_hash(position), shadowed_value);
    assert_ne!(decoded.get_leaf_hash(position), Word::default());
}

#[test]
fn empty_unique_nodes_roundtrips() {
    let value = UniqueNodes::empty();
    assert_eq!(UniqueNodes::read_from_bytes(&value.to_bytes()), Ok(value));
}

#[test]
fn unique_nodes_roundtrips() {
    // The roundtrip oracle over this shape is subsumed by the 50-case
    // property in property_tests.rs; this fixture pins the specific edge
    // indices (max-depth leaf, deep node) with patterned don't-care values.
    let patterned = |i: u64| Felt::new_unchecked(0x6700_0000_0000_0000 + i);
    let node_word =
        |i: u64| Word::new([patterned(i), patterned(i + 40), patterned(i + 41), patterned(i + 42)]);
    let nodes = [
        (NodeIndex::new(6, 8).unwrap(), node_word(1)),
        (NodeIndex::new(6, 63).unwrap(), node_word(2)),
        (NodeIndex::new(61, 2u64.pow(58) + 31).unwrap(), node_word(3)),
    ]
    .into_iter()
    .collect();

    let leaf_1_index = u64::MAX;
    let leaf_1_value = SmtLeaf::new_empty(LeafIndex::new_max_depth(leaf_1_index));
    let leaf_2_value = SmtLeaf::new_single(
        Word::new([patterned(4), patterned(5), patterned(16), patterned(17)]),
        Word::new([patterned(18), patterned(19), patterned(20), patterned(21)]),
    );
    let leaf_2_index = leaf_2_value.index().position();
    let leaf_index: Felt = patterned(6);
    let leaf_3_value = SmtLeaf::new_multiple(vec![
        (
            Word::new([patterned(7), patterned(8), patterned(9), leaf_index]),
            Word::new([patterned(10), patterned(22), patterned(23), patterned(24)]),
        ),
        (
            Word::new([patterned(11), patterned(12), patterned(13), leaf_index]),
            Word::new([patterned(14), patterned(25), patterned(26), patterned(27)]),
        ),
    ])
    .unwrap();
    let leaf_3_index = leaf_3_value.index().position();

    let mut value = UniqueNodes::empty();
    value.root = Word::new([patterned(15), patterned(28), patterned(29), patterned(30)]);
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
