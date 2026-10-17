#![cfg(test)]
//! Handwritten tests for partial SMT serialization.

use alloc::{collections::BTreeMap, vec::Vec};

use miden_field::{Felt, Word};
use miden_serde_utils::{Deserializable, DeserializationError, Serializable};

use crate::merkle::{
    EmptySubtreeRoots, NodeIndex, SparseMerklePath,
    smt::{LeafIndex, PartialSmt, SMT_DEPTH, Smt, SmtLeaf, SmtProof, SmtWitness, UniqueNodes},
    store::MerkleStore,
};

/// Hand-writes a UniqueNodes payload: root, then `levels` as (depth, [(position, value)])
/// with an explicit depth per level and per-node values, then an empty leaf section and
/// an empty value-only section.
fn write_nodes_payload(levels: &[(u8, &[(u64, Word)])], target: &mut Vec<u8>) {
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

/// Duplicate entries must be rejected before either value can replace the other.
#[test]
fn duplicate_node_position_in_a_level_is_rejected() {
    let first_value = Word::new([Felt::new_unchecked(0x6700_0000_0000_0001); 4]);
    let second_value = Word::new([Felt::new_unchecked(0x6700_0000_0000_0002); 4]);
    let mut bytes = Vec::new();
    write_nodes_payload(&[(1, &[(1, first_value), (1, second_value)])], &mut bytes);

    assert_eq!(
        UniqueNodes::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(
            "Duplicate node position 1 at depth 1".into()
        ))
    );
}

/// The writer emits levels in strictly increasing depth order.
#[test]
fn levels_in_descending_order_are_rejected() {
    let mut bytes = Vec::new();
    // The writer emits ascending depths; this payload is the reverse.
    let word_at = |i: u64| Word::new([Felt::new_unchecked(0x6700_0000_0000_0000 + i); 4]);
    write_nodes_payload(&[(2, &[(1, word_at(1))]), (1, &[(1, word_at(2))])], &mut bytes);

    assert_eq!(
        UniqueNodes::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(
            "Level depth 1 does not exceed previous depth 2".into()
        ))
    );
}

/// A position must identify either a leaf or its hash alone.
#[test]
fn position_in_leaves_and_value_only_leaves_is_rejected() {
    use miden_serde_utils::ByteWriter;

    let key = Word::new([Felt::new_unchecked(0x6700_0000_0000_0009); 4]);
    let leaf_value = Word::new([Felt::new_unchecked(0x6700_0000_0000_000a); 4]);
    let leaf_index = LeafIndex::<SMT_DEPTH>::from(key);
    let leaf = SmtLeaf::new(vec![(key, leaf_value)], leaf_index).expect("populated leaf is valid");
    let position = leaf_index.position();
    let shadowed_value = Word::new([Felt::new_unchecked(0x6700_0000_0000_0003); 4]);

    let mut bytes = Vec::new();
    Word::default().write_into(&mut bytes); // expected root
    bytes.write_u64(0); // level count
    bytes.write_u64(1); // leaf count
    position.write_into(&mut bytes); // the leaf section's position field
    leaf.write_into(&mut bytes); // num_entries + embedded leaf index + entries
    bytes.write_u64(1); // value-only leaf count
    position.write_into(&mut bytes);
    shadowed_value.write_into(&mut bytes);

    assert_eq!(
        UniqueNodes::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(format!(
            "Leaf position {position} appears in both leaf maps"
        )))
    );
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
    use miden_serde_utils::ByteWriter;

    let mut bytes = Vec::new();
    UniqueNodes::empty().root.write_into(&mut bytes);
    bytes.write_u64(0);
    bytes.write_u64(1);
    (8u64, leaf).write_into(&mut bytes);
    bytes.write_u64(0);
    assert_eq!(
        UniqueNodes::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(
            "Node index 8 did not match the embedded leaf index 7".into()
        ))
    );
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

#[test]
fn smt_witness_preserves_openings_and_updates() {
    let key =
        |position| Word::new([crate::ONE, crate::ZERO, crate::ZERO, Felt::new_unchecked(position)]);
    let value = Word::from([5, 6, 7, 8u32]);
    for positions in [
        vec![],
        vec![7],
        (0..16).collect(),
        (0..16).map(|i| i * (u64::MAX / 17)).collect(),
    ] {
        let mut full = Smt::with_entries(positions.iter().map(|&p| (key(p), value))).unwrap();
        let mut keys: Vec<_> = positions.into_iter().map(key).collect();
        keys.push(key(31)); // An exclusion proof, including the entirely empty tree case.
        let partial = PartialSmt::from_proofs(keys.iter().map(|key| full.open(key))).unwrap();
        let bytes = SmtWitness::from(&partial).to_bytes();
        let mut decoded = SmtWitness::read_from_bytes_with_budget(&bytes, bytes.len())
            .unwrap()
            .into_partial_smt(4096)
            .unwrap();
        assert_eq!(partial, decoded);

        let mut store: MerkleStore = decoded.inner_nodes().collect();
        for key in &keys {
            assert_eq!(decoded.get_value(key).unwrap(), full.get_value(key));
            let index = NodeIndex::from(LeafIndex::<SMT_DEPTH>::from(*key));
            assert_eq!(
                store.get_path(full.root(), index).unwrap().path,
                full.open(key).path().clone()
            );
        }

        // Check both update APIs against a full tree, not against another deserialization.
        let updated_key = *keys.last().unwrap();
        let index = NodeIndex::from(LeafIndex::<SMT_DEPTH>::from(updated_key));
        let old_root = full.root();
        let new_value = Word::from([11, 12, 13, 14u32]);
        full.insert(updated_key, new_value).unwrap();
        decoded.insert(updated_key, new_value).unwrap();
        assert_eq!(decoded.root(), full.root());
        assert_eq!(
            store
                .set_node(old_root, index, full.get_leaf(&updated_key).hash())
                .unwrap()
                .root,
            full.root()
        );
    }
}

/// Independent encoder for malformed inputs and the one-position-per-leaf wire contract.
fn witness_payload(
    root: Word,
    nodes: &[(NodeIndex, Word)],
    leaves: &[SmtLeaf],
    hashes: &[(u64, Word)],
) -> Vec<u8> {
    use miden_serde_utils::ByteWriter;

    let mut bytes = Vec::from(*b"SMTWITNS");
    bytes.write_u8(1);
    root.write_into(&mut bytes);
    bytes.write_usize(nodes.len());
    bytes.write_many(nodes);
    bytes.write_usize(leaves.len());
    bytes.write_many(leaves);
    bytes.write_usize(hashes.len());
    bytes.write_many(hashes);
    bytes
}

#[test]
fn smt_witness_writes_leaf_positions_once_and_bounds_shared_reconstruction() {
    let entries = [
        (Word::from([1, 2, 3, 0u32]), Word::from([4, 5, 6, 7u32])),
        (Word::from([8, 9, 10, 2u32]), Word::from([11, 12, 13, 14u32])),
    ];
    let full = Smt::with_entries(entries).unwrap();
    let partial = PartialSmt::from_proofs(entries.iter().map(|(key, _)| full.open(key))).unwrap();
    let leaves: Vec<_> = partial.leaves().map(|(_, leaf)| leaf.clone()).collect();
    let bytes = SmtWitness::from(&partial).to_bytes();
    assert_eq!(bytes, witness_payload(full.root(), &[], &leaves, &[]));
    assert_eq!(bytes.len(), 8 + 1 + 32 + 3 + 2 * (1 + 8 + 64));
    // Positions 0 and 2 require two bottom parents and 63 shared ancestors: 65, not 128.
    assert_eq!(SmtWitness::read_from_bytes(&bytes).unwrap().into_partial_smt(65), Ok(partial));
    assert!(SmtWitness::read_from_bytes(&bytes).unwrap().into_partial_smt(64).is_err());

    // Empty parents still cost reconstruction work, even though PartialSmt does not retain them.
    let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let bytes =
        witness_payload(empty_root, &[], &[SmtLeaf::new_empty(LeafIndex::new_max_depth(7))], &[]);
    assert!(SmtWitness::read_from_bytes(&bytes).unwrap().into_partial_smt(63).is_err());
    assert_eq!(
        SmtWitness::read_from_bytes(&bytes)
            .unwrap()
            .into_partial_smt(64)
            .unwrap()
            .root(),
        empty_root
    );
}

#[test]
fn smt_witness_rejects_invalid_wire_data_and_corrupt_roots() {
    use miden_serde_utils::ByteWriter;

    let root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let leaf = SmtLeaf::new_empty(LeafIndex::new_max_depth(7));
    let value = Word::from([1, 2, 3, 4u32]);
    let node = NodeIndex::new(3, 2).unwrap();
    for bytes in [
        witness_payload(root, &[(node, value), (node, value)], &[], &[]),
        witness_payload(root, &[(node, value), (NodeIndex::new(2, 0).unwrap(), value)], &[], &[]),
        witness_payload(root, &[], &[leaf.clone(), leaf.clone()], &[]),
        witness_payload(
            root,
            &[],
            &[leaf.clone(), SmtLeaf::new_empty(LeafIndex::new_max_depth(3))],
            &[],
        ),
        witness_payload(root, &[], core::slice::from_ref(&leaf), &[(7, value)]),
        witness_payload(root, &[], &[], &[(7, value), (7, value)]),
        witness_payload(root, &[], &[], &[(7, value), (3, value)]),
        witness_payload(root, &[(NodeIndex::new(0, 0).unwrap(), value)], &[], &[]),
        witness_payload(root, &[(NodeIndex::new(64, 7).unwrap(), value)], &[], &[]),
    ] {
        assert!(SmtWitness::read_from_bytes_with_budget(&bytes, bytes.len()).is_err());
    }

    let bytes = witness_payload(root, &[], &[leaf], &[]);
    for end in 0..bytes.len() {
        assert!(SmtWitness::read_from_bytes(&bytes[..end]).is_err());
    }
    assert!(SmtWitness::read_from_bytes_with_budget(&bytes, bytes.len() - 1).is_err());
    let mut corrupt = bytes.clone();
    corrupt[8] = 2;
    assert!(SmtWitness::read_from_bytes(&corrupt).is_err());
    assert!(SmtWitness::read_from_bytes(&PartialSmt::default().to_bytes()).is_err());
    let mut corrupt = bytes.clone();
    corrupt[9..41].copy_from_slice(&value.to_bytes());
    assert!(SmtWitness::read_from_bytes(&corrupt).unwrap().into_partial_smt(64).is_err());

    let mut oversized = bytes[..41].to_vec();
    oversized.write_usize(usize::MAX);
    assert!(SmtWitness::read_from_bytes_with_budget(&oversized, oversized.len()).is_err());
}

#[test]
fn smt_witness_rejects_frontier_nodes_masking_forged_empty_openings() {
    let key = Word::from([1, 2, 3, 7u32]);
    let full = Smt::with_entries([(key, Word::from([4, 5, 6, 8u32]))]).unwrap();
    let store: MerkleStore = full.inner_nodes().collect();
    let leaf = SmtLeaf::new_empty(LeafIndex::new_max_depth(7));
    let lower = NodeIndex::new(63, 3).unwrap();
    let upper = lower.parent();
    let lower_hash = store.get_node(full.root(), lower).unwrap();
    let upper_hash = store.get_node(full.root(), upper).unwrap();

    // A frontier hash alone authenticates the subtree, but not a value inside it.
    let bytes = witness_payload(full.root(), &[(lower, lower_hash)], &[], &[]);
    let partial = SmtWitness::read_from_bytes(&bytes).unwrap().into_partial_smt(64).unwrap();
    assert_eq!(partial.root(), full.root());
    assert!(partial.get_value(&key).is_err());

    // The genuine ancestor hash must not mask a forged empty complete leaf, hash-only leaf,
    // or frontier descendant after the reconstructed empty parent is discarded.
    for (bytes, expected) in [
        (
            witness_payload(full.root(), &[(lower, lower_hash)], core::slice::from_ref(&leaf), &[]),
            "SMT frontier node at depth 63 position 3 overlaps a descendant",
        ),
        (
            witness_payload(full.root(), &[(lower, lower_hash)], &[], &[(7, leaf.hash())]),
            "SMT frontier node at depth 63 position 3 overlaps a descendant",
        ),
        (
            witness_payload(
                full.root(),
                &[(upper, upper_hash), (lower, *EmptySubtreeRoots::entry(SMT_DEPTH, 63))],
                &[],
                &[],
            ),
            "SMT frontier node at depth 62 position 1 overlaps a descendant",
        ),
    ] {
        let witness = SmtWitness::read_from_bytes(&bytes).unwrap();
        assert_eq!(
            witness.into_partial_smt(128),
            Err(DeserializationError::InvalidValue(expected.into()))
        );
    }
}

#[test]
fn budgeted_collections_accept_compact_empty_transports() {
    type Transports = (SparseMerklePath, SmtProof, UniqueNodes, PartialSmt, SmtWitness);

    let partial = PartialSmt::default();
    let values: Vec<Transports> = vec![(
        SparseMerklePath::default(),
        Smt::default().open(&Word::default()),
        UniqueNodes::empty(),
        partial.clone(),
        SmtWitness::from(&partial),
    )];
    let bytes = values.to_bytes();
    assert_eq!(Vec::<Transports>::read_from_bytes_with_budget(&bytes, bytes.len()), Ok(values));
    assert!(Vec::<Transports>::read_from_bytes_with_budget(&bytes, bytes.len() - 1).is_err());
}
