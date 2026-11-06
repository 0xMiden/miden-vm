use miden_crypto::{
    Felt, Word,
    merkle::smt::{LeafIndex, SMT_DEPTH, SmtLeaf, UniqueNodes},
    utils::{Deserializable, DeserializationError, Serializable},
};

/// Hand-writes a UniqueNodes payload: root, then `levels` as (depth, [(position, value)])
/// with an explicit depth per level and per-node values, then an empty leaf section and
/// an empty value-only section.
fn write_nodes_payload(levels: &[(u8, &[(u64, Word)])], target: &mut Vec<u8>) {
    use miden_crypto::utils::ByteWriter;

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
    use miden_crypto::utils::ByteWriter;

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
fn repeated_level_depth_is_rejected() {
    let mut bytes = Vec::new();
    let value = Word::new([Felt::from(1u32); 4]);
    write_nodes_payload(&[(1, &[(0, value)]), (1, &[(1, value)])], &mut bytes);
    assert_eq!(
        UniqueNodes::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(
            "Level depth 1 does not exceed previous depth 1".into()
        ))
    );
}

#[test]
fn duplicate_leaf_positions_are_rejected() {
    use miden_crypto::utils::ByteWriter;

    let key = Word::new([Felt::from(7u32); 4]);
    let position = LeafIndex::<SMT_DEPTH>::from(key).position();
    let first = SmtLeaf::new_single(key, Word::new([Felt::from(1u32); 4]));
    let second = SmtLeaf::new_single(key, Word::new([Felt::from(2u32); 4]));
    let mut bytes = Vec::new();
    Word::default().write_into(&mut bytes);
    bytes.write_u64(0);
    bytes.write_u64(2);
    (position, first).write_into(&mut bytes);
    (position, second).write_into(&mut bytes);
    bytes.write_u64(0);
    assert_eq!(
        UniqueNodes::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(format!(
            "Duplicate leaf position {position}"
        )))
    );
}

#[test]
fn duplicate_value_only_leaf_positions_are_rejected() {
    use miden_crypto::utils::ByteWriter;

    let mut bytes = Vec::new();
    Word::default().write_into(&mut bytes);
    bytes.write_u64(0);
    bytes.write_u64(0);
    bytes.write_u64(2);
    (17u64, Word::new([Felt::from(1u32); 4])).write_into(&mut bytes);
    (17u64, Word::new([Felt::from(2u32); 4])).write_into(&mut bytes);
    assert_eq!(
        UniqueNodes::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(
            "Duplicate value-only leaf position 17".into()
        ))
    );
}

#[test]
fn empty_node_level_is_rejected() {
    let mut bytes = Vec::new();
    write_nodes_payload(&[(1, &[])], &mut bytes);
    assert_eq!(
        UniqueNodes::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue("Empty node level at depth 1".into()))
    );
}

#[test]
fn descending_node_positions_are_rejected() {
    let value = Word::from([1, 2, 3, 4u32]);
    let mut bytes = Vec::new();
    write_nodes_payload(&[(1, &[(1, value), (0, value)])], &mut bytes);
    assert_eq!(
        UniqueNodes::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(
            "Node position 0 precedes 1 at depth 1".into()
        ))
    );
}

#[test]
fn descending_leaf_positions_are_rejected() {
    use miden_crypto::utils::ByteWriter;

    let mut bytes = Vec::new();
    Word::default().write_into(&mut bytes);
    bytes.write_u64(0);
    bytes.write_u64(2);
    (2u64, SmtLeaf::new_empty(LeafIndex::new_max_depth(2))).write_into(&mut bytes);
    (1u64, SmtLeaf::new_empty(LeafIndex::new_max_depth(1))).write_into(&mut bytes);
    bytes.write_u64(0);
    assert_eq!(
        UniqueNodes::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue("Leaf position 1 precedes 2".into()))
    );
}

#[test]
fn descending_value_only_leaf_positions_are_rejected() {
    use miden_crypto::utils::ByteWriter;

    let mut bytes = Vec::new();
    Word::default().write_into(&mut bytes);
    bytes.write_u64(0);
    bytes.write_u64(0);
    bytes.write_u64(2);
    let value = Word::from([1, 2, 3, 4u32]);
    (2u64, value).write_into(&mut bytes);
    (1u64, value).write_into(&mut bytes);
    assert_eq!(
        UniqueNodes::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(
            "Value-only leaf position 1 precedes 2".into()
        ))
    );
}

#[test]
#[should_panic(expected = "cannot serialize invalid UniqueNodes")]
fn serializing_overlapping_leaf_maps_is_rejected() {
    let mut value = UniqueNodes::empty();
    value.leaves.insert(7, SmtLeaf::new_empty(LeafIndex::new_max_depth(7)));
    value.value_only_leaves.insert(7, Word::from([1, 2, 3, 4u32]));
    value.to_bytes();
}

#[test]
#[should_panic(expected = "cannot serialize invalid UniqueNodes")]
fn serializing_mismatched_leaf_positions_is_rejected() {
    let mut value = UniqueNodes::empty();
    value.leaves.insert(8, SmtLeaf::new_empty(LeafIndex::new_max_depth(7)));
    value.to_bytes();
}
