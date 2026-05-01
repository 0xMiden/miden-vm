#![cfg(test)]
//! The basic handwritten tests for the serialization functionality of the partial SMT.

mod unique_nodes {
    use miden_field::{Felt, Word};
    use miden_serde_utils::{Deserializable, Serializable};

    use crate::{
        merkle::smt::{LeafIndex, NodeValue, SmtLeaf, UniqueNodes},
        rand::test_utils::ContinuousRng,
    };

    #[test]
    fn empty_unique_nodes_roundtrips() {
        let value = UniqueNodes::empty();
        assert_eq!(UniqueNodes::read_from_bytes(&value.to_bytes()), Ok(value))
    }

    #[test]
    fn unique_nodes_roundtrips() {
        let mut rng = ContinuousRng::new([0x67; 32]);

        let level_1_depth = 6u8;
        let level_1_nodes = vec![
            (0u64, NodeValue::EmptySubtreeRoot),
            (2u64.pow(3), NodeValue::Present(rng.value())),
            (2u64.pow(6) - 1, NodeValue::Present(rng.value())),
        ];

        let level_2_depth = 61u8;
        let level_2_nodes = vec![
            (0u64, NodeValue::EmptySubtreeRoot),
            (2u64.pow(12), NodeValue::Present(rng.value())),
            (2u64.pow(14) - 1, NodeValue::Present(rng.value())),
            (2u64.pow(58) + 31, NodeValue::Present(rng.value())),
        ];

        let leaf_1_index = u64::MAX;
        let leaf_1_value = SmtLeaf::new_empty(LeafIndex::new_max_depth(leaf_1_index));

        let leaf_2_index = 2u64.pow(32);
        let leaf_2_value = SmtLeaf::new_single(rng.value(), rng.value());

        let leaf_3_index = 12;
        let leaf_index: Felt = rng.value();
        let leaf_3_value = SmtLeaf::new_multiple(vec![
            (Word::new([rng.value(), rng.value(), rng.value(), leaf_index]), rng.value()),
            (Word::new([rng.value(), rng.value(), rng.value(), leaf_index]), rng.value()),
            (Word::new([rng.value(), rng.value(), rng.value(), leaf_index]), rng.value()),
        ])
        .unwrap();

        let mut value = UniqueNodes::empty();
        value.root = rng.value();
        value.nodes.insert(level_1_depth, level_1_nodes);
        value.nodes.insert(level_2_depth, level_2_nodes);
        value.leaves.push((leaf_1_index, leaf_1_value));
        value.leaves.push((leaf_2_index, leaf_2_value));
        value.leaves.push((leaf_3_index, leaf_3_value));

        assert_eq!(UniqueNodes::read_from_bytes(&value.to_bytes()), Ok(value))
    }
}

mod node_value {
    use miden_field::{Felt, Word};
    use miden_serde_utils::{Deserializable, Serializable};

    use super::super::NodeValue;
    use crate::rand::test_utils::ContinuousRng;

    #[test]
    fn empty_node_value_serializes_correctly() {
        assert_eq!(NodeValue::EmptySubtreeRoot.to_bytes(), u64::MAX.to_le_bytes())
    }

    #[test]
    fn word_node_value_serializes_correctly() {
        // The limit values should both serialize to known values.
        assert_eq!(NodeValue::Present(Word::empty()).to_bytes(), vec![0x00; 32]);
        assert_eq!(
            NodeValue::Present(Word::new([Felt::new_unchecked(Felt::ORDER - 1); 4])).to_bytes(),
            vec![
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff,
            ]
        );

        // It should always produce the same bytes as serializing the word directly.
        let mut rng = ContinuousRng::new([0x42; 32]);
        let rand_word: Word = rng.value();
        assert_eq!(NodeValue::Present(rand_word).to_bytes(), rand_word.to_bytes());
    }

    #[test]
    fn empty_node_value_deserializes_correctly() {
        assert_eq!(
            NodeValue::read_from_bytes(&u64::MAX.to_le_bytes()),
            Ok(NodeValue::EmptySubtreeRoot)
        );
        assert_eq!(
            NodeValue::read_from_bytes(&u64::MAX.to_le_bytes()),
            Ok(NodeValue::EmptySubtreeRoot)
        );
    }

    #[test]
    fn word_node_value_deserializes_correctly() {
        // The limit values should both deserialize from known values.
        assert_eq!(NodeValue::read_from_bytes(&[0x00; 32]), Ok(NodeValue::Present(Word::empty())));
        assert_eq!(
            NodeValue::read_from_bytes(&[
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff,
            ]),
            Ok(NodeValue::Present(Word::new([Felt::new_unchecked(Felt::ORDER - 1); 4])))
        );

        // And a series of random valid word bytes should result in that same word being stored.
        let mut rng = ContinuousRng::new([0x96; 32]);
        let rand_word: Word = rng.value();
        assert_eq!(
            NodeValue::read_from_bytes(&rand_word.to_bytes()),
            Ok(NodeValue::Present(rand_word))
        );
    }

    #[test]
    fn empty_node_value_roundtrips() {
        let value = NodeValue::EmptySubtreeRoot;
        assert_eq!(NodeValue::read_from_bytes(&value.to_bytes()), Ok(value));
    }

    #[test]
    fn word_node_value_roundtrips() {
        let mut rng = ContinuousRng::new([0x69; 32]);
        let rand_word: Word = rng.value();
        let value = NodeValue::Present(rand_word);
        assert_eq!(NodeValue::read_from_bytes(&value.to_bytes()), Ok(value));

        let failing_word = Word::new([
            Felt::new_unchecked(3603862270821680383),
            Felt::new_unchecked(0),
            Felt::new_unchecked(0),
            Felt::new_unchecked(0),
        ]);
        let value = NodeValue::Present(failing_word);
        assert_eq!(NodeValue::read_from_bytes(&value.to_bytes()), Ok(value));
    }
}
