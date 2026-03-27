use alloc::vec::Vec;

use assert_matches::assert_matches;

use super::{EMPTY_WORD, LeafIndex, NodeIndex, SMT_DEPTH, Smt, SmtLeaf};
use crate::{
    Felt, ONE, Word,
    hash::poseidon2::Poseidon2,
    merkle::{
        EmptySubtreeRoots,
        smt::{
            Map, MutationSet, NodeMutation, SmtLeafError, SmtProofError, SparseMerkleTree,
            full::MAX_LEAF_ENTRIES,
        },
        store::MerkleStore,
    },
    utils::{Deserializable, Serializable},
};

// SMT
// --------------------------------------------------------------------------------------------

/// This test checks that inserting twice at the same key functions as expected. The test covers
/// only the case where the key is alone in its leaf
#[test]
fn test_smt_insert_at_same_key() {
    let mut smt = Smt::default();
    let mut store: MerkleStore = MerkleStore::default();

    assert_eq!(smt.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));

    let key_1: Word = {
        let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

        Word::from([ONE, ONE, ONE, Felt::new(raw)])
    };
    let key_1_index: NodeIndex = LeafIndex::<SMT_DEPTH>::from(key_1).into();

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([ONE + ONE; Word::NUM_ELEMENTS]);

    // Insert value 1 and ensure root is as expected
    {
        let leaf_node = build_empty_or_single_leaf_node(key_1, value_1);
        let tree_root = store.set_node(smt.root(), key_1_index, leaf_node).unwrap().root;

        let old_value_1 = smt.insert(key_1, value_1).unwrap();
        assert_eq!(old_value_1, EMPTY_WORD);

        assert_eq!(smt.root(), tree_root);
    }

    // Insert value 2 and ensure root is as expected
    {
        let leaf_node = build_empty_or_single_leaf_node(key_1, value_2);
        let tree_root = store.set_node(smt.root(), key_1_index, leaf_node).unwrap().root;

        let old_value_2 = smt.insert(key_1, value_2).unwrap();
        assert_eq!(old_value_2, value_1);

        assert_eq!(smt.root(), tree_root);
    }
}

/// This test checks that inserting twice at the same key functions as expected. The test covers
/// only the case where the leaf type is `SmtLeaf::Multiple`
#[test]
fn test_smt_insert_at_same_key_2() {
    // The most significant u64 used for both keys (to ensure they map to the same leaf)
    let key_msb: u64 = 42;

    let key_already_present = Word::from([2_u64, 2_u64, 2_u64, key_msb].map(Felt::new));
    let key_already_present_index: NodeIndex =
        LeafIndex::<SMT_DEPTH>::from(key_already_present).into();
    let value_already_present = Word::new([ONE + ONE + ONE; Word::NUM_ELEMENTS]);

    let mut smt =
        Smt::with_entries(core::iter::once((key_already_present, value_already_present))).unwrap();
    let mut store: MerkleStore = {
        let mut store = MerkleStore::default();

        let leaf_node = build_empty_or_single_leaf_node(key_already_present, value_already_present);
        store
            .set_node(*EmptySubtreeRoots::entry(SMT_DEPTH, 0), key_already_present_index, leaf_node)
            .unwrap();
        store
    };

    let key_1: Word = Word::from([ONE, ONE, ONE, Felt::new(key_msb)]);
    let key_1_index: NodeIndex = LeafIndex::<SMT_DEPTH>::from(key_1).into();

    assert_eq!(key_1_index, key_already_present_index);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([ONE + ONE; Word::NUM_ELEMENTS]);

    // Insert value 1 and ensure root is as expected
    {
        // Note: key_1 comes first because it is smaller
        let leaf_node = build_multiple_leaf_node(&[
            (key_1, value_1),
            (key_already_present, value_already_present),
        ]);
        let tree_root = store.set_node(smt.root(), key_1_index, leaf_node).unwrap().root;

        let old_value_1 = smt.insert(key_1, value_1).unwrap();
        assert_eq!(old_value_1, EMPTY_WORD);

        assert_eq!(smt.root(), tree_root);
    }

    // Insert value 2 and ensure root is as expected
    {
        let leaf_node = build_multiple_leaf_node(&[
            (key_1, value_2),
            (key_already_present, value_already_present),
        ]);
        let tree_root = store.set_node(smt.root(), key_1_index, leaf_node).unwrap().root;

        let old_value_2 = smt.insert(key_1, value_2).unwrap();
        assert_eq!(old_value_2, value_1);

        assert_eq!(smt.root(), tree_root);
    }
}

/// This test ensures that the root of the tree is as expected when we add/remove 3 items at 3
/// different keys. This also tests that the merkle paths produced are as expected.
#[test]
fn test_smt_insert_and_remove_multiple_values() {
    fn insert_values_and_assert_path(
        smt: &mut Smt,
        store: &mut MerkleStore,
        key_values: &[(Word, Word)],
    ) {
        for &(key, value) in key_values {
            let key_index: NodeIndex = LeafIndex::<SMT_DEPTH>::from(key).into();

            let leaf_node = build_empty_or_single_leaf_node(key, value);
            let tree_root = store.set_node(smt.root(), key_index, leaf_node).unwrap().root;

            smt.insert(key, value).unwrap();

            assert_eq!(smt.root(), tree_root);

            let expected_path = store.get_path(tree_root, key_index).unwrap();
            assert_eq!(smt.open(&key).into_parts().0, expected_path.path);
        }
    }
    let mut smt = Smt::default();
    let mut store: MerkleStore = MerkleStore::default();

    assert_eq!(smt.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));

    let key_1: Word = {
        let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

        Word::from([ONE, ONE, ONE, Felt::new(raw)])
    };

    let key_2: Word = {
        let raw = 0b_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_u64;

        Word::from([ONE, ONE, ONE, Felt::new(raw)])
    };

    let key_3: Word = {
        let raw = 0b_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_u64;

        Word::from([ONE, ONE, ONE, Felt::new(raw)])
    };

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([ONE + ONE; Word::NUM_ELEMENTS]);
    let value_3 = Word::new([ONE + ONE + ONE; Word::NUM_ELEMENTS]);

    // Insert values in the tree
    let key_values = [(key_1, value_1), (key_2, value_2), (key_3, value_3)];
    insert_values_and_assert_path(&mut smt, &mut store, &key_values);

    // Remove values from the tree
    let key_empty_values = [(key_1, EMPTY_WORD), (key_2, EMPTY_WORD), (key_3, EMPTY_WORD)];
    insert_values_and_assert_path(&mut smt, &mut store, &key_empty_values);

    let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    assert_eq!(smt.root(), empty_root);

    // an empty tree should have no leaves or inner nodes
    assert!(smt.leaves.is_empty());
    assert!(smt.inner_nodes.is_empty());
}

/// Verify that the `insert_inner_node` doesn't store empty subtrees.
#[test]
fn test_smt_dont_store_empty_subtrees() {
    use crate::merkle::smt::InnerNode;

    let mut smt = Smt::default();

    let node_index = NodeIndex::new(10, 42).unwrap();
    let depth = node_index.depth();
    let empty_subtree_node = EmptySubtreeRoots::get_inner_node(SMT_DEPTH, depth);

    // Empty subtrees are not stored
    assert!(!smt.inner_nodes.contains_key(&node_index));
    let old_node = smt.insert_inner_node(node_index, empty_subtree_node.clone());
    assert_eq!(old_node, None);
    assert!(!smt.inner_nodes.contains_key(&node_index));

    // Insert a non-empty node, then insert the empty subtree node again. This should remove the
    // inner node.
    let non_empty_node = InnerNode {
        left: Word::new([ONE; 4]),
        right: Word::new([ONE + ONE; 4]),
    };
    smt.insert_inner_node(node_index, non_empty_node.clone());
    let old_node = smt.insert_inner_node(node_index, empty_subtree_node.clone());
    assert_eq!(old_node, Some(non_empty_node));
    assert!(!smt.inner_nodes.contains_key(&node_index));

    // Verify that get_inner_node returns the correct empty subtree node
    let retrieved_node = smt.get_inner_node(node_index);
    assert_eq!(retrieved_node, empty_subtree_node);
}

/// This tests that inserting the empty value does indeed remove the key-value contained at the
/// leaf. We insert & remove 3 values at the same leaf to ensure that all cases are covered (empty,
/// single, multiple).
#[test]
fn test_smt_removal() {
    let mut smt = Smt::default();

    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

    let key_1: Word = Word::from([ONE, ONE, ONE, Felt::new(raw)]);
    let key_2: Word = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(raw)]);
    let key_3: Word = Word::from([
        Felt::from_u32(3_u32),
        Felt::from_u32(3_u32),
        Felt::from_u32(3_u32),
        Felt::new(raw),
    ]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let value_3 = Word::new([Felt::from_u32(3_u32); Word::NUM_ELEMENTS]);

    // insert key-value 1
    {
        let old_value_1 = smt.insert(key_1, value_1).unwrap();
        assert_eq!(old_value_1, EMPTY_WORD);

        assert_eq!(smt.get_leaf(&key_1), SmtLeaf::Single((key_1, value_1)));
    }

    // insert key-value 2
    {
        let old_value_2 = smt.insert(key_2, value_2).unwrap();
        assert_eq!(old_value_2, EMPTY_WORD);

        assert_eq!(
            smt.get_leaf(&key_2),
            SmtLeaf::Multiple(vec![(key_1, value_1), (key_2, value_2)])
        );
    }

    // insert key-value 3
    {
        let old_value_3 = smt.insert(key_3, value_3).unwrap();
        assert_eq!(old_value_3, EMPTY_WORD);

        assert_eq!(
            smt.get_leaf(&key_3),
            SmtLeaf::Multiple(vec![(key_1, value_1), (key_2, value_2), (key_3, value_3)])
        );
    }

    // remove key 3
    {
        let old_value_3 = smt.insert(key_3, EMPTY_WORD).unwrap();
        assert_eq!(old_value_3, value_3);

        assert_eq!(
            smt.get_leaf(&key_3),
            SmtLeaf::Multiple(vec![(key_1, value_1), (key_2, value_2)])
        );
    }

    // remove key 2
    {
        let old_value_2 = smt.insert(key_2, EMPTY_WORD).unwrap();
        assert_eq!(old_value_2, value_2);

        assert_eq!(smt.get_leaf(&key_2), SmtLeaf::Single((key_1, value_1)));
    }

    // remove key 1
    {
        let old_value_1 = smt.insert(key_1, EMPTY_WORD).unwrap();
        assert_eq!(old_value_1, value_1);

        assert_eq!(smt.get_leaf(&key_1), SmtLeaf::new_empty(key_1.into()));
    }
}

/// This tests that we can correctly calculate prospective leaves -- that is, we can construct
/// correct [`SmtLeaf`] values for a theoretical insertion on a Merkle tree without mutating or
/// cloning the tree.
#[test]
fn test_prospective_hash() {
    let mut smt = Smt::default();

    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

    let key_1: Word = Word::from([ONE, ONE, ONE, Felt::new(raw)]);
    let key_2: Word = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(raw)]);
    // Sort key_3 before key_1, to test non-append insertion.
    let key_3: Word = Word::from([
        Felt::from_u32(0_u32),
        Felt::from_u32(0_u32),
        Felt::from_u32(0_u32),
        Felt::new(raw),
    ]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let value_3 = Word::new([Felt::from_u32(3_u32); Word::NUM_ELEMENTS]);

    // insert key-value 1
    {
        let prospective = smt
            .construct_prospective_leaf(smt.get_leaf(&key_1), &key_1, &value_1)
            .unwrap()
            .hash();
        smt.insert(key_1, value_1).unwrap();

        let leaf = smt.get_leaf(&key_1);
        assert_eq!(
            prospective,
            leaf.hash(),
            "prospective hash for leaf {leaf:?} did not match actual hash",
        );
    }

    // insert key-value 2
    {
        let prospective = smt
            .construct_prospective_leaf(smt.get_leaf(&key_2), &key_2, &value_2)
            .unwrap()
            .hash();
        smt.insert(key_2, value_2).unwrap();

        let leaf = smt.get_leaf(&key_2);
        assert_eq!(
            prospective,
            leaf.hash(),
            "prospective hash for leaf {leaf:?} did not match actual hash",
        );
    }

    // insert key-value 3
    {
        let prospective = smt
            .construct_prospective_leaf(smt.get_leaf(&key_3), &key_3, &value_3)
            .unwrap()
            .hash();
        smt.insert(key_3, value_3).unwrap();

        let leaf = smt.get_leaf(&key_3);
        assert_eq!(
            prospective,
            leaf.hash(),
            "prospective hash for leaf {leaf:?} did not match actual hash",
        );
    }

    // remove key 3
    {
        let old_leaf = smt.get_leaf(&key_3);
        let old_value_3 = smt.insert(key_3, EMPTY_WORD).unwrap();
        assert_eq!(old_value_3, value_3);
        let prospective_leaf = smt
            .construct_prospective_leaf(smt.get_leaf(&key_3), &key_3, &old_value_3)
            .unwrap();

        assert_eq!(
            old_leaf.hash(),
            prospective_leaf.hash(),
            "removing and prospectively re-adding a leaf didn't yield the original leaf:\
            \n  original leaf:    {old_leaf:?}\
            \n  prospective leaf: {prospective_leaf:?}",
        );
    }

    // remove key 2
    {
        let old_leaf = smt.get_leaf(&key_2);
        let old_value_2 = smt.insert(key_2, EMPTY_WORD).unwrap();
        assert_eq!(old_value_2, value_2);
        let prospective_leaf = smt
            .construct_prospective_leaf(smt.get_leaf(&key_2), &key_2, &old_value_2)
            .unwrap();

        assert_eq!(
            old_leaf.hash(),
            prospective_leaf.hash(),
            "removing and prospectively re-adding a leaf didn't yield the original leaf:\
            \n  original leaf:    {old_leaf:?}\
            \n  prospective leaf: {prospective_leaf:?}",
        );
    }

    // remove key 1
    {
        let old_leaf = smt.get_leaf(&key_1);
        let old_value_1 = smt.insert(key_1, EMPTY_WORD).unwrap();
        assert_eq!(old_value_1, value_1);
        let prospective_leaf = smt
            .construct_prospective_leaf(smt.get_leaf(&key_1), &key_1, &old_value_1)
            .unwrap();
        assert_eq!(
            old_leaf.hash(),
            prospective_leaf.hash(),
            "removing and prospectively re-adding a leaf didn't yield the original leaf:\
            \n  original leaf:    {old_leaf:?}\
            \n  prospective leaf: {prospective_leaf:?}",
        );
    }
}

/// This tests that we can perform prospective changes correctly.
#[test]
fn test_prospective_insertion() {
    let mut smt = Smt::default();

    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

    let key_1: Word = Word::from([ONE, ONE, ONE, Felt::new(raw)]);
    let key_2: Word = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(raw)]);
    // Sort key_3 before key_1, to test non-append insertion.
    let key_3: Word = Word::from([
        Felt::from_u32(0_u32),
        Felt::from_u32(0_u32),
        Felt::from_u32(0_u32),
        Felt::new(raw),
    ]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let value_3 = Word::new([Felt::from_u32(3_u32); Word::NUM_ELEMENTS]);

    let root_empty = smt.root();

    let root_1 = {
        smt.insert(key_1, value_1).unwrap();
        smt.root()
    };

    let root_2 = {
        smt.insert(key_2, value_2).unwrap();
        smt.root()
    };

    let root_3 = {
        smt.insert(key_3, value_3).unwrap();
        smt.root()
    };

    // Test incremental updates.

    let mut smt = Smt::default();

    let mutations = smt.compute_mutations(vec![(key_1, value_1)]).unwrap();
    assert_eq!(mutations.root(), root_1, "prospective root 1 did not match actual root 1");
    let revert = apply_mutations(&mut smt, mutations);
    assert_eq!(smt.root(), root_1, "mutations before and after apply did not match");
    assert_eq!(revert.old_root, smt.root(), "reverse mutations old root did not match");
    assert_eq!(revert.root(), root_empty, "reverse mutations new root did not match");
    assert_eq!(
        revert.new_pairs,
        Map::from_iter([(key_1, EMPTY_WORD)]),
        "reverse mutations pairs did not match"
    );
    assert_eq!(
        revert.node_mutations,
        smt.inner_nodes.keys().map(|key| (*key, NodeMutation::Removal)).collect(),
        "reverse mutations inner nodes did not match"
    );

    let mutations = smt.compute_mutations(vec![(key_2, value_2)]).unwrap();
    assert_eq!(mutations.root(), root_2, "prospective root 2 did not match actual root 2");
    let mutations = smt.compute_mutations(vec![(key_2, value_2), (key_3, value_3)]).unwrap();
    assert_eq!(mutations.root(), root_3, "mutations before and after apply did not match");
    let old_root = smt.root();
    let revert = apply_mutations(&mut smt, mutations);
    assert_eq!(revert.old_root, smt.root(), "reverse mutations old root did not match");
    assert_eq!(revert.root(), old_root, "reverse mutations new root did not match");
    assert_eq!(
        revert.new_pairs,
        Map::from_iter([(key_2, EMPTY_WORD), (key_3, EMPTY_WORD)]),
        "reverse mutations pairs did not match"
    );

    // Test batch updates, and that the order doesn't matter.
    let pairs = vec![(key_3, EMPTY_WORD), (key_2, EMPTY_WORD), (key_1, EMPTY_WORD)];
    let mutations = smt.compute_mutations(pairs).unwrap();
    assert_eq!(
        mutations.root(),
        root_empty,
        "prospective root for batch removal did not match actual root",
    );
    let old_root = smt.root();
    let revert = apply_mutations(&mut smt, mutations);
    assert_eq!(smt.root(), root_empty, "mutations before and after apply did not match");
    assert_eq!(revert.old_root, smt.root(), "reverse mutations old root did not match");
    assert_eq!(revert.root(), old_root, "reverse mutations new root did not match");
    assert_eq!(
        revert.new_pairs,
        Map::from_iter([(key_1, value_1), (key_2, value_2), (key_3, value_3)]),
        "reverse mutations pairs did not match"
    );

    let pairs = vec![(key_3, value_3), (key_1, value_1), (key_2, value_2)];
    let mutations = smt.compute_mutations(pairs).unwrap();
    assert_eq!(mutations.root(), root_3);
    smt.apply_mutations(mutations).unwrap();
    assert_eq!(smt.root(), root_3);
}

#[test]
fn test_mutations_no_mutations() {
    let key = Word::from([ONE, ONE, ONE, ONE]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);
    let entries = [(key, value)];

    let tree = Smt::with_entries(entries).unwrap();
    let mutations = tree.compute_mutations(entries).unwrap();

    assert_eq!(mutations.root(), mutations.old_root(), "Root should not change");
    assert!(mutations.node_mutations().is_empty(), "Node mutations should be empty");
    assert!(mutations.new_pairs().is_empty(), "There should be no new pairs");
}

#[test]
fn test_mutations_revert() {
    let mut smt = Smt::default();

    let key_1: Word = Word::from([ONE, ONE, ONE, Felt::new(1)]);
    let key_2: Word = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(2)]);
    let key_3: Word = Word::from([
        Felt::from_u32(0_u32),
        Felt::from_u32(0_u32),
        Felt::from_u32(0_u32),
        Felt::new(3),
    ]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let value_3 = Word::new([Felt::from_u32(3_u32); Word::NUM_ELEMENTS]);

    smt.insert(key_1, value_1).unwrap();
    smt.insert(key_2, value_2).unwrap();

    let mutations = smt
        .compute_mutations(vec![(key_1, EMPTY_WORD), (key_2, value_1), (key_3, value_3)])
        .unwrap();

    let original = smt.clone();

    let revert = smt.apply_mutations_with_reversion(mutations).unwrap();
    assert_eq!(revert.old_root, smt.root(), "reverse mutations old root did not match");
    assert_eq!(revert.root(), original.root(), "reverse mutations new root did not match");

    smt.apply_mutations(revert).unwrap();

    assert_eq!(smt, original, "SMT with applied revert mutations did not match original SMT");
}

#[test]
fn test_mutation_set_serialization() {
    let mut smt = Smt::default();

    let key_1: Word = Word::from([ONE, ONE, ONE, Felt::new(1)]);
    let key_2: Word = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(2)]);
    let key_3: Word = Word::from([
        Felt::from_u32(0_u32),
        Felt::from_u32(0_u32),
        Felt::from_u32(0_u32),
        Felt::new(3),
    ]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let value_3 = Word::new([Felt::from_u32(3_u32); Word::NUM_ELEMENTS]);

    smt.insert(key_1, value_1).unwrap();
    smt.insert(key_2, value_2).unwrap();

    let mutations = smt
        .compute_mutations(vec![(key_1, EMPTY_WORD), (key_2, value_1), (key_3, value_3)])
        .unwrap();

    let serialized = mutations.to_bytes();
    let deserialized = MutationSet::<SMT_DEPTH, Word, Word>::read_from_bytes(&serialized).unwrap();

    assert_eq!(deserialized, mutations, "deserialized mutations did not match original");

    let revert = smt.apply_mutations_with_reversion(mutations).unwrap();

    let serialized = revert.to_bytes();
    let deserialized = MutationSet::<SMT_DEPTH, Word, Word>::read_from_bytes(&serialized).unwrap();

    assert_eq!(deserialized, revert, "deserialized mutations did not match original");
}

/// Tests that 2 key-value pairs stored in the same leaf have the same path
#[test]
fn test_smt_path_to_keys_in_same_leaf_are_equal() {
    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

    let key_1: Word = Word::from([ONE, ONE, ONE, Felt::new(raw)]);
    let key_2: Word = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(raw)]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);

    let smt = Smt::with_entries([(key_1, value_1), (key_2, value_2)]).unwrap();

    assert_eq!(smt.open(&key_1), smt.open(&key_2));
}

/// Tests that an empty leaf hashes to the empty word
#[test]
fn test_empty_leaf_hash() {
    let smt = Smt::default();

    let leaf = smt.get_leaf(&Word::default());
    assert_eq!(leaf.hash(), EMPTY_WORD);
}

/// Tests that `get_value()` works as expected
#[test]
fn test_smt_get_value() {
    let key_1: Word = Word::from([ONE, ONE, ONE, ONE]);
    let key_2: Word = Word::from([2_u32, 2_u32, 2_u32, 2_u32]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);

    let smt = Smt::with_entries([(key_1, value_1), (key_2, value_2)]).unwrap();

    let returned_value_1 = smt.get_value(&key_1);
    let returned_value_2 = smt.get_value(&key_2);

    assert_eq!(value_1, returned_value_1);
    assert_eq!(value_2, returned_value_2);

    // Check that a key with no inserted value returns the empty word
    let key_no_value = Word::from([42_u32, 42_u32, 42_u32, 42_u32]);

    assert_eq!(EMPTY_WORD, smt.get_value(&key_no_value));
}

/// Tests that `entries()` works as expected
#[test]
fn test_smt_entries() {
    let key_1 = Word::from([ONE, ONE, ONE, ONE]);
    let key_2 = Word::from([2_u32, 2_u32, 2_u32, 2_u32]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let entries = [(key_1, value_1), (key_2, value_2)];

    let smt = Smt::with_entries(entries).unwrap();

    let mut expected = Vec::from_iter(entries);
    expected.sort_by_key(|(k, _)| *k);
    let mut actual: Vec<_> = smt.entries().cloned().collect();
    actual.sort_by_key(|(k, _)| *k);

    assert_eq!(actual, expected);
}

/// Tests that `EMPTY_ROOT` constant generated in the `Smt` equals to the root of the empty tree of
/// depth 64
#[test]
fn test_smt_check_empty_root_constant() {
    // get the root of the empty tree of depth 64
    let empty_root_64_depth = EmptySubtreeRoots::empty_hashes(64)[0];

    assert_eq!(empty_root_64_depth, Smt::EMPTY_ROOT);
}

/// Tests that empty SMT deserializes under a tight budget.
#[test]
fn test_empty_smt_deserialization_with_budget() {
    let smt = Smt::default();
    let bytes = smt.to_bytes();

    let parsed = Smt::read_from_bytes_with_budget(&bytes, bytes.len()).unwrap();
    assert_eq!(smt, parsed);
}

// SMT LEAF
// --------------------------------------------------------------------------------------------

#[test]
fn test_empty_smt_leaf_serialization() {
    let empty_leaf = SmtLeaf::new_empty(LeafIndex::new_max_depth(42));

    let mut serialized = empty_leaf.to_bytes();
    // extend buffer with random bytes
    serialized.extend([1, 2, 3, 4, 5]);
    let deserialized = SmtLeaf::read_from_bytes(&serialized).unwrap();

    assert_eq!(empty_leaf, deserialized);
}

#[test]
fn test_empty_smt_leaf_deserialization_with_budget() {
    let empty_leaf = SmtLeaf::new_empty(LeafIndex::new_max_depth(42));
    let bytes = empty_leaf.to_bytes();

    let deserialized = SmtLeaf::read_from_bytes_with_budget(&bytes, bytes.len()).unwrap();
    assert_eq!(empty_leaf, deserialized);
}

#[test]
fn test_single_smt_leaf_serialization() {
    let single_leaf = SmtLeaf::new_single(
        Word::from([10_u32, 11_u32, 12_u32, 13_u32]),
        Word::new([
            Felt::from_u32(1_u32),
            Felt::from_u32(2_u32),
            Felt::from_u32(3_u32),
            Felt::from_u32(4_u32),
        ]),
    );

    let mut serialized = single_leaf.to_bytes();
    // extend buffer with random bytes
    serialized.extend([1, 2, 3, 4, 5]);
    let deserialized = SmtLeaf::read_from_bytes(&serialized).unwrap();

    assert_eq!(single_leaf, deserialized);
}

#[test]
fn test_multiple_smt_leaf_serialization_success() {
    let multiple_leaf = SmtLeaf::new_multiple(vec![
        (
            Word::from([10_u32, 11_u32, 12_u32, 13_u32]),
            Word::new([
                Felt::from_u32(1_u32),
                Felt::from_u32(2_u32),
                Felt::from_u32(3_u32),
                Felt::from_u32(4_u32),
            ]),
        ),
        (
            Word::from([100_u32, 101_u32, 102_u32, 13_u32]),
            Word::new([
                Felt::from_u32(11_u32),
                Felt::from_u32(12_u32),
                Felt::from_u32(13_u32),
                Felt::from_u32(14_u32),
            ]),
        ),
    ])
    .unwrap();

    let mut serialized = multiple_leaf.to_bytes();
    // extend buffer with random bytes
    serialized.extend([1, 2, 3, 4, 5]);
    let deserialized = SmtLeaf::read_from_bytes(&serialized).unwrap();

    assert_eq!(multiple_leaf, deserialized);
}

/// Test that creating a multiple leaf with exactly MAX_LEAF_ENTRIES works
/// and that constructing a leaf with MAX_LEAF_ENTRIES + 1 returns an error.
#[test]
fn test_max_leaf_entries_validation() {
    let mut entries = Vec::new();

    for i in 0..MAX_LEAF_ENTRIES {
        let key = Word::new([ONE, ONE, Felt::new(i as u64), ONE]);
        let value = Word::new([ONE, ONE, ONE, Felt::new(i as u64)]);
        entries.push((key, value));
    }

    let result = SmtLeaf::new_multiple(entries.clone());
    assert!(result.is_ok(), "Should allow exactly MAX_LEAF_ENTRIES entries");

    // Test that creating a multiple leaf with more than MAX_LEAF_ENTRIES fails
    let key = Word::new([ONE, ONE, Felt::new(MAX_LEAF_ENTRIES as u64), ONE]);
    let value = Word::new([ONE, ONE, ONE, Felt::new(MAX_LEAF_ENTRIES as u64)]);
    entries.push((key, value));

    let error = SmtLeaf::new_multiple(entries).unwrap_err();
    assert_matches!(
        error,
        SmtLeafError::TooManyLeafEntries { .. },
        "should reject more than MAX_LEAF_ENTRIES entries"
    );
}

/// Tests that verify_presence returns InvalidKeyForProof when key maps to different leaf index
#[test]
fn test_smt_proof_error_invalid_key_for_proof() {
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let smt = Smt::with_entries([(key, value)]).unwrap();
    let proof = smt.open(&key);
    let root = smt.root();

    // Use a key that maps to a different leaf index (different most significant felt)
    let different_index_key = Word::from([ONE, ONE, ONE, Felt::new(999)]);

    assert_matches!(
        proof.verify_presence(&different_index_key, &value, &root),
        Err(SmtProofError::InvalidKeyForProof)
    );
}

/// Tests that verify_presence returns ValueMismatch when value doesn't match
#[test]
fn test_smt_proof_error_value_mismatch() {
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let smt = Smt::with_entries([(key, value)]).unwrap();
    let proof = smt.open(&key);
    let root = smt.root();

    // Use the correct key but wrong value
    let wrong_value = Word::new([Felt::new(999); Word::NUM_ELEMENTS]);

    assert_matches!(
        proof.verify_presence(&key, &wrong_value, &root),
        Err(SmtProofError::ValueMismatch { expected, actual })
            if expected == wrong_value && actual == value
    );
}

/// Tests that verify_presence returns ConflictingRoots when root doesn't match
#[test]
fn test_smt_proof_error_conflicting_roots() {
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let smt = Smt::with_entries([(key, value)]).unwrap();
    let proof = smt.open(&key);
    let actual_root = smt.root();

    // Use a completely wrong root
    let wrong_root = Word::new([Felt::new(999); Word::NUM_ELEMENTS]);

    assert_matches!(
        proof.verify_presence(&key, &value, &wrong_root),
        Err(SmtProofError::ConflictingRoots { expected_root, actual_root: got_root })
            if expected_root == wrong_root && got_root == actual_root
    );
}

/// Tests that verify_unset returns Ok for keys with no value
#[test]
fn test_smt_proof_verify_unset_success() {
    // Use an empty tree where no keys have values
    let smt = Smt::default();
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let proof = smt.open(&key);
    let root = smt.root();

    // This key has no value in the empty tree
    proof.verify_unset(&key, &root).unwrap();
}

/// Tests that verify_unset returns ValueMismatch when key has a value
#[test]
fn test_smt_proof_verify_unset_fails_when_value_exists() {
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let smt = Smt::with_entries([(key, value)]).unwrap();
    let proof = smt.open(&key);
    let root = smt.root();

    // Key has a value, so non-membership should fail
    assert_matches!(proof.verify_unset(&key, &root), Err(SmtProofError::ValueMismatch { .. }));
}

/// Tests that verify_absence returns Ok when the key has a different value
#[test]
fn test_smt_proof_verify_absence_success_different_value() {
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let actual_value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let smt = Smt::with_entries([(key, actual_value)]).unwrap();
    let proof = smt.open(&key);
    let root = smt.root();

    // The key has a different value, so this pair is absent
    let absent_value = Word::new([Felt::new(999); Word::NUM_ELEMENTS]);
    proof.verify_absence(&key, &absent_value, &root).unwrap();
}

/// Tests that verify_absence returns Ok when the key is unset
#[test]
fn test_smt_proof_verify_absence_success_key_unset() {
    // Use an empty tree
    let smt = Smt::default();
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let proof = smt.open(&key);
    let root = smt.root();

    // Any non-empty value should be absent since key is unset
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);
    proof.verify_absence(&key, &value, &root).unwrap();
}

/// Tests that verify_absence returns ValuePresent when the key-value pair exists
#[test]
fn test_smt_proof_error_value_present() {
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let smt = Smt::with_entries([(key, value)]).unwrap();
    let proof = smt.open(&key);
    let root = smt.root();

    // The exact key-value pair exists, so absence verification fails
    assert_matches!(
        proof.verify_absence(&key, &value, &root),
        Err(SmtProofError::ValuePresent { key: k, value: v }) if k == key && v == value
    );
}

/// Tests that verify_absence returns InvalidKeyForProof for wrong leaf index
#[test]
fn test_smt_proof_verify_absence_invalid_key() {
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let smt = Smt::with_entries([(key, value)]).unwrap();
    let proof = smt.open(&key);
    let root = smt.root();

    // Use a key that maps to a different leaf index
    let different_index_key = Word::from([ONE, ONE, ONE, Felt::new(999)]);

    assert_matches!(
        proof.verify_absence(&different_index_key, &value, &root),
        Err(SmtProofError::InvalidKeyForProof)
    );
}

/// Tests that `get()` returns None for keys that don't map to the proof's leaf index.
#[test]
fn test_smt_proof_get_returns_none_for_different_leaf() {
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let smt = Smt::with_entries([(key, value)]).unwrap();
    let proof = smt.open(&key);

    // Key that maps to a different leaf index
    let different_leaf_key = Word::from([ONE, ONE, ONE, Felt::new(999)]);

    assert!(
        proof.get(&different_leaf_key).is_none(),
        "get() should return None for key mapping to different leaf"
    );
}

/// Tests that `get()` returns EMPTY_WORD for keys that map to the proof's leaf but don't exist.
#[test]
fn test_smt_proof_get_returns_empty_for_absent_key_same_leaf() {
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let smt = Smt::with_entries([(key, value)]).unwrap();
    let proof = smt.open(&key);

    // Key that maps to the same leaf but doesn't exist (same most significant felt)
    let absent_key_same_leaf =
        Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(42)]);

    let result = proof.get(&absent_key_same_leaf);
    assert_eq!(
        result,
        Some(EMPTY_WORD),
        "get() should return Some(EMPTY_WORD) for absent key mapping to same leaf"
    );
}

/// Tests that `try_from_elements()` round-trips correctly for an empty leaf.
#[test]
fn test_smt_leaf_try_from_elements_empty() {
    let leaf_index = LeafIndex::new_max_depth(42);
    let expected = SmtLeaf::new_empty(leaf_index);
    let elements: Vec<Felt> = expected.to_elements().collect();
    let actual = SmtLeaf::try_from_elements(&elements, leaf_index).unwrap();
    assert_eq!(actual, expected);
}

/// Tests that `try_from_elements()` round-trips correctly for a single-entry leaf.
#[test]
fn test_smt_leaf_try_from_elements_single_entry() {
    let expected = SmtLeaf::new_single(
        Word::from([10_u32, 11_u32, 12_u32, 13_u32]),
        Word::from([1_u32, 2_u32, 3_u32, 4_u32]),
    );
    let elements: Vec<Felt> = expected.to_elements().collect();
    let actual = SmtLeaf::try_from_elements(&elements, expected.index()).unwrap();
    assert_eq!(actual, expected);
}

/// Tests that `try_from_elements()` round-trips correctly for a multiple-entry leaf.
#[test]
fn test_smt_leaf_try_from_elements_multiple_entries() {
    // Keys must have the same value in position 3 to map to the same leaf index.
    let expected = SmtLeaf::new_multiple(vec![
        (
            Word::from([10_u32, 11_u32, 12_u32, 13_u32]),
            Word::from([1_u32, 2_u32, 3_u32, 4_u32]),
        ),
        (
            Word::from([100_u32, 101_u32, 102_u32, 13_u32]),
            Word::from([11_u32, 12_u32, 13_u32, 14_u32]),
        ),
    ])
    .unwrap();
    let elements: Vec<Felt> = expected.to_elements().collect();
    let actual = SmtLeaf::try_from_elements(&elements, expected.index()).unwrap();
    assert_eq!(actual, expected);
}

/// Tests that `try_from_elements()` returns the expected error when the list of elements is
/// not a multiple of 8.
#[test]
fn test_smt_leaf_try_from_elements_invalid_length() {
    let elements = vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3)];
    let leaf_index = LeafIndex::new_max_depth(42);
    let result = SmtLeaf::try_from_elements(&elements, leaf_index);
    assert_matches!(result, Err(SmtLeafError::DecodingError(_)));
}

// DUPLICATE KEY DETECTION
// --------------------------------------------------------------------------------------------

/// Tests that `compute_mutations` rejects duplicate keys (same key, same value).
#[test]
fn test_compute_mutations_rejects_duplicate_keys() {
    use crate::merkle::MerkleError;

    let smt = Smt::default();
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let result = smt.compute_mutations(vec![(key, value), (key, value)]);

    let expected_pos = Smt::key_to_leaf_index(&key).position();
    assert_matches!(result, Err(MerkleError::DuplicateValuesForIndex(pos)) if pos == expected_pos);
}

/// Tests that `compute_mutations` rejects duplicate keys even with different values.
#[test]
fn test_compute_mutations_rejects_duplicate_keys_different_values() {
    use crate::merkle::MerkleError;

    let smt = Smt::default();
    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);

    let result = smt.compute_mutations(vec![(key, value_1), (key, value_2)]);

    let expected_pos = Smt::key_to_leaf_index(&key).position();
    assert_matches!(result, Err(MerkleError::DuplicateValuesForIndex(pos)) if pos == expected_pos);
}

/// Tests that `compute_mutations` rejects duplicate keys even when interleaved with another key
/// that shares the same leaf index: `[(k1, v1), (k2, v2), (k1, v3)]`.
#[test]
fn test_compute_mutations_rejects_interleaved_duplicate_keys() {
    use crate::merkle::MerkleError;

    let smt = Smt::default();

    // Two different keys that map to the same leaf (same most significant felt)
    let key_1 = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let key_2 = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(42)]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let value_3 = Word::new([Felt::from_u32(3_u32); Word::NUM_ELEMENTS]);

    // k1 appears at positions 0 and 2, interleaved with k2
    let result = smt.compute_mutations(vec![(key_1, value_1), (key_2, value_2), (key_1, value_3)]);

    let expected_pos = Smt::key_to_leaf_index(&key_1).position();
    assert_matches!(result, Err(MerkleError::DuplicateValuesForIndex(pos)) if pos == expected_pos);
}

/// Tests that different keys mapping to the same leaf index do NOT trigger the duplicate error.
#[test]
fn test_compute_mutations_no_false_positives() {
    let smt = Smt::default();

    // Two different keys that map to the same leaf (same most significant felt)
    let key_1 = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let key_2 = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(42)]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);

    // These are different keys (despite sharing a leaf index), so this should succeed.
    let result = smt.compute_mutations(vec![(key_1, value_1), (key_2, value_2)]);

    assert!(result.is_ok(), "Different keys at the same leaf index should not be rejected");
}

/// Tests that `Smt::with_entries` rejects duplicate keys.
#[test]
fn test_with_entries_rejects_duplicate_keys() {
    use crate::merkle::MerkleError;

    let key = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);

    let result = Smt::with_entries(vec![(key, value_1), (key, value_2)]);

    let expected_pos = Smt::key_to_leaf_index(&key).position();
    assert_matches!(result, Err(MerkleError::DuplicateValuesForIndex(pos)) if pos == expected_pos);
}

/// Tests that `Smt::with_entries` rejects interleaved duplicate keys.
#[test]
fn test_with_entries_rejects_interleaved_duplicate_keys() {
    use crate::merkle::MerkleError;

    // Two different keys that map to the same leaf (same most significant felt)
    let key_1 = Word::from([ONE, ONE, ONE, Felt::new(42)]);
    let key_2 = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(42)]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let value_3 = Word::new([Felt::from_u32(3_u32); Word::NUM_ELEMENTS]);

    // k1 appears at positions 0 and 2, interleaved with k2
    let result = Smt::with_entries(vec![(key_1, value_1), (key_2, value_2), (key_1, value_3)]);

    let expected_pos = Smt::key_to_leaf_index(&key_1).position();
    assert_matches!(result, Err(MerkleError::DuplicateValuesForIndex(pos)) if pos == expected_pos);
}

// HELPERS
// --------------------------------------------------------------------------------------------

fn build_empty_or_single_leaf_node(key: Word, value: Word) -> Word {
    if value == EMPTY_WORD {
        SmtLeaf::new_empty(key.into()).hash()
    } else {
        SmtLeaf::Single((key, value)).hash()
    }
}

fn build_multiple_leaf_node(kv_pairs: &[(Word, Word)]) -> Word {
    let elements: Vec<Felt> = kv_pairs
        .iter()
        .flat_map(|(key, value)| {
            let key_elements = key.into_iter();
            let value_elements = (*value).into_iter();

            key_elements.chain(value_elements)
        })
        .collect();

    Poseidon2::hash_elements(&elements)
}

/// Applies mutations with and without reversion to the given SMT, comparing resulting SMTs,
/// returning mutation set for reversion.
fn apply_mutations(
    smt: &mut Smt,
    mutation_set: MutationSet<SMT_DEPTH, Word, Word>,
) -> MutationSet<SMT_DEPTH, Word, Word> {
    let mut smt2 = smt.clone();

    let reversion = smt.apply_mutations_with_reversion(mutation_set.clone()).unwrap();
    smt2.apply_mutations(mutation_set).unwrap();

    assert_eq!(&smt2, smt);

    reversion
}
