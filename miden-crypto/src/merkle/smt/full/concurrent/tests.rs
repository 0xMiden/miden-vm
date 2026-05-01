#![cfg(feature = "std")]

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use assert_matches::assert_matches;
use proptest::prelude::*;
use rand::{Rng, SeedableRng, prelude::IteratorRandom};
use rand_chacha::ChaCha20Rng;

use super::{
    COLS_PER_SUBTREE, InnerNode, Map, NodeIndex, NodeMutations, PairComputations, SMT_DEPTH,
    SUBTREE_DEPTH, Smt, SmtLeaf, SparseMerkleTreeReader, SubtreeLeaf, SubtreeLeavesIter, Word,
    build_subtree,
};
use crate::{
    EMPTY_WORD, Felt, ONE, ZERO,
    merkle::{MerkleError, smt::LeafIndex},
};

fn smtleaf_to_subtree_leaf(leaf: &SmtLeaf) -> SubtreeLeaf {
    SubtreeLeaf {
        col: leaf.index().index.position(),
        hash: leaf.hash(),
    }
}

#[test]
fn test_sorted_pairs_to_leaves() {
    let entries: Vec<(Word, Word)> = vec![
        // Subtree 0.
        ([ONE, ONE, ONE, Felt::new_unchecked(16)].into(), [ONE; 4].into()),
        ([ONE, ONE, ONE, Felt::new_unchecked(17)].into(), [ONE; 4].into()),
        // Leaf index collision.
        (
            [ONE, ONE, Felt::new_unchecked(10), Felt::new_unchecked(20)].into(),
            [ONE; 4].into(),
        ),
        (
            [ONE, ONE, Felt::new_unchecked(20), Felt::new_unchecked(20)].into(),
            [ONE; 4].into(),
        ),
        // Subtree 1. Normal single leaf again.
        ([ONE, ONE, ONE, Felt::new_unchecked(400)].into(), [ONE; 4].into()), // Subtree boundary.
        ([ONE, ONE, ONE, Felt::new_unchecked(401)].into(), [ONE; 4].into()),
        // Subtree 2. Another normal leaf.
        ([ONE, ONE, ONE, Felt::new_unchecked(1024)].into(), [ONE; 4].into()),
    ];

    let control = Smt::with_entries_sequential(entries.clone()).unwrap();
    let control_leaves: Vec<SmtLeaf> = {
        let mut entries_iter = entries.iter().cloned();
        let mut next_entry = || entries_iter.next().unwrap();
        let control_leaves = vec![
            // Subtree 0.
            SmtLeaf::Single(next_entry()),
            SmtLeaf::Single(next_entry()),
            SmtLeaf::new_multiple(vec![next_entry(), next_entry()]).unwrap(),
            // Subtree 1.
            SmtLeaf::Single(next_entry()),
            SmtLeaf::Single(next_entry()),
            // Subtree 2.
            SmtLeaf::Single(next_entry()),
        ];
        assert_eq!(entries_iter.next(), None);
        control_leaves
    };

    let control_subtree_leaves: Vec<Vec<SubtreeLeaf>> = {
        let mut control_leaves_iter = control_leaves.iter();
        let mut next_leaf = || control_leaves_iter.next().unwrap();
        let control_subtree_leaves: Vec<Vec<SubtreeLeaf>> = [
            // Subtree 0.
            vec![next_leaf(), next_leaf(), next_leaf()],
            // Subtree 1.
            vec![next_leaf(), next_leaf()],
            // Subtree 2.
            vec![next_leaf()],
        ]
        .map(|subtree| subtree.into_iter().map(smtleaf_to_subtree_leaf).collect())
        .to_vec();
        assert_eq!(control_leaves_iter.next(), None);
        control_subtree_leaves
    };

    let subtrees: PairComputations<u64, SmtLeaf> = Smt::sorted_pairs_to_leaves(entries).unwrap();
    // This will check that the hashes, columns, and subtree assignments all match.
    assert_eq!(subtrees.leaves, control_subtree_leaves);
    // Flattening and re-separating out the leaves into subtrees should have the same result.
    let mut all_leaves: Vec<SubtreeLeaf> = subtrees.leaves.clone().into_iter().flatten().collect();
    let re_grouped: Vec<Vec<_>> = SubtreeLeavesIter::from_leaves(&mut all_leaves).collect();
    assert_eq!(subtrees.leaves, re_grouped);
    // Then finally we might as well check the computed leaf nodes too.
    let control_leaves: BTreeMap<u64, SmtLeaf> = control
        .leaves()
        .map(|(index, value)| (index.index.position(), value.clone()))
        .collect();

    for (column, test_leaf) in subtrees.nodes {
        if test_leaf.is_empty() {
            continue;
        }
        let control_leaf = control_leaves
            .get(&column)
            .unwrap_or_else(|| panic!("no leaf node found for column {column}"));
        assert_eq!(control_leaf, &test_leaf);
    }
}

// Helper for the below tests.
fn generate_entries(pair_count: u64) -> Vec<(Word, Word)> {
    (0..pair_count)
        .map(|i| {
            let leaf_index = ((i as f64 / pair_count as f64) * (pair_count as f64)) as u64;
            let key =
                Word::new([ONE, ONE, Felt::new_unchecked(i), Felt::new_unchecked(leaf_index)]);
            let value = Word::new([ONE, ONE, ONE, Felt::new_unchecked(i)]);
            (key, value)
        })
        .collect()
}

fn generate_updates(entries: Vec<(Word, Word)>, updates: usize) -> Vec<(Word, Word)> {
    const REMOVAL_PROBABILITY: f64 = 0.2;
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    // Assertion to ensure input keys are unique
    assert!(
        entries.iter().map(|(key, _)| key).collect::<BTreeSet<_>>().len() == entries.len(),
        "Input entries contain duplicate keys!"
    );
    let mut sorted_entries: Vec<(Word, Word)> = entries
        .into_iter()
        .choose_multiple(&mut rng, updates)
        .into_iter()
        .map(|(key, _)| {
            let value = if rng.random_bool(REMOVAL_PROBABILITY) {
                EMPTY_WORD
            } else {
                Word::new([ONE, ONE, ONE, Felt::new_unchecked(rng.random())])
            };
            (key, value)
        })
        .collect();
    sorted_entries.sort_by_key(|(key, _)| Smt::key_to_leaf_index(key).position());
    sorted_entries
}

#[test]
fn test_single_subtree() {
    // A single subtree's worth of leaves.
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE;
    let entries = generate_entries(PAIR_COUNT);
    let control = Smt::with_entries_sequential(entries.clone()).unwrap();
    // `entries` should already be sorted by nature of how we constructed it.
    let leaves = Smt::sorted_pairs_to_leaves(entries).unwrap().leaves;
    let leaves = leaves.into_iter().next().unwrap();
    let (first_subtree, subtree_root) = build_subtree(leaves, SMT_DEPTH, SMT_DEPTH);
    assert!(!first_subtree.is_empty());
    // The inner nodes computed from that subtree should match the nodes in our control tree.
    for (index, node) in first_subtree.into_iter() {
        let control = control.get_inner_node(index);
        assert_eq!(
            control, node,
            "subtree-computed node at index {index:?} does not match control",
        );
    }
    // The root returned should also match the equivalent node in the control tree.
    let control_root_index =
        NodeIndex::new(SMT_DEPTH - SUBTREE_DEPTH, subtree_root.col).expect("Valid root index");
    let control_root_node = control.get_inner_node(control_root_index);
    let control_hash = control_root_node.hash();
    assert_eq!(
        control_hash, subtree_root.hash,
        "Subtree-computed root at index {control_root_index:?} does not match control"
    );
}

// Test that not just can we compute a subtree correctly, but we can feed the results of one
// subtree into computing another. In other words, test that `build_subtree()` is correctly
// composable.
#[test]
fn test_two_subtrees() {
    // Two subtrees' worth of leaves.
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 2;
    let entries = generate_entries(PAIR_COUNT);
    let control = Smt::with_entries_sequential(entries.clone()).unwrap();
    let PairComputations { leaves, .. } = Smt::sorted_pairs_to_leaves(entries).unwrap();
    // With two subtrees' worth of leaves, we should have exactly two subtrees.
    let [first, second]: [Vec<_>; 2] = leaves.try_into().unwrap();
    assert_eq!(first.len() as u64, PAIR_COUNT / 2);
    assert_eq!(first.len(), second.len());
    let mut current_depth = SMT_DEPTH;
    let mut next_leaves: Vec<SubtreeLeaf> = Default::default();
    let (first_nodes, first_root) = build_subtree(first, SMT_DEPTH, current_depth);
    next_leaves.push(first_root);
    let (second_nodes, second_root) = build_subtree(second, SMT_DEPTH, current_depth);
    next_leaves.push(second_root);
    // All new inner nodes + the new subtree-leaves should be 512, for one depth-cycle.
    let total_computed = first_nodes.len() + second_nodes.len() + next_leaves.len();
    assert_eq!(total_computed as u64, PAIR_COUNT);
    // Verify the computed nodes of both subtrees.
    let computed_nodes = first_nodes.into_iter().chain(second_nodes);
    for (index, test_node) in computed_nodes {
        let control_node = control.get_inner_node(index);
        assert_eq!(
            control_node, test_node,
            "subtree-computed node at index {index:?} does not match control",
        );
    }
    current_depth -= SUBTREE_DEPTH;
    let (nodes, root_leaf) = build_subtree(next_leaves, SMT_DEPTH, current_depth);
    assert_eq!(nodes.len(), SUBTREE_DEPTH as usize);
    assert_eq!(root_leaf.col, 0);
    for (index, test_node) in nodes {
        let control_node = control.get_inner_node(index);
        assert_eq!(
            control_node, test_node,
            "subtree-computed node at index {index:?} does not match control",
        );
    }
    let index = NodeIndex::new(current_depth - SUBTREE_DEPTH, root_leaf.col).unwrap();
    let control_root = control.get_inner_node(index).hash();
    assert_eq!(control_root, root_leaf.hash, "Root mismatch");
}

#[test]
fn test_singlethreaded_subtrees() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;
    let entries = generate_entries(PAIR_COUNT);
    let control = Smt::with_entries_sequential(entries.clone()).unwrap();
    let mut accumulated_nodes: BTreeMap<NodeIndex, InnerNode> = Default::default();
    let PairComputations {
        leaves: mut leaf_subtrees,
        nodes: test_leaves,
    } = Smt::sorted_pairs_to_leaves(entries).unwrap();
    for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
        // There's no flat_map_unzip(), so this is the best we can do.
        let (nodes, mut subtree_roots): (Vec<Map<_, _>>, Vec<SubtreeLeaf>) = leaf_subtrees
            .into_iter()
            .enumerate()
            .map(|(i, subtree)| {
                // Pre-assertions.
                assert!(
                    subtree.is_sorted(),
                    "subtree {i} at bottom-depth {current_depth} is not sorted",
                );
                assert!(
                    !subtree.is_empty(),
                    "subtree {i} at bottom-depth {current_depth} is empty!",
                );
                // Do actual things.
                let (nodes, subtree_root) = build_subtree(subtree, SMT_DEPTH, current_depth);
                // Post-assertions.
                for (&index, test_node) in nodes.iter() {
                    let control_node = control.get_inner_node(index);
                    assert_eq!(
                        test_node, &control_node,
                        "depth {current_depth} subtree {i}: test node does not match control at index {index:?}",
                    );
                }
                (nodes, subtree_root)
            })
            .unzip();
        // Update state between each depth iteration.
        leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
        accumulated_nodes.extend(nodes.into_iter().flatten());
        assert!(!leaf_subtrees.is_empty(), "on depth {current_depth}");
    }
    // Make sure the true leaves match, first checking length and then checking each individual
    // leaf.
    let control_leaves: BTreeMap<_, _> = control.leaves().collect();
    let control_leaves_len = control_leaves.len();
    let test_leaves_len = test_leaves.len();
    assert_eq!(test_leaves_len, control_leaves_len);
    for (col, ref test_leaf) in test_leaves {
        let index = LeafIndex::new_max_depth(col);
        let &control_leaf = control_leaves.get(&index).unwrap();
        assert_eq!(test_leaf, control_leaf, "test leaf at column {col} does not match control");
    }
    // Make sure the inner nodes match, checking length first and then each individual leaf.
    let control_nodes_len = control.inner_nodes().count();
    let test_nodes_len = accumulated_nodes.len();
    assert_eq!(test_nodes_len, control_nodes_len);
    for (index, test_node) in accumulated_nodes.clone() {
        let control_node = control.get_inner_node(index);
        assert_eq!(test_node, control_node, "test node does not match control at {index:?}");
    }
    // After the last iteration of the above for loop, we should have the new root node actually
    // in two places: one in `accumulated_nodes`, and the other as the "next leaves" return from
    // `build_subtree()`. So let's check both!
    let control_root = control.get_inner_node(NodeIndex::root());
    // That for loop should have left us with only one leaf subtree...
    let [leaf_subtree]: [Vec<_>; 1] = leaf_subtrees.try_into().unwrap();
    // which itself contains only one 'leaf'...
    let [root_leaf]: [SubtreeLeaf; 1] = leaf_subtree.try_into().unwrap();
    // which matches the expected root.
    assert_eq!(control.root(), root_leaf.hash);
    // Likewise `accumulated_nodes` should contain a node at the root index...
    assert!(accumulated_nodes.contains_key(&NodeIndex::root()));
    // and it should match our actual root.
    let test_root = accumulated_nodes.get(&NodeIndex::root()).unwrap();
    assert_eq!(control_root, *test_root);
    // And of course the root we got from each place should match.
    assert_eq!(control.root(), root_leaf.hash);
}

/// The parallel version of `test_singlethreaded_subtree()`.
#[test]
fn test_multithreaded_subtrees() {
    use p3_maybe_rayon::prelude::*;
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;
    let entries = generate_entries(PAIR_COUNT);
    let control = Smt::with_entries_sequential(entries.clone()).unwrap();
    let mut accumulated_nodes: BTreeMap<NodeIndex, InnerNode> = Default::default();
    let PairComputations {
        leaves: mut leaf_subtrees,
        nodes: test_leaves,
    } = Smt::sorted_pairs_to_leaves(entries).unwrap();
    for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
        let (nodes, mut subtree_roots): (Vec<Map<_, _>>, Vec<SubtreeLeaf>) = leaf_subtrees
            .into_par_iter()
            .enumerate()
            .map(|(i, subtree)| {
                // Pre-assertions.
                assert!(
                    subtree.is_sorted(),
                    "subtree {i} at bottom-depth {current_depth} is not sorted",
                );
                assert!(
                    !subtree.is_empty(),
                    "subtree {i} at bottom-depth {current_depth} is empty!",
                );
                let (nodes, subtree_root) = build_subtree(subtree, SMT_DEPTH, current_depth);
                // Post-assertions.
                for (&index, test_node) in nodes.iter() {
                    let control_node = control.get_inner_node(index);
                    assert_eq!(
                        test_node, &control_node,
                        "depth {current_depth} subtree {i}: test node does not match control at index {index:?}",
                    );
                }
                (nodes, subtree_root)
            })
            .unzip();
        leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
        accumulated_nodes.extend(nodes.into_iter().flatten());
        assert!(!leaf_subtrees.is_empty(), "on depth {current_depth}");
    }
    // Make sure the true leaves match, checking length first and then each individual leaf.
    let control_leaves: BTreeMap<_, _> = control.leaves().collect();
    let control_leaves_len = control_leaves.len();
    let test_leaves_len = test_leaves.len();
    assert_eq!(test_leaves_len, control_leaves_len);
    for (col, ref test_leaf) in test_leaves {
        let index = LeafIndex::new_max_depth(col);
        let &control_leaf = control_leaves.get(&index).unwrap();
        assert_eq!(test_leaf, control_leaf);
    }
    // Make sure the inner nodes match, checking length first and then each individual leaf.
    let control_nodes_len = control.inner_nodes().count();
    let test_nodes_len = accumulated_nodes.len();
    assert_eq!(test_nodes_len, control_nodes_len);
    for (index, test_node) in accumulated_nodes.clone() {
        let control_node = control.get_inner_node(index);
        assert_eq!(test_node, control_node, "test node does not match control at {index:?}");
    }
    // After the last iteration of the above for loop, we should have the new root node actually
    // in two places: one in `accumulated_nodes`, and the other as the "next leaves" return from
    // `build_subtree()`. So let's check both!
    let control_root = control.get_inner_node(NodeIndex::root());
    // That for loop should have left us with only one leaf subtree...
    let [leaf_subtree]: [_; 1] = leaf_subtrees.try_into().unwrap();
    // which itself contains only one 'leaf'...
    let [root_leaf]: [_; 1] = leaf_subtree.try_into().unwrap();
    // which matches the expected root.
    assert_eq!(control.root(), root_leaf.hash);
    // Likewise `accumulated_nodes` should contain a node at the root index...
    assert!(accumulated_nodes.contains_key(&NodeIndex::root()));
    // and it should match our actual root.
    let test_root = accumulated_nodes.get(&NodeIndex::root()).unwrap();
    assert_eq!(control_root, *test_root);
    // And of course the root we got from each place should match.
    assert_eq!(control.root(), root_leaf.hash);
}

#[test]
fn test_with_entries_concurrent() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;
    let mut entries = generate_entries(PAIR_COUNT);
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    // Set 10% of the entries to have empty words as their values.
    for _ in 0..PAIR_COUNT / 10 {
        let random_index = rng.random_range(0..PAIR_COUNT);
        entries[random_index as usize].1 = EMPTY_WORD;
    }

    let control = Smt::with_entries_sequential(entries.clone()).unwrap();
    let smt = Smt::with_entries(entries.clone()).unwrap();
    assert_eq!(smt.root(), control.root());
    assert_eq!(smt, control);
}

/// Concurrent mutations
#[test]
fn test_singlethreaded_subtree_mutations() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;
    let entries = generate_entries(PAIR_COUNT);
    let updates = generate_updates(entries.clone(), 1000);
    let tree = Smt::with_entries_sequential(entries).unwrap();
    let control = tree.compute_mutations_sequential(updates.clone()).unwrap();
    let mut node_mutations = NodeMutations::default();
    let (mut subtree_leaves, new_pairs) =
        tree.sorted_pairs_to_mutated_subtree_leaves(updates).unwrap();
    for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
        // There's no flat_map_unzip(), so this is the best we can do.
        let (mutations_per_subtree, mut subtree_roots): (Vec<_>, Vec<_>) = subtree_leaves
            .into_iter()
            .enumerate()
            .map(|(i, subtree)| {
                // Pre-assertions.
                assert!(
                    subtree.is_sorted(),
                    "subtree {i} at bottom-depth {current_depth} is not sorted",
                );
                assert!(
                    !subtree.is_empty(),
                    "subtree {i} at bottom-depth {current_depth} is empty!",
                );
                // Calculate the mutations for this subtree.
                let (mutations_per_subtree, subtree_root) =
                    tree.build_subtree_mutations(subtree, SMT_DEPTH, current_depth);
                // Check that the mutations match the control tree.
                for (&index, mutation) in mutations_per_subtree.iter() {
                    let control_mutation = control.node_mutations().get(&index).unwrap();
                    assert_eq!(
                        control_mutation, mutation,
                        "depth {current_depth} subtree {i}: mutation does not match control at index {index:?}",
                    );
                }
                (mutations_per_subtree, subtree_root)
            })
            .unzip();
        subtree_leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
        node_mutations.extend(mutations_per_subtree.into_iter().flatten());
        assert!(!subtree_leaves.is_empty(), "on depth {current_depth}");
    }
    let [subtree]: [Vec<_>; 1] = subtree_leaves.try_into().unwrap();
    let [root_leaf]: [SubtreeLeaf; 1] = subtree.try_into().unwrap();
    // Check that the new root matches the control.
    assert_eq!(control.new_root, root_leaf.hash);
    // Check that the node mutations match the control.
    assert_eq!(control.node_mutations().len(), node_mutations.len());
    for (&index, mutation) in control.node_mutations().iter() {
        let test_mutation = node_mutations.get(&index).unwrap();
        assert_eq!(test_mutation, mutation);
    }
    // Check that the new pairs match the control
    assert_eq!(control.new_pairs.len(), new_pairs.len());
    for (&key, &value) in control.new_pairs.iter() {
        let test_value = new_pairs.get(&key).unwrap();
        assert_eq!(test_value, &value);
    }
}

#[test]
fn test_compute_mutations_parallel() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;
    let entries = generate_entries(PAIR_COUNT);
    let tree = Smt::with_entries(entries.clone()).unwrap();
    let updates = generate_updates(entries, 1000);
    let control = tree.compute_mutations_sequential(updates.clone()).unwrap();
    let mutations = tree.compute_mutations(updates).unwrap();
    assert_eq!(mutations.root(), control.root());
    assert_eq!(mutations.old_root(), control.old_root());
    assert_eq!(mutations.node_mutations(), control.node_mutations());
    assert_eq!(mutations.new_pairs(), control.new_pairs());
}

#[test]
fn test_smt_construction_with_entries_unsorted() {
    let entries = [
        ([ONE, ONE, Felt::new_unchecked(2_u64), ONE].into(), [ONE; 4].into()),
        ([ONE; 4].into(), [ONE; 4].into()),
    ];
    let control = Smt::with_entries_sequential(entries).unwrap();
    let smt = Smt::with_entries(entries).unwrap();
    assert_eq!(smt.root(), control.root());
    assert_eq!(smt, control);
}

#[test]
fn test_smt_construction_with_entries_duplicate_keys() {
    let entries = [
        ([ONE, ONE, ONE, Felt::new_unchecked(16)].into(), [ONE; 4].into()),
        ([ONE; 4].into(), [ONE; 4].into()),
        ([ONE, ONE, ONE, Felt::new_unchecked(16)].into(), [ONE; 4].into()),
    ];
    let expected_col = Smt::key_to_leaf_index(&entries[0].0).index.position();
    let err = Smt::with_entries(entries).unwrap_err();
    assert_matches!(err, MerkleError::DuplicateValuesForIndex(col) if col == expected_col);
}

#[test]
fn test_smt_construction_with_some_empty_values() {
    let entries = [
        ([ONE, ONE, ONE, ONE].into(), Smt::EMPTY_VALUE),
        ([ONE, ONE, ONE, Felt::new_unchecked(2)].into(), [ONE; 4].into()),
    ];

    let result = Smt::with_entries(entries);
    assert!(result.is_ok(), "SMT construction failed with mixed empty values");

    let smt = result.unwrap();
    let control = Smt::with_entries_sequential(entries).unwrap();

    assert_eq!(smt.num_leaves(), 1);
    assert_eq!(smt.root(), control.root(), "Root hashes do not match");
    assert_eq!(smt, control, "SMTs are not equal");
}

#[test]
fn test_smt_construction_with_all_empty_values() {
    let entries = [([ONE, ONE, ONE, ONE].into(), Smt::EMPTY_VALUE)];

    let result = Smt::with_entries(entries);
    assert!(result.is_ok(), "SMT construction failed with all empty values");

    let smt = result.unwrap();

    assert_eq!(
        smt.root(),
        Smt::default().root(),
        "SMT with all empty values should have the same root as the default SMT"
    );
    assert_eq!(smt, Smt::default(), "SMT with all empty values should be empty");
}

#[test]
fn test_smt_construction_with_no_entries() {
    let entries: [(Word, Word); 0] = [];

    let result = Smt::with_entries(entries);
    assert!(result.is_ok(), "SMT construction failed with no entries");

    let smt = result.unwrap();
    assert_eq!(smt, Smt::default(), "SMT with no entries should be empty");
}

fn arb_felt() -> impl Strategy<Value = Felt> {
    prop_oneof![any::<u64>().prop_map(Felt::new_unchecked), Just(ZERO), Just(ONE),]
}

/// Test that the debug assertion panics on unsorted entries.
#[test]
#[should_panic = "is_sorted_by_key"]
fn smt_with_sorted_entries_panics_on_unsorted_entries() {
    // Unsorted keys.
    let smt_leaves_2: [(Word, Word); 2] = [
        (
            Word::new([
                Felt::new_unchecked(105),
                Felt::new_unchecked(106),
                Felt::new_unchecked(107),
                Felt::new_unchecked(108),
            ]),
            [
                Felt::new_unchecked(5_u64),
                Felt::new_unchecked(6_u64),
                Felt::new_unchecked(7_u64),
                Felt::new_unchecked(8_u64),
            ]
            .into(),
        ),
        (
            Word::new([
                Felt::new_unchecked(101),
                Felt::new_unchecked(102),
                Felt::new_unchecked(103),
                Felt::new_unchecked(104),
            ]),
            [
                Felt::new_unchecked(1_u64),
                Felt::new_unchecked(2_u64),
                Felt::new_unchecked(3_u64),
                Felt::new_unchecked(4_u64),
            ]
            .into(),
        ),
    ];

    // Should panic because entries are not sorted.
    Smt::with_sorted_entries(smt_leaves_2).unwrap();
}

#[test]
fn test_with_sorted_entries_large_num_leaves() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 8;
    let entries = generate_entries(PAIR_COUNT);
    let control = Smt::with_entries_sequential(entries.clone()).unwrap();
    // `entries` should already be sorted by nature of how we constructed it.
    let actual = Smt::with_sorted_entries(entries).unwrap();
    assert_eq!(actual, control);
}

/// Generate entries that are guaranteed to be in different subtrees
fn generate_cross_subtree_entries() -> impl Strategy<Value = Vec<(Word, Word)>> {
    let subtree_offsets = prop::collection::vec(0..(COLS_PER_SUBTREE * 4), 1..100);

    subtree_offsets.prop_map(|offsets| {
        offsets
            .into_iter()
            .map(|base_col| {
                let key = Word::new([ONE, ONE, ONE, Felt::new_unchecked(base_col)]);
                let value = Word::new([ONE, ONE, ONE, Felt::new_unchecked(base_col)]);
                (key, value)
            })
            .collect()
    })
}

fn arb_entries() -> impl Strategy<Value = Vec<(Word, Word)>> {
    // Combine random entries with guaranteed cross-subtree entries
    prop_oneof![
        // Original random entry generation
        prop::collection::vec(
            prop_oneof![
                // Random values case
                (
                    prop::array::uniform4(arb_felt()).prop_map(Word::new),
                    prop::array::uniform4(arb_felt()).prop_map(Word::new)
                ),
                // Edge case values
                (
                    Just([ONE, ONE, ONE, Felt::new_unchecked(0)].into()),
                    Just([ONE, ONE, ONE, Felt::new_unchecked(u64::MAX)].into())
                )
            ],
            1..1000,
        ),
        // Guaranteed cross-subtree entries
        generate_cross_subtree_entries(),
        // Mix of both (combine random and cross-subtree entries)
        (
            generate_cross_subtree_entries(),
            prop::collection::vec(
                (
                    prop::array::uniform4(arb_felt()).prop_map(Word::new),
                    prop::array::uniform4(arb_felt()).prop_map(Word::new)
                ),
                1..1000,
            )
        )
            .prop_map(|(mut cross_subtree, mut random)| {
                cross_subtree.append(&mut random);
                cross_subtree
            })
    ]
    .prop_map(|entries| {
        // Ensure uniqueness of entries as `Smt::with_entries` returns an error if multiple values
        // exist for the same key.
        let mut used_indices = BTreeSet::new();
        let mut used_keys = BTreeSet::new();
        let mut result = Vec::new();

        for (key, value) in entries {
            let leaf_index = LeafIndex::<SMT_DEPTH>::from(key).position();
            if used_indices.insert(leaf_index) && used_keys.insert(key) {
                result.push((key, value));
            }
        }
        result
    })
}

proptest! {
    #[test]
    fn test_with_entries_consistency(entries in arb_entries()) {
        let sequential = Smt::with_entries_sequential(entries.clone()).unwrap();
        let concurrent = Smt::with_entries(entries).unwrap();
        prop_assert_eq!(concurrent, sequential);
    }

    #[test]
    fn test_compute_mutations_consistency(
        initial_entries in arb_entries(),
        update_entries in arb_entries().prop_filter(
            "Update must not be empty and must differ from initial entries",
            |updates| !updates.is_empty()
        )
    ) {
        let tree = Smt::with_entries_sequential(initial_entries.clone()).unwrap();

        let has_real_changes = update_entries.iter().any(|(key, value)| {
            match initial_entries.iter().find(|(init_key, _)| init_key == key) {
                Some((_, init_value)) => init_value != value,
                None => *value != EMPTY_WORD,
            }
        });

        let sequential = tree.compute_mutations_sequential(update_entries.clone()).unwrap();
        let concurrent = tree.compute_mutations(update_entries).unwrap();

        // If there are real changes, the root should change
        if has_real_changes {
            let sequential_changed = sequential.old_root != sequential.new_root;
            let concurrent_changed = concurrent.old_root != concurrent.new_root;

            prop_assert!(
                sequential_changed || concurrent_changed,
                "Root should have changed"
            );
        }

        prop_assert_eq!(sequential.old_root, concurrent.old_root);
        prop_assert_eq!(sequential.new_root, concurrent.new_root);
        prop_assert_eq!(sequential.node_mutations(), concurrent.node_mutations());
        prop_assert_eq!(sequential.new_pairs.len(), concurrent.new_pairs.len());
    }
}
