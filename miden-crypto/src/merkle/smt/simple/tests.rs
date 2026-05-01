use alloc::{collections::BTreeMap, vec::Vec};

use assert_matches::assert_matches;
use proptest::prelude::*;

use super::{
    super::{MerkleError, SimpleSmt, Word},
    NodeIndex,
};
use crate::{
    EMPTY_WORD,
    hash::poseidon2::Poseidon2,
    merkle::{
        EmptySubtreeRoots, InnerNodeInfo, MerklePath, MerkleTree, int_to_leaf, int_to_node,
        smt::{LeafIndex, SparseMerkleTreeReader},
    },
};

// TEST DATA
// ================================================================================================

const KEYS4: [u64; 4] = [0, 1, 2, 3];
const KEYS8: [u64; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

const VALUES4: [Word; 4] = [int_to_node(1), int_to_node(2), int_to_node(3), int_to_node(4)];

const VALUES8: [Word; 8] = [
    int_to_node(1),
    int_to_node(2),
    int_to_node(3),
    int_to_node(4),
    int_to_node(5),
    int_to_node(6),
    int_to_node(7),
    int_to_node(8),
];

const ZERO_VALUES8: [Word; 8] = [int_to_leaf(0); 8];

// TESTS
// ================================================================================================

#[test]
fn build_empty_tree() {
    // tree of depth 3
    let smt = SimpleSmt::<3>::new().unwrap();
    let mt = MerkleTree::new(ZERO_VALUES8).unwrap();
    assert_eq!(mt.root(), smt.root());
}

#[test]
fn build_sparse_tree() {
    const DEPTH: u8 = 3;
    let mut smt = SimpleSmt::<DEPTH>::new().unwrap();
    let mut values = ZERO_VALUES8.to_vec();

    assert_eq!(smt.num_leaves(), 0);

    // insert single value
    let key = 6;
    let new_node = int_to_leaf(7);
    values[key as usize] = new_node;
    let old_value = smt.insert(LeafIndex::<DEPTH>::new(key).unwrap(), new_node);
    let mt2 = MerkleTree::new(values.clone()).unwrap();
    assert_eq!(mt2.root(), smt.root());
    assert_eq!(
        mt2.get_path(NodeIndex::make(3, 6)).unwrap(),
        smt.open(&LeafIndex::<3>::new(6).unwrap()).path
    );
    assert_eq!(old_value, EMPTY_WORD);
    assert_eq!(smt.num_leaves(), 1);

    // insert second value at distinct leaf branch
    let key = 2;
    let new_node = int_to_leaf(3);
    values[key as usize] = new_node;
    let old_value = smt.insert(LeafIndex::<DEPTH>::new(key).unwrap(), new_node);
    let mt3 = MerkleTree::new(values).unwrap();
    assert_eq!(mt3.root(), smt.root());
    assert_eq!(
        mt3.get_path(NodeIndex::make(3, 2)).unwrap(),
        smt.open(&LeafIndex::<3>::new(2).unwrap()).path
    );
    assert_eq!(old_value, EMPTY_WORD);
    assert_eq!(smt.num_leaves(), 2);
}

/// Tests that [`SimpleSmt::with_contiguous_leaves`] works as expected
#[test]
fn build_contiguous_tree() {
    let tree_with_leaves =
        SimpleSmt::<2>::with_leaves([0, 1, 2, 3].into_iter().zip(VALUES4.to_vec())).unwrap();

    let tree_with_contiguous_leaves =
        SimpleSmt::<2>::with_contiguous_leaves(VALUES4.to_vec()).unwrap();

    assert_eq!(tree_with_leaves, tree_with_contiguous_leaves);
}

#[test]
fn test_depth2_tree() {
    let tree = SimpleSmt::<2>::with_leaves(KEYS4.into_iter().zip(VALUES4.to_vec())).unwrap();

    // check internal structure
    let (root, node2, node3) = compute_internal_nodes();
    assert_eq!(root, tree.root());
    assert_eq!(node2, tree.get_node(NodeIndex::make(1, 0)).unwrap());
    assert_eq!(node3, tree.get_node(NodeIndex::make(1, 1)).unwrap());

    // check get_node()
    assert_eq!(VALUES4[0], tree.get_node(NodeIndex::make(2, 0)).unwrap());
    assert_eq!(VALUES4[1], tree.get_node(NodeIndex::make(2, 1)).unwrap());
    assert_eq!(VALUES4[2], tree.get_node(NodeIndex::make(2, 2)).unwrap());
    assert_eq!(VALUES4[3], tree.get_node(NodeIndex::make(2, 3)).unwrap());

    // check get_path(): depth 2
    assert_eq!(
        MerklePath::from(vec![VALUES4[1], node3]),
        tree.open(&LeafIndex::<2>::new(0).unwrap()).path,
    );
    assert_eq!(
        MerklePath::from(vec![VALUES4[0], node3]),
        tree.open(&LeafIndex::<2>::new(1).unwrap()).path,
    );
    assert_eq!(
        MerklePath::from(vec![VALUES4[3], node2]),
        tree.open(&LeafIndex::<2>::new(2).unwrap()).path,
    );
    assert_eq!(
        MerklePath::from(vec![VALUES4[2], node2]),
        tree.open(&LeafIndex::<2>::new(3).unwrap()).path,
    );
}

#[test]
fn test_inner_node_iterator() -> Result<(), MerkleError> {
    let tree = SimpleSmt::<2>::with_leaves(KEYS4.into_iter().zip(VALUES4.to_vec())).unwrap();

    // check depth 2
    assert_eq!(VALUES4[0], tree.get_node(NodeIndex::make(2, 0)).unwrap());
    assert_eq!(VALUES4[1], tree.get_node(NodeIndex::make(2, 1)).unwrap());
    assert_eq!(VALUES4[2], tree.get_node(NodeIndex::make(2, 2)).unwrap());
    assert_eq!(VALUES4[3], tree.get_node(NodeIndex::make(2, 3)).unwrap());

    // get parent nodes
    let root = tree.root();
    let l1n0 = tree.get_node(NodeIndex::make(1, 0))?;
    let l1n1 = tree.get_node(NodeIndex::make(1, 1))?;
    let l2n0 = tree.get_node(NodeIndex::make(2, 0))?;
    let l2n1 = tree.get_node(NodeIndex::make(2, 1))?;
    let l2n2 = tree.get_node(NodeIndex::make(2, 2))?;
    let l2n3 = tree.get_node(NodeIndex::make(2, 3))?;

    let mut nodes: Vec<InnerNodeInfo> = tree.inner_nodes().collect();
    let mut expected = [
        InnerNodeInfo { value: root, left: l1n0, right: l1n1 },
        InnerNodeInfo { value: l1n0, left: l2n0, right: l2n1 },
        InnerNodeInfo { value: l1n1, left: l2n2, right: l2n3 },
    ];
    nodes.sort();
    expected.sort();

    assert_eq!(nodes, expected);

    Ok(())
}

#[test]
fn test_insert() {
    const DEPTH: u8 = 3;
    let mut tree =
        SimpleSmt::<DEPTH>::with_leaves(KEYS8.into_iter().zip(VALUES8.to_vec())).unwrap();
    assert_eq!(tree.num_leaves(), 8);

    // update one value
    let key = 3;
    let new_node = int_to_leaf(9);
    let mut expected_values = VALUES8.to_vec();
    expected_values[key] = new_node;
    let expected_tree = MerkleTree::new(expected_values.clone()).unwrap();

    let old_leaf = tree.insert(LeafIndex::<DEPTH>::new(key as u64).unwrap(), new_node);
    assert_eq!(expected_tree.root(), tree.root);
    assert_eq!(old_leaf, VALUES8[key]);
    assert_eq!(tree.num_leaves(), 8);

    // update another value
    let key = 6;
    let new_node = int_to_leaf(10);
    expected_values[key] = new_node;
    let expected_tree = MerkleTree::new(expected_values.clone()).unwrap();

    let old_leaf = tree.insert(LeafIndex::<DEPTH>::new(key as u64).unwrap(), new_node);
    assert_eq!(expected_tree.root(), tree.root);
    assert_eq!(old_leaf, VALUES8[key]);
    assert_eq!(tree.num_leaves(), 8);

    // set a leaf to empty value
    let key = 5;
    let new_node = EMPTY_WORD;
    expected_values[key] = new_node;
    let expected_tree = MerkleTree::new(expected_values.clone()).unwrap();

    let old_leaf = tree.insert(LeafIndex::<DEPTH>::new(key as u64).unwrap(), new_node);
    assert_eq!(expected_tree.root(), tree.root);
    assert_eq!(old_leaf, VALUES8[key]);
    assert_eq!(tree.num_leaves(), 7);
}

#[test]
fn small_tree_opening_is_consistent() {
    //        ____k____
    //       /         \
    //     _i_         _j_
    //    /   \       /   \
    //   e     f     g     h
    //  / \   / \   / \   / \
    // a   b 0   0 c   0 0   d

    let z = EMPTY_WORD;

    let a = Poseidon2::merge(&[z; 2]);
    let b = Poseidon2::merge(&[a; 2]);
    let c = Poseidon2::merge(&[b; 2]);
    let d = Poseidon2::merge(&[c; 2]);

    let e = Poseidon2::merge(&[a, b]);
    let f = Poseidon2::merge(&[z, z]);
    let g = Poseidon2::merge(&[c, z]);
    let h = Poseidon2::merge(&[z, d]);

    let i = Poseidon2::merge(&[e, f]);
    let j = Poseidon2::merge(&[g, h]);

    let k = Poseidon2::merge(&[i, j]);

    let entries = vec![(0, a), (1, b), (4, c), (7, d)];
    let tree = SimpleSmt::<3>::with_leaves(entries).unwrap();

    assert_eq!(tree.root(), k);

    let cases: Vec<(u64, Vec<Word>)> =
        vec![(0, vec![b, f, j]), (1, vec![a, f, j]), (4, vec![z, h, i]), (7, vec![z, g, i])];

    for (key, path) in cases {
        let opening = tree.open(&LeafIndex::<3>::new(key).unwrap());

        assert_eq!(MerklePath::from(path), opening.path);
    }
}

#[test]
fn test_simplesmt_fail_on_duplicates() {
    let values = [
        // same key, same value
        (int_to_leaf(1), int_to_leaf(1)),
        // same key, different values
        (int_to_leaf(1), int_to_leaf(2)),
        // same key, set to zero
        (EMPTY_WORD, int_to_leaf(1)),
        // same key, re-set to zero
        (int_to_leaf(1), EMPTY_WORD),
        // same key, set to zero twice
        (EMPTY_WORD, EMPTY_WORD),
    ];

    for (first, second) in values.iter() {
        // consecutive
        let entries = [(1, *first), (1, *second)];
        let smt = SimpleSmt::<64>::with_leaves(entries);
        assert_matches!(smt.unwrap_err(), MerkleError::DuplicateValuesForIndex(1));

        // not consecutive
        let entries = [(1, *first), (5, int_to_leaf(5)), (1, *second)];
        let smt = SimpleSmt::<64>::with_leaves(entries);
        assert_matches!(smt.unwrap_err(), MerkleError::DuplicateValuesForIndex(1));
    }
}

#[test]
fn with_no_duplicates_empty_node() {
    let entries = [(1_u64, int_to_leaf(0)), (5, int_to_leaf(2))];
    let smt = SimpleSmt::<64>::with_leaves(entries);
    assert!(smt.is_ok());
}

#[test]
fn test_simplesmt_with_leaves_nonexisting_leaf() {
    // TESTING WITH EMPTY WORD
    // --------------------------------------------------------------------------------------------

    // Depth 1 has 2 leaf. Position is 0-indexed, position 2 doesn't exist.
    let leaves = [(2, EMPTY_WORD)];
    let result = SimpleSmt::<1>::with_leaves(leaves);
    assert!(result.is_err());

    // Depth 2 has 4 leaves. Position is 0-indexed, position 4 doesn't exist.
    let leaves = [(4, EMPTY_WORD)];
    let result = SimpleSmt::<2>::with_leaves(leaves);
    assert!(result.is_err());

    // Depth 3 has 8 leaves. Position is 0-indexed, position 8 doesn't exist.
    let leaves = [(8, EMPTY_WORD)];
    let result = SimpleSmt::<3>::with_leaves(leaves);
    assert!(result.is_err());

    // TESTING WITH A VALUE
    // --------------------------------------------------------------------------------------------
    let value = int_to_node(1);

    // Depth 1 has 2 leaves. Position is 0-indexed, position 2 doesn't exist.
    let leaves = [(2, value)];
    let result = SimpleSmt::<1>::with_leaves(leaves);
    assert!(result.is_err());

    // Depth 2 has 4 leaves. Position is 0-indexed, position 4 doesn't exist.
    let leaves = [(4, value)];
    let result = SimpleSmt::<2>::with_leaves(leaves);
    assert!(result.is_err());

    // Depth 3 has 8 leaves. Position is 0-indexed, position 8 doesn't exist.
    let leaves = [(8, value)];
    let result = SimpleSmt::<3>::with_leaves(leaves);
    assert!(result.is_err());
}

#[test]
fn test_simplesmt_set_subtree() {
    // Final Tree:
    //
    //        ____k____
    //       /         \
    //     _i_         _j_
    //    /   \       /   \
    //   e     f     g     h
    //  / \   / \   / \   / \
    // a   b 0   0 c   0 0   d

    let z = EMPTY_WORD;

    let a = Poseidon2::merge(&[z; 2]);
    let b = Poseidon2::merge(&[a; 2]);
    let c = Poseidon2::merge(&[b; 2]);
    let d = Poseidon2::merge(&[c; 2]);

    let e = Poseidon2::merge(&[a, b]);
    let f = Poseidon2::merge(&[z, z]);
    let g = Poseidon2::merge(&[c, z]);
    let h = Poseidon2::merge(&[z, d]);

    let i = Poseidon2::merge(&[e, f]);
    let j = Poseidon2::merge(&[g, h]);

    let k = Poseidon2::merge(&[i, j]);

    // subtree:
    //   g
    //  / \
    // c   0
    let subtree = {
        let entries = vec![(0, c)];
        SimpleSmt::<1>::with_leaves(entries).unwrap()
    };

    // insert subtree
    const TREE_DEPTH: u8 = 3;
    let tree = {
        let entries = vec![(0, a), (1, b), (7, d)];
        let mut tree = SimpleSmt::<TREE_DEPTH>::with_leaves(entries).unwrap();

        tree.set_subtree(2, subtree).unwrap();

        tree
    };

    assert_eq!(tree.root(), k);
    assert_eq!(tree.get_leaf(&LeafIndex::<TREE_DEPTH>::new(4).unwrap()), c);
    assert_eq!(tree.get_inner_node(NodeIndex::new_unchecked(2, 2)).hash(), g);
}

/// Ensures that an invalid input node index into `set_subtree()` incurs no mutation of the tree
#[test]
fn test_simplesmt_set_subtree_unchanged_for_wrong_index() {
    // Final Tree:
    //
    //        ____k____
    //       /         \
    //     _i_         _j_
    //    /   \       /   \
    //   e     f     g     h
    //  / \   / \   / \   / \
    // a   b 0   0 c   0 0   d

    let z = EMPTY_WORD;

    let a = Poseidon2::merge(&[z; 2]);
    let b = Poseidon2::merge(&[a; 2]);
    let c = Poseidon2::merge(&[b; 2]);
    let d = Poseidon2::merge(&[c; 2]);

    // subtree:
    //   g
    //  / \
    // c   0
    let subtree = {
        let entries = vec![(0, c)];
        SimpleSmt::<1>::with_leaves(entries).unwrap()
    };

    let mut tree = {
        let entries = vec![(0, a), (1, b), (7, d)];
        SimpleSmt::<3>::with_leaves(entries).unwrap()
    };
    let tree_root_before_insertion = tree.root();

    // insert subtree
    assert!(tree.set_subtree(500, subtree).is_err());

    assert_eq!(tree.root(), tree_root_before_insertion);
}

// Covers whole-tree replacement, where the subtree depth equals the tree depth.
#[test]
fn test_simplesmt_set_subtree_entire_tree() {
    // Initial Tree:
    //
    //        ____k____
    //       /         \
    //     _i_         _j_
    //    /   \       /   \
    //   e     f     g     h
    //  / \   / \   / \   / \
    // a   b 0   0 c   0 0   d

    let z = EMPTY_WORD;

    let a = Poseidon2::merge(&[z; 2]);
    let b = Poseidon2::merge(&[a; 2]);
    let c = Poseidon2::merge(&[b; 2]);
    let d = Poseidon2::merge(&[c; 2]);

    // subtree: E3
    const DEPTH: u8 = 3;
    let subtree = { SimpleSmt::<DEPTH>::with_leaves(Vec::new()).unwrap() };
    assert_eq!(subtree.root(), *EmptySubtreeRoots::entry(DEPTH, 0));

    // insert subtree
    let mut tree = {
        let entries = vec![(0, a), (1, b), (4, c), (7, d)];
        SimpleSmt::<3>::with_leaves(entries).unwrap()
    };

    tree.set_subtree(0, subtree).unwrap();

    assert_eq!(tree.root(), *EmptySubtreeRoots::entry(DEPTH, 0));
    assert_eq!(tree.num_leaves(), 0);
    assert!(tree.is_empty());
    assert_eq!(tree.inner_nodes().count(), 0);
}

/// Verifies that `set_subtree()` removes stale leaves and inner nodes in the insertion region.
#[test]
fn test_simplesmt_set_subtree_clears_region() {
    let z = EMPTY_WORD;

    let a = Poseidon2::merge(&[z; 2]);
    let b = Poseidon2::merge(&[a; 2]);
    let c = Poseidon2::merge(&[b; 2]);
    let d = Poseidon2::merge(&[c; 2]);

    let mut tree = {
        let entries = vec![(0, a), (1, b), (4, c), (5, d), (7, d)];
        SimpleSmt::<3>::with_leaves(entries).unwrap()
    };

    let empty_subtree = SimpleSmt::<1>::new().unwrap();
    tree.set_subtree(2, empty_subtree).unwrap();

    assert_eq!(tree.num_leaves(), 3);
    assert_eq!(tree.get_leaf(&LeafIndex::<3>::new(0).unwrap()), a);
    assert_eq!(tree.get_leaf(&LeafIndex::<3>::new(1).unwrap()), b);
    assert_eq!(tree.get_leaf(&LeafIndex::<3>::new(4).unwrap()), EMPTY_WORD);
    assert_eq!(tree.get_leaf(&LeafIndex::<3>::new(5).unwrap()), EMPTY_WORD);
    assert_eq!(tree.get_leaf(&LeafIndex::<3>::new(7).unwrap()), d);
    assert_eq!(tree.get_node(NodeIndex::make(2, 2)).unwrap(), *EmptySubtreeRoots::entry(3, 2));
}

#[test]
fn test_simplesmt_set_subtree_replaces_populated_region() {
    let z = EMPTY_WORD;

    let a = Poseidon2::merge(&[z; 2]);
    let b = Poseidon2::merge(&[a; 2]);
    let c = Poseidon2::merge(&[b; 2]);
    let d = Poseidon2::merge(&[c; 2]);

    let subtree = SimpleSmt::<1>::with_leaves(vec![(1, c)]).unwrap();
    let mut tree = {
        let entries = vec![(0, a), (1, b), (4, d), (5, d), (7, d)];
        SimpleSmt::<3>::with_leaves(entries).unwrap()
    };

    tree.set_subtree(2, subtree).unwrap();

    let expected_tree = {
        let entries = vec![(0, a), (1, b), (5, c), (7, d)];
        SimpleSmt::<3>::with_leaves(entries).unwrap()
    };

    assert_eq!(tree.root(), expected_tree.root());
    assert_eq!(tree.num_leaves(), expected_tree.num_leaves());
    assert_eq!(tree.get_leaf(&LeafIndex::<3>::new(4).unwrap()), EMPTY_WORD);
    assert_eq!(tree.get_leaf(&LeafIndex::<3>::new(5).unwrap()), c);
    assert_eq!(
        tree.open(&LeafIndex::<3>::new(5).unwrap()),
        expected_tree.open(&LeafIndex::<3>::new(5).unwrap())
    );
}

// Covers depth-64 indexing, including `u64::MAX`, outside the bounded proptest.
#[test]
fn test_simplesmt_set_subtree_clears_depth_64_tree() {
    let a = int_to_node(1);
    let b = int_to_node(2);
    let subtree = SimpleSmt::<64>::new().unwrap();
    let mut tree = SimpleSmt::<64>::with_leaves(vec![(0, a), (u64::MAX, b)]).unwrap();

    tree.set_subtree(0, subtree).unwrap();

    assert_eq!(tree.root(), SimpleSmt::<64>::EMPTY_ROOT);
    assert_eq!(tree.num_leaves(), 0);
    assert!(tree.is_empty());
    assert_eq!(tree.inner_nodes().count(), 0);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_simplesmt_set_subtree_matches_rebuilt_tree(
        initial_entries in prop::collection::vec((0_u64..16, 1_u64..1000), 0..16),
        subtree_entries in prop::collection::vec((0_u64..4, 1_u64..1000), 0..4),
        subtree_insertion_index in 0_u64..4,
    ) {
        const TREE_DEPTH: u8 = 4;
        const SUBTREE_DEPTH: u8 = 2;

        let initial_entries = to_entries(initial_entries);
        let subtree_entries = to_entries(subtree_entries);

        let mut tree = SimpleSmt::<TREE_DEPTH>::with_leaves(initial_entries.clone()).unwrap();
        let subtree = SimpleSmt::<SUBTREE_DEPTH>::with_leaves(subtree_entries.clone()).unwrap();
        tree.set_subtree(subtree_insertion_index, subtree).unwrap();

        let expected_entries =
            expected_entries_after_set_subtree::<SUBTREE_DEPTH>(
                initial_entries,
                subtree_entries,
                subtree_insertion_index,
            );
        let expected_tree = SimpleSmt::<TREE_DEPTH>::with_leaves(expected_entries).unwrap();

        prop_assert_eq!(tree.root(), expected_tree.root());
        prop_assert_eq!(tree.num_leaves(), expected_tree.num_leaves());

        for leaf_idx in 0..16 {
            let leaf_idx = LeafIndex::<TREE_DEPTH>::new(leaf_idx).unwrap();
            prop_assert_eq!(tree.get_leaf(&leaf_idx), expected_tree.get_leaf(&leaf_idx));
            prop_assert_eq!(tree.open(&leaf_idx), expected_tree.open(&leaf_idx));
        }

        for depth in 1..TREE_DEPTH {
            for position in 0..(1_u64 << depth) {
                let index = NodeIndex::new(depth, position).unwrap();
                prop_assert_eq!(tree.get_node(index).unwrap(), expected_tree.get_node(index).unwrap());
            }
        }
    }
}

fn to_entries(entries: Vec<(u64, u64)>) -> Vec<(u64, Word)> {
    entries
        .into_iter()
        .map(|(key, value)| (key, int_to_node(value)))
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .collect()
}

fn expected_entries_after_set_subtree<const SUBTREE_DEPTH: u8>(
    initial_entries: Vec<(u64, Word)>,
    subtree_entries: Vec<(u64, Word)>,
    subtree_insertion_index: u64,
) -> Vec<(u64, Word)> {
    let leaf_index_shift = subtree_insertion_index << u32::from(SUBTREE_DEPTH);
    let mut expected_entries: BTreeMap<_, _> = initial_entries
        .into_iter()
        .filter(|(leaf_idx, _)| (leaf_idx >> u32::from(SUBTREE_DEPTH)) != subtree_insertion_index)
        .collect();

    expected_entries.extend(
        subtree_entries
            .into_iter()
            .map(|(leaf_idx, value)| (leaf_index_shift + leaf_idx, value)),
    );

    expected_entries.into_iter().collect()
}

/// Tests that `EMPTY_ROOT` constant generated in the `SimpleSmt` equals to the root of the empty
/// tree of depth 64
#[test]
fn test_simplesmt_check_empty_root_constant() {
    // get the root of the empty tree of depth 64
    let empty_root_64_depth = EmptySubtreeRoots::empty_hashes(64)[0];
    assert_eq!(empty_root_64_depth, SimpleSmt::<64>::EMPTY_ROOT);

    // get the root of the empty tree of depth 32
    let empty_root_32_depth = EmptySubtreeRoots::empty_hashes(32)[0];
    assert_eq!(empty_root_32_depth, SimpleSmt::<32>::EMPTY_ROOT);

    // get the root of the empty tree of depth 0
    let empty_root_1_depth = EmptySubtreeRoots::empty_hashes(1)[0];
    assert_eq!(empty_root_1_depth, SimpleSmt::<1>::EMPTY_ROOT);
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn compute_internal_nodes() -> (Word, Word, Word) {
    let node2 = Poseidon2::merge(&[VALUES4[0], VALUES4[1]]);
    let node3 = Poseidon2::merge(&[VALUES4[2], VALUES4[3]]);
    let root = Poseidon2::merge(&[node2, node3]);

    (root, node2, node3)
}
