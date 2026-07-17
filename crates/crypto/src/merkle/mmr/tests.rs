use alloc::vec::Vec;

use assert_matches::assert_matches;

use super::{
    super::{InnerNodeInfo, Poseidon2, Word},
    Mmr, MmrError, MmrPeaks, PartialMmr, nodes_from_mask,
};
use crate::{
    Felt,
    merkle::{
        MerklePath, MerkleTree, NodeIndex, int_to_node,
        mmr::{
            InOrderIndex, MmrPath, MmrProof,
            forest::{Forest, TreeSizeIterator, high_bitmask},
        },
    },
};

#[test]
fn tests_empty_mmr_peaks() {
    let peaks = MmrPeaks::default();
    assert_eq!(peaks.num_peaks(), 0);
    assert_eq!(peaks.num_leaves(), 0);
}

#[test]
fn test_empty_partial_mmr() {
    let mmr = PartialMmr::default();
    assert_eq!(mmr.num_leaves(), 0);
    assert_eq!(mmr.forest(), Forest::empty());
    assert_eq!(mmr.peaks(), MmrPeaks::default());
    assert!(mmr.nodes.is_empty());
    assert!(mmr.tracked_leaves.is_empty());
}

#[test]
fn test_position_equal_or_higher_than_leaves_is_never_contained() {
    let empty_forest = 0;
    for pos in 1..1024 {
        // pos is index, 0 based
        // tree is a length counter, 1 based
        // so a valid pos is always smaller, not equal, to tree
        assert_eq!(leaf_to_corresponding_tree(pos, pos), None);
        assert_eq!(leaf_to_corresponding_tree(pos, pos - 1), None);
        // and empty forest has no trees, so no position is valid
        assert_eq!(leaf_to_corresponding_tree(pos, empty_forest), None);
    }
}

#[test]
fn test_position_zero_is_always_contained_by_the_highest_tree() {
    for leaves in 1..1024usize {
        let tree = leaves.ilog2();
        assert_eq!(leaf_to_corresponding_tree(0, leaves), Some(tree));
    }
}

#[test]
fn test_leaf_to_corresponding_tree() {
    assert_eq!(leaf_to_corresponding_tree(0, 0b0001), Some(0));
    assert_eq!(leaf_to_corresponding_tree(0, 0b0010), Some(1));
    assert_eq!(leaf_to_corresponding_tree(0, 0b0011), Some(1));
    assert_eq!(leaf_to_corresponding_tree(0, 0b1011), Some(3));

    // position one is always owned by the left-most tree
    assert_eq!(leaf_to_corresponding_tree(1, 0b0010), Some(1));
    assert_eq!(leaf_to_corresponding_tree(1, 0b0011), Some(1));
    assert_eq!(leaf_to_corresponding_tree(1, 0b1011), Some(3));

    // position two starts as its own root, and then it is merged with the left-most tree
    assert_eq!(leaf_to_corresponding_tree(2, 0b0011), Some(0));
    assert_eq!(leaf_to_corresponding_tree(2, 0b0100), Some(2));
    assert_eq!(leaf_to_corresponding_tree(2, 0b1011), Some(3));

    // position tree is merged on the left-most tree
    assert_eq!(leaf_to_corresponding_tree(3, 0b0011), None);
    assert_eq!(leaf_to_corresponding_tree(3, 0b0100), Some(2));
    assert_eq!(leaf_to_corresponding_tree(3, 0b1011), Some(3));

    assert_eq!(leaf_to_corresponding_tree(4, 0b0101), Some(0));
    assert_eq!(leaf_to_corresponding_tree(4, 0b0110), Some(1));
    assert_eq!(leaf_to_corresponding_tree(4, 0b0111), Some(1));
    assert_eq!(leaf_to_corresponding_tree(4, 0b1000), Some(3));

    assert_eq!(leaf_to_corresponding_tree(12, 0b01101), Some(0));
    assert_eq!(leaf_to_corresponding_tree(12, 0b01110), Some(1));
    assert_eq!(leaf_to_corresponding_tree(12, 0b01111), Some(1));
    assert_eq!(leaf_to_corresponding_tree(12, 0b10000), Some(4));
}

#[test]
fn test_high_bitmask() {
    assert_eq!(high_bitmask(0), usize::MAX);
    assert_eq!(high_bitmask(1), usize::MAX << 1);
    assert_eq!(high_bitmask(usize::BITS - 2), 0b11usize.rotate_right(2));
    assert_eq!(high_bitmask(usize::BITS - 1), 0b1usize.rotate_right(1));
    assert_eq!(high_bitmask(usize::BITS), 0, "overflow should be handled");
}

#[test]
fn test_nodes_in_forest() {
    assert_eq!(nodes_in_forest(0b0000), 0);
    assert_eq!(nodes_in_forest(0b0001), 1);
    assert_eq!(nodes_in_forest(0b0010), 3);
    assert_eq!(nodes_in_forest(0b0011), 4);
    assert_eq!(nodes_in_forest(0b0100), 7);
    assert_eq!(nodes_in_forest(0b0101), 8);
    assert_eq!(nodes_in_forest(0b0110), 10);
    assert_eq!(nodes_in_forest(0b0111), 11);
    assert_eq!(nodes_in_forest(0b1000), 15);
    assert_eq!(nodes_in_forest(0b1001), 16);
    assert_eq!(nodes_in_forest(0b1010), 18);
    assert_eq!(nodes_in_forest(0b1011), 19);
}

#[test]
fn test_nodes_in_forest_single_bit() {
    assert_eq!(nodes_in_forest(2usize.pow(0)), 2usize.pow(1) - 1);
    assert_eq!(nodes_in_forest(2usize.pow(1)), 2usize.pow(2) - 1);
    assert_eq!(nodes_in_forest(2usize.pow(2)), 2usize.pow(3) - 1);
    assert_eq!(nodes_in_forest(2usize.pow(3)), 2usize.pow(4) - 1);

    let mut bit = 0u32;
    while let Some(leaves) = 1usize.checked_shl(bit) {
        if leaves > Forest::MAX_LEAVES {
            break;
        }

        if leaves > usize::MAX / 2 {
            break;
        }

        let size = leaves * 2 - 1;
        assert_eq!(nodes_in_forest(leaves), size);
        bit += 1;
    }

    if Forest::MAX_LEAVES.is_power_of_two() {
        let expected = (Forest::MAX_LEAVES as u128).saturating_mul(2).saturating_sub(1);
        let actual = nodes_in_forest(Forest::MAX_LEAVES) as u128;
        assert_eq!(actual, expected);
    }
}

#[test]
fn test_forest_largest_smallest_tree() {
    // largest_tree and smallest_tree return correct results
    let forest = Forest::new(0b1101_0100).unwrap();
    let largest = Forest::new(0b1000_0000).unwrap();
    let smallest = Forest::new(0b0000_0100).unwrap();

    assert_eq!(forest.largest_tree(), largest);
    assert_eq!(forest.smallest_tree(), smallest);

    // no trees in an empty forest
    let empty_forest = Forest::new(0).unwrap();
    assert_eq!(empty_forest.largest_tree(), empty_forest);
    assert_eq!(empty_forest.smallest_tree(), empty_forest);
}

#[test]
fn test_forest_append_leaf_limit() {
    let mut forest = Forest::new(Forest::MAX_LEAVES).unwrap();
    assert_matches!(
        forest.append_leaf(),
        Err(MmrError::ForestSizeExceeded { requested, max }) if
            requested == Forest::MAX_LEAVES + 1 && max == Forest::MAX_LEAVES
    );
}

#[test]
fn test_forest_new_limit() {
    assert!(Forest::new(Forest::MAX_LEAVES).is_ok());
    assert!(Forest::new(Forest::MAX_LEAVES + 1).is_err());
}

#[cfg(feature = "serde")]
#[test]
fn test_forest_serde_rejects_large_value() {
    use serde::{Deserialize, de::value::UsizeDeserializer};

    let result = Forest::deserialize(UsizeDeserializer::<serde::de::value::Error>::new(
        Forest::MAX_LEAVES + 1,
    ));
    assert!(result.is_err());
}

#[test]
fn test_forest_with_single_leaf_limit() {
    let forest = Forest::new(Forest::MAX_LEAVES).unwrap();
    let result = forest.with_single_leaf();
    assert_eq!(result.num_leaves(), Forest::MAX_LEAVES);
}

#[test]
fn test_forest_bitxor_within_limit() {
    let high = Forest::new(Forest::MAX_LEAVES).unwrap();
    let low = Forest::new(Forest::MAX_LEAVES - 1).unwrap();
    let result = high ^ low;
    assert!(result.num_leaves() <= Forest::MAX_LEAVES);
}

#[test]
fn test_forest_bitor_within_limit() {
    let high = Forest::new(Forest::MAX_LEAVES).unwrap();
    let low = Forest::new(1).unwrap();
    let result = high | low;
    assert!(result.num_leaves() <= Forest::MAX_LEAVES);
}

#[test]
fn test_forest_without_trees_does_not_add_bits() {
    let forest = Forest::new(0b1000).unwrap();
    let other = Forest::new(0b0001).unwrap();
    let result = forest.without_trees(other);
    assert_eq!(result, forest);
}

#[test]
fn test_mmr_add_limit_prevents_mutation() {
    let mut mmr = Mmr {
        forest: Forest::new(Forest::MAX_LEAVES).unwrap(),
        nodes: Vec::new(),
    };
    let result = mmr.add(Word::empty());
    assert_matches!(result, Err(MmrError::ForestSizeExceeded { .. }));
    assert_eq!(mmr.nodes.len(), 0);
    assert_eq!(mmr.forest.num_leaves(), Forest::MAX_LEAVES);
}

#[test]
fn test_mmr_try_from_iter_accepts_oversize_upper_hint() {
    struct OversizeIter;

    impl Iterator for OversizeIter {
        type Item = Word;

        fn next(&mut self) -> Option<Self::Item> {
            None
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (0, Some(Forest::MAX_LEAVES + 1))
        }
    }

    let result = Mmr::try_from_iter(OversizeIter);
    assert!(result.is_ok());
}

#[test]
fn test_mmr_try_from_iter_rejects_oversize_lower_bound() {
    struct OversizeLowerIter {
        remaining: usize,
    }

    impl Iterator for OversizeLowerIter {
        type Item = Word;

        fn next(&mut self) -> Option<Self::Item> {
            if self.remaining == 0 {
                None
            } else {
                self.remaining -= 1;
                Some(Word::empty())
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.remaining, Some(self.remaining))
        }
    }

    let result = Mmr::try_from_iter(OversizeLowerIter { remaining: Forest::MAX_LEAVES + 1 });
    assert_matches!(result, Err(MmrError::ForestSizeExceeded { .. }));
}

#[test]
fn test_mmr_try_from_iter_rejects_oversize_actual() {
    let max_leaves = 8;

    struct OversizeActualIter {
        remaining: usize,
    }

    impl Iterator for OversizeActualIter {
        type Item = Word;

        fn next(&mut self) -> Option<Self::Item> {
            if self.remaining == 0 {
                None
            } else {
                self.remaining -= 1;
                Some(Word::empty())
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (0, None)
        }
    }

    let result =
        Mmr::try_from_iter_with_limit(OversizeActualIter { remaining: max_leaves + 1 }, max_leaves);
    assert_matches!(
        result,
        Err(MmrError::ForestSizeExceeded { requested, max }) if
            requested == max_leaves + 1 && max == max_leaves
    );
}

#[test]
fn test_partial_mmr_add_limit_prevents_mutation() {
    let mut partial = PartialMmr {
        forest: Forest::new(Forest::MAX_LEAVES).unwrap(),
        ..Default::default()
    };
    let before_peaks = partial.peaks.clone();
    let before_nodes = partial.nodes.clone();
    let before_tracked = partial.tracked_leaves.clone();

    let result = partial.add(Word::empty(), true);
    assert_matches!(result, Err(MmrError::ForestSizeExceeded { .. }));
    assert_eq!(partial.forest.num_leaves(), Forest::MAX_LEAVES);
    assert_eq!(partial.peaks, before_peaks);
    assert_eq!(partial.nodes, before_nodes);
    assert_eq!(partial.tracked_leaves, before_tracked);
}

#[test]
fn test_forest_to_root_index() {
    fn idx(pos: usize) -> InOrderIndex {
        InOrderIndex::new(pos.try_into().unwrap())
    }

    // When there is a single tree in the forest, the index is equivalent to the number of
    // leaves in that tree, which is `2^n`.
    assert_eq!(Forest::new(0b0001).unwrap().root_in_order_index(), idx(1));
    assert_eq!(Forest::new(0b0010).unwrap().root_in_order_index(), idx(2));
    assert_eq!(Forest::new(0b0100).unwrap().root_in_order_index(), idx(4));
    assert_eq!(Forest::new(0b1000).unwrap().root_in_order_index(), idx(8));

    assert_eq!(Forest::new(0b0011).unwrap().root_in_order_index(), idx(5));
    assert_eq!(Forest::new(0b0101).unwrap().root_in_order_index(), idx(9));
    assert_eq!(Forest::new(0b1001).unwrap().root_in_order_index(), idx(17));
    assert_eq!(Forest::new(0b0111).unwrap().root_in_order_index(), idx(13));
    assert_eq!(Forest::new(0b1011).unwrap().root_in_order_index(), idx(21));
    assert_eq!(Forest::new(0b1111).unwrap().root_in_order_index(), idx(29));

    assert_eq!(Forest::new(0b0110).unwrap().root_in_order_index(), idx(10));
    assert_eq!(Forest::new(0b1010).unwrap().root_in_order_index(), idx(18));
    assert_eq!(Forest::new(0b1100).unwrap().root_in_order_index(), idx(20));
    assert_eq!(Forest::new(0b1110).unwrap().root_in_order_index(), idx(26));
}

#[test]
fn test_forest_to_rightmost_index() {
    fn idx(pos: usize) -> InOrderIndex {
        InOrderIndex::new(pos.try_into().unwrap())
    }

    for forest in 1..256 {
        assert!(
            Forest::new(forest).unwrap().rightmost_in_order_index().inner() % 2 == 1,
            "Leaves are always odd"
        );
    }

    assert_eq!(Forest::new(0b0001).unwrap().rightmost_in_order_index(), idx(1));
    assert_eq!(Forest::new(0b0010).unwrap().rightmost_in_order_index(), idx(3));
    assert_eq!(Forest::new(0b0011).unwrap().rightmost_in_order_index(), idx(5));
    assert_eq!(Forest::new(0b0100).unwrap().rightmost_in_order_index(), idx(7));
    assert_eq!(Forest::new(0b0101).unwrap().rightmost_in_order_index(), idx(9));
    assert_eq!(Forest::new(0b0110).unwrap().rightmost_in_order_index(), idx(11));
    assert_eq!(Forest::new(0b0111).unwrap().rightmost_in_order_index(), idx(13));
    assert_eq!(Forest::new(0b1000).unwrap().rightmost_in_order_index(), idx(15));
    assert_eq!(Forest::new(0b1001).unwrap().rightmost_in_order_index(), idx(17));
    assert_eq!(Forest::new(0b1010).unwrap().rightmost_in_order_index(), idx(19));
    assert_eq!(Forest::new(0b1011).unwrap().rightmost_in_order_index(), idx(21));
    assert_eq!(Forest::new(0b1100).unwrap().rightmost_in_order_index(), idx(23));
    assert_eq!(Forest::new(0b1101).unwrap().rightmost_in_order_index(), idx(25));
    assert_eq!(Forest::new(0b1110).unwrap().rightmost_in_order_index(), idx(27));
    assert_eq!(Forest::new(0b1111).unwrap().rightmost_in_order_index(), idx(29));
}

#[test]
fn test_is_valid_in_order_index() {
    fn idx(pos: usize) -> InOrderIndex {
        InOrderIndex::new(pos.try_into().unwrap())
    }

    // Empty forest has no valid indices
    let empty = Forest::empty();
    assert!(!empty.is_valid_in_order_index(&idx(1)));

    // Single tree forests (power of 2 leaves) have no separators
    // Forest with 1 leaf: valid indices are just 1
    let forest_1 = Forest::new(0b0001).unwrap();
    assert!(!forest_1.is_valid_in_order_index(&idx(2)), "index 2 is invalid");
    assert!(forest_1.is_valid_in_order_index(&idx(1)));
    assert!(!forest_1.is_valid_in_order_index(&idx(2)), "beyond bounds");

    // Forest with 2 leaves: valid indices are 1, 2, 3
    let forest_2 = Forest::new(0b0010).unwrap();
    assert!(forest_2.is_valid_in_order_index(&idx(1)));
    assert!(forest_2.is_valid_in_order_index(&idx(2)));
    assert!(forest_2.is_valid_in_order_index(&idx(3)));
    assert!(!forest_2.is_valid_in_order_index(&idx(4)), "beyond bounds");

    // Forest with 4 leaves: valid indices are 1-7
    let forest_4 = Forest::new(0b0100).unwrap();
    for i in 1..=7 {
        assert!(forest_4.is_valid_in_order_index(&idx(i)), "index {i} should be valid");
    }
    assert!(!forest_4.is_valid_in_order_index(&idx(8)), "beyond bounds");

    // Multi-tree forest: 7 leaves (0b111 = 4 + 2 + 1)
    // Tree 1 (4 leaves): indices 1-7
    // Separator: index 8
    // Tree 2 (2 leaves): indices 9-11
    // Separator: index 12
    // Tree 3 (1 leaf): index 13
    let forest_7 = Forest::new(0b0111).unwrap();

    // Valid indices in first tree (4 leaves, 7 nodes)
    for i in 1..=7 {
        assert!(
            forest_7.is_valid_in_order_index(&idx(i)),
            "index {i} should be valid in first tree"
        );
    }

    // Separator between first and second tree
    assert!(!forest_7.is_valid_in_order_index(&idx(8)), "index 8 is a separator");

    // Valid indices in second tree (2 leaves, 3 nodes)
    for i in 9..=11 {
        assert!(
            forest_7.is_valid_in_order_index(&idx(i)),
            "index {i} should be valid in second tree"
        );
    }

    // Separator between second and third tree
    assert!(!forest_7.is_valid_in_order_index(&idx(12)), "index 12 is a separator");

    // Valid index in third tree (1 leaf)
    assert!(
        forest_7.is_valid_in_order_index(&idx(13)),
        "index 13 should be valid in third tree"
    );

    // Beyond bounds
    assert!(!forest_7.is_valid_in_order_index(&idx(14)), "index 14 is beyond bounds");

    // Another multi-tree example: 6 leaves (0b110 = 4 + 2)
    // Tree 1 (4 leaves): indices 1-7
    // Separator: index 8
    // Tree 2 (2 leaves): indices 9-11
    let forest_6 = Forest::new(0b0110).unwrap();
    for i in 1..=7 {
        assert!(forest_6.is_valid_in_order_index(&idx(i)), "index {i} should be valid");
    }
    assert!(!forest_6.is_valid_in_order_index(&idx(8)), "index 8 is a separator");
    for i in 9..=11 {
        assert!(forest_6.is_valid_in_order_index(&idx(i)), "index {i} should be valid");
    }
    assert!(!forest_6.is_valid_in_order_index(&idx(12)), "index 12 is beyond bounds");
}

#[test]
fn test_bit_position_iterator() {
    assert_eq!(TreeSizeIterator::new(Forest::empty()).count(), 0);
    assert_eq!(TreeSizeIterator::new(Forest::empty()).rev().count(), 0);

    assert_eq!(
        TreeSizeIterator::new(Forest::new(1).unwrap()).collect::<Vec<Forest>>(),
        vec![Forest::new(1).unwrap()]
    );
    assert_eq!(
        TreeSizeIterator::new(Forest::new(1).unwrap()).rev().collect::<Vec<Forest>>(),
        vec![Forest::new(1).unwrap()],
    );

    assert_eq!(
        TreeSizeIterator::new(Forest::new(2).unwrap()).collect::<Vec<Forest>>(),
        vec![Forest::new(2).unwrap()]
    );
    assert_eq!(
        TreeSizeIterator::new(Forest::new(2).unwrap()).rev().collect::<Vec<Forest>>(),
        vec![Forest::new(2).unwrap()],
    );

    assert_eq!(
        TreeSizeIterator::new(Forest::new(3).unwrap()).collect::<Vec<Forest>>(),
        vec![Forest::new(1).unwrap(), Forest::new(2).unwrap()],
    );
    assert_eq!(
        TreeSizeIterator::new(Forest::new(3).unwrap()).rev().collect::<Vec<Forest>>(),
        vec![Forest::new(2).unwrap(), Forest::new(1).unwrap()],
    );

    assert_eq!(
        TreeSizeIterator::new(Forest::new(0b11010101).unwrap()).collect::<Vec<Forest>>(),
        vec![0, 2, 4, 6, 7]
            .into_iter()
            .map(|bit| Forest::new(1 << bit).unwrap())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        TreeSizeIterator::new(Forest::new(0b11010101).unwrap())
            .rev()
            .collect::<Vec<Forest>>(),
        vec![7, 6, 4, 2, 0]
            .into_iter()
            .map(|bit| Forest::new(1 << bit).unwrap())
            .collect::<Vec<_>>()
    );

    let forest = Forest::new(0b1101_0101).unwrap();
    let mut it = TreeSizeIterator::new(forest);

    // 0b1101_0101
    //           ^
    let smallest = it.next().unwrap();
    assert_eq!(smallest.smallest_tree_unchecked(), smallest);
    assert_eq!(smallest.num_leaves(), 0b0000_0001);
    assert_eq!(smallest.num_nodes(), 1);
    assert_eq!(smallest.num_trees(), 1);

    // 0b1101_0101
    //         ^
    let next_smallest = it.next().unwrap();
    assert_eq!(next_smallest.smallest_tree_unchecked(), next_smallest);
    assert_eq!(next_smallest.num_leaves(), 0b0000_0100);
    assert_eq!(next_smallest.num_nodes(), 0b0000_0111);
    assert_eq!(next_smallest.num_trees(), 1);

    // 0b1101_0101
    //      ^
    let next_smallest = it.next().unwrap();
    assert_eq!(next_smallest.smallest_tree_unchecked(), next_smallest);
    assert_eq!(next_smallest.num_leaves(), 0b0001_0000);
    assert_eq!(next_smallest.num_nodes(), 0b0001_1111);
    assert_eq!(next_smallest.num_trees(), 1);

    // 0b1101_0101
    //    ^
    let next_smallest = it.next().unwrap();
    assert_eq!(next_smallest.smallest_tree_unchecked(), next_smallest);
    assert_eq!(next_smallest.num_leaves(), 0b0100_0000);
    assert_eq!(next_smallest.num_nodes(), 0b0111_1111);
    assert_eq!(next_smallest.num_trees(), 1);

    // 0b1101_0101
    //   ^
    let next_smallest = it.next().unwrap();
    assert_eq!(next_smallest.smallest_tree_unchecked(), next_smallest);
    assert_eq!(next_smallest.num_leaves(), 0b1000_0000);
    assert_eq!(next_smallest.num_nodes(), 0b1111_1111);
    assert_eq!(next_smallest.num_trees(), 1);

    assert_eq!(it.next(), None);
}

const LEAVES: [Word; 7] = [
    int_to_node(0),
    int_to_node(1),
    int_to_node(2),
    int_to_node(3),
    int_to_node(4),
    int_to_node(5),
    int_to_node(6),
];

#[test]
fn test_mmr_simple() {
    let mut postorder = vec![
        LEAVES[0],
        LEAVES[1],
        merge(LEAVES[0], LEAVES[1]),
        LEAVES[2],
        LEAVES[3],
        merge(LEAVES[2], LEAVES[3]),
    ];
    postorder.push(merge(postorder[2], postorder[5]));
    postorder.push(LEAVES[4]);
    postorder.push(LEAVES[5]);
    postorder.push(merge(LEAVES[4], LEAVES[5]));
    postorder.push(LEAVES[6]);

    let mut mmr = Mmr::new();
    assert_eq!(mmr.forest().num_leaves(), 0);
    assert_eq!(mmr.nodes.len(), 0);

    mmr.add(LEAVES[0]).unwrap();
    assert_eq!(mmr.forest().num_leaves(), 1);
    assert_eq!(mmr.nodes.len(), 1);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 1);
    assert_eq!(acc.peaks(), &[postorder[0]]);

    mmr.add(LEAVES[1]).unwrap();
    assert_eq!(mmr.forest().num_leaves(), 2);
    assert_eq!(mmr.nodes.len(), 3);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 2);
    assert_eq!(acc.peaks(), &[postorder[2]]);

    mmr.add(LEAVES[2]).unwrap();
    assert_eq!(mmr.forest().num_leaves(), 3);
    assert_eq!(mmr.nodes.len(), 4);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 3);
    assert_eq!(acc.peaks(), &[postorder[2], postorder[3]]);

    mmr.add(LEAVES[3]).unwrap();
    assert_eq!(mmr.forest().num_leaves(), 4);
    assert_eq!(mmr.nodes.len(), 7);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 4);
    assert_eq!(acc.peaks(), &[postorder[6]]);

    mmr.add(LEAVES[4]).unwrap();
    assert_eq!(mmr.forest().num_leaves(), 5);
    assert_eq!(mmr.nodes.len(), 8);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 5);
    assert_eq!(acc.peaks(), &[postorder[6], postorder[7]]);

    mmr.add(LEAVES[5]).unwrap();
    assert_eq!(mmr.forest().num_leaves(), 6);
    assert_eq!(mmr.nodes.len(), 10);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 6);
    assert_eq!(acc.peaks(), &[postorder[6], postorder[9]]);

    mmr.add(LEAVES[6]).unwrap();
    assert_eq!(mmr.forest().num_leaves(), 7);
    assert_eq!(mmr.nodes.len(), 11);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 7);
    assert_eq!(acc.peaks(), &[postorder[6], postorder[9], postorder[10]]);
}

#[test]
fn test_mmr_open() {
    let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();
    let h01 = merge(LEAVES[0], LEAVES[1]);
    let h23 = merge(LEAVES[2], LEAVES[3]);

    // node at pos 7 is the root
    assert!(mmr.open(7).is_err(), "Element 7 is not in the tree, result should be None");

    // node at pos 6 is the root
    let empty: MerklePath = MerklePath::new(vec![]);
    let opening = mmr
        .open(6)
        .expect("Element 6 is contained in the tree, expected an opening result.");
    assert_eq!(opening.path().merkle_path(), &empty);
    assert_eq!(opening.path().forest(), mmr.forest);
    assert_eq!(opening.path().position(), 6);
    mmr.peaks().verify(LEAVES[6], opening).unwrap();

    // nodes 4,5 are depth 1
    let root_to_path = MerklePath::new(vec![LEAVES[4]]);
    let opening = mmr
        .open(5)
        .expect("Element 5 is contained in the tree, expected an opening result.");
    assert_eq!(opening.path().merkle_path(), &root_to_path);
    assert_eq!(opening.path().forest(), mmr.forest);
    assert_eq!(opening.path().position(), 5);
    mmr.peaks().verify(LEAVES[5], opening).unwrap();

    let root_to_path = MerklePath::new(vec![LEAVES[5]]);
    let opening = mmr
        .open(4)
        .expect("Element 4 is contained in the tree, expected an opening result.");
    assert_eq!(opening.path().merkle_path(), &root_to_path);
    assert_eq!(opening.path().forest(), mmr.forest);
    assert_eq!(opening.path().position(), 4);
    mmr.peaks().verify(LEAVES[4], opening).unwrap();

    // nodes 0,1,2,3 are detph 2
    let root_to_path = MerklePath::new(vec![LEAVES[2], h01]);
    let opening = mmr
        .open(3)
        .expect("Element 3 is contained in the tree, expected an opening result.");
    assert_eq!(opening.path().merkle_path(), &root_to_path);
    assert_eq!(opening.path().forest(), mmr.forest);
    assert_eq!(opening.path().position(), 3);
    mmr.peaks().verify(LEAVES[3], opening).unwrap();

    let root_to_path = MerklePath::new(vec![LEAVES[3], h01]);
    let opening = mmr
        .open(2)
        .expect("Element 2 is contained in the tree, expected an opening result.");
    assert_eq!(opening.path().merkle_path(), &root_to_path);
    assert_eq!(opening.path().forest(), mmr.forest);
    assert_eq!(opening.path().position(), 2);
    mmr.peaks().verify(LEAVES[2], opening).unwrap();

    let root_to_path = MerklePath::new(vec![LEAVES[0], h23]);
    let opening = mmr
        .open(1)
        .expect("Element 1 is contained in the tree, expected an opening result.");
    assert_eq!(opening.path().merkle_path(), &root_to_path);
    assert_eq!(opening.path().forest(), mmr.forest);
    assert_eq!(opening.path().position(), 1);
    mmr.peaks().verify(LEAVES[1], opening).unwrap();

    let root_to_path = MerklePath::new(vec![LEAVES[1], h23]);
    let opening = mmr
        .open(0)
        .expect("Element 0 is contained in the tree, expected an opening result.");
    assert_eq!(opening.path().merkle_path(), &root_to_path);
    assert_eq!(opening.path().forest(), mmr.forest);
    assert_eq!(opening.path().position(), 0);
    mmr.peaks().verify(LEAVES[0], opening).unwrap();
}

#[test]
fn test_mmr_open_older_version() {
    let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();

    fn is_even(v: usize) -> bool {
        v & 1 == 0
    }

    // merkle path of a node is empty if there are no elements to pair with it
    for pos in (0..mmr.forest().num_leaves()).filter(|&v| is_even(v)) {
        let forest = Forest::new(pos + 1).unwrap();
        let proof = mmr.open_at(pos, forest).unwrap();
        assert_eq!(proof.path().forest(), forest);
        assert_eq!(proof.path().merkle_path().nodes(), []);
        assert_eq!(proof.path().position(), pos);
    }

    // openings match that of a merkle tree
    let mtree: MerkleTree = LEAVES[..4].try_into().unwrap();
    for forest in 4..=LEAVES.len() {
        let forest = Forest::new(forest).unwrap();
        for pos in 0..4 {
            let idx = NodeIndex::new(2, pos).unwrap();
            let path = mtree.get_path(idx).unwrap();
            let proof = mmr.open_at(pos as usize, forest).unwrap();
            assert_eq!(path, *proof.path().merkle_path());
        }
    }
    let mtree: MerkleTree = LEAVES[4..6].try_into().unwrap();
    for forest in 6..=LEAVES.len() {
        let forest = Forest::new(forest).unwrap();
        for pos in 0..2 {
            let idx = NodeIndex::new(1, pos).unwrap();
            let path = mtree.get_path(idx).unwrap();
            // account for the bigger tree with 4 elements
            let mmr_pos = (pos + 4) as usize;
            let proof = mmr.open_at(mmr_pos, forest).unwrap();
            assert_eq!(path, *proof.path().merkle_path());
        }
    }
}

/// Tests the openings of a simple Mmr with a single tree of depth 8.
#[test]
fn test_mmr_open_eight() {
    let leaves = [
        int_to_node(0),
        int_to_node(1),
        int_to_node(2),
        int_to_node(3),
        int_to_node(4),
        int_to_node(5),
        int_to_node(6),
        int_to_node(7),
    ];

    let mtree: MerkleTree = leaves.as_slice().try_into().unwrap();
    let forest = Forest::new(leaves.len()).unwrap();
    let mmr = Mmr::try_from_iter(leaves.iter().copied()).unwrap();
    let root = mtree.root();

    let position = 0;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), leaves[position])
    );
    assert_eq!(
        proof
            .path()
            .merkle_path()
            .compute_root(position as u64, leaves[position])
            .unwrap(),
        root
    );

    let position = 1;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), leaves[position])
    );
    assert_eq!(
        proof
            .path()
            .merkle_path()
            .compute_root(position as u64, leaves[position])
            .unwrap(),
        root
    );

    let position = 2;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), leaves[position])
    );
    assert_eq!(
        proof
            .path()
            .merkle_path()
            .compute_root(position as u64, leaves[position])
            .unwrap(),
        root
    );

    let position = 3;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), leaves[position])
    );
    assert_eq!(
        proof
            .path()
            .merkle_path()
            .compute_root(position as u64, leaves[position])
            .unwrap(),
        root
    );

    let position = 4;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), leaves[position])
    );
    assert_eq!(
        proof
            .path()
            .merkle_path()
            .compute_root(position as u64, leaves[position])
            .unwrap(),
        root
    );

    let position = 5;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), leaves[position])
    );
    assert_eq!(
        proof
            .path()
            .merkle_path()
            .compute_root(position as u64, leaves[position])
            .unwrap(),
        root
    );

    let position = 6;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), leaves[position])
    );
    assert_eq!(
        proof
            .path()
            .merkle_path()
            .compute_root(position as u64, leaves[position])
            .unwrap(),
        root
    );

    let position = 7;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), leaves[position])
    );
    assert_eq!(
        proof
            .path()
            .merkle_path()
            .compute_root(position as u64, leaves[position])
            .unwrap(),
        root
    );
}

/// Tests the openings of Mmr with a 3 trees of depths 4, 2, and 1.
#[test]
fn test_mmr_open_seven() {
    let mtree1: MerkleTree = LEAVES[..4].try_into().unwrap();
    let mtree2: MerkleTree = LEAVES[4..6].try_into().unwrap();

    let forest = Forest::new(LEAVES.len()).unwrap();
    let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();

    let position = 0;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath =
        mtree1.get_path(NodeIndex::new(2, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), LEAVES[position])
    );
    assert_eq!(proof.path().merkle_path().compute_root(0, LEAVES[0]).unwrap(), mtree1.root());

    let position = 1;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath =
        mtree1.get_path(NodeIndex::new(2, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), LEAVES[position])
    );
    assert_eq!(proof.path().merkle_path().compute_root(1, LEAVES[1]).unwrap(), mtree1.root());

    let position = 2;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath =
        mtree1.get_path(NodeIndex::new(2, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), LEAVES[position])
    );
    assert_eq!(proof.path().merkle_path().compute_root(2, LEAVES[2]).unwrap(), mtree1.root());

    let position = 3;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath =
        mtree1.get_path(NodeIndex::new(2, position as u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), LEAVES[position])
    );
    assert_eq!(proof.path().merkle_path().compute_root(3, LEAVES[3]).unwrap(), mtree1.root());

    let position = 4;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath = mtree2.get_path(NodeIndex::new(1, 0u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), LEAVES[position])
    );
    assert_eq!(proof.path().merkle_path().compute_root(0, LEAVES[4]).unwrap(), mtree2.root());

    let position = 5;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath = mtree2.get_path(NodeIndex::new(1, 1u64).unwrap()).unwrap();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), LEAVES[position])
    );
    assert_eq!(proof.path().merkle_path().compute_root(1, LEAVES[5]).unwrap(), mtree2.root());

    let position = 6;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath = [].as_ref().into();
    assert_eq!(
        proof,
        MmrProof::new(MmrPath::new(forest, position, merkle_path), LEAVES[position])
    );
    assert_eq!(proof.path().merkle_path().compute_root(0, LEAVES[6]).unwrap(), LEAVES[6]);
}

#[test]
fn test_mmr_get() {
    let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();
    assert_eq!(mmr.get(0).unwrap(), LEAVES[0], "value at pos 0 must correspond");
    assert_eq!(mmr.get(1).unwrap(), LEAVES[1], "value at pos 1 must correspond");
    assert_eq!(mmr.get(2).unwrap(), LEAVES[2], "value at pos 2 must correspond");
    assert_eq!(mmr.get(3).unwrap(), LEAVES[3], "value at pos 3 must correspond");
    assert_eq!(mmr.get(4).unwrap(), LEAVES[4], "value at pos 4 must correspond");
    assert_eq!(mmr.get(5).unwrap(), LEAVES[5], "value at pos 5 must correspond");
    assert_eq!(mmr.get(6).unwrap(), LEAVES[6], "value at pos 6 must correspond");
    assert!(mmr.get(7).is_err());
}

#[test]
fn test_mmr_invariants() {
    let mut mmr = Mmr::new();
    for v in 1..=1028 {
        mmr.add(int_to_node(v)).unwrap();
        let accumulator = mmr.peaks();
        assert_eq!(
            v as usize,
            mmr.forest().num_leaves(),
            "MMR leaf count must increase by one on every add"
        );
        assert_eq!(
            v as usize,
            accumulator.num_leaves(),
            "MMR and its accumulator must match leaves count"
        );
        assert_eq!(
            accumulator.num_leaves().count_ones() as usize,
            accumulator.peaks().len(),
            "bits on leaves must match the number of peaks"
        );

        let expected_nodes: usize =
            TreeSizeIterator::new(mmr.forest()).map(Forest::num_nodes).sum();

        assert_eq!(
            expected_nodes,
            mmr.nodes.len(),
            "the sum of every tree size must be equal to the number of nodes in the MMR (forest: {:b})",
            mmr.forest(),
        );
    }
}

#[test]
fn test_mmr_inner_nodes() {
    let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();
    let nodes: Vec<InnerNodeInfo> = mmr.inner_nodes().collect();

    let h01 = Poseidon2::merge(&[LEAVES[0], LEAVES[1]]);
    let h23 = Poseidon2::merge(&[LEAVES[2], LEAVES[3]]);
    let h0123 = Poseidon2::merge(&[h01, h23]);
    let h45 = Poseidon2::merge(&[LEAVES[4], LEAVES[5]]);
    let postorder = vec![
        InnerNodeInfo {
            value: h01,
            left: LEAVES[0],
            right: LEAVES[1],
        },
        InnerNodeInfo {
            value: h23,
            left: LEAVES[2],
            right: LEAVES[3],
        },
        InnerNodeInfo { value: h0123, left: h01, right: h23 },
        InnerNodeInfo {
            value: h45,
            left: LEAVES[4],
            right: LEAVES[5],
        },
    ];

    assert_eq!(postorder, nodes);
}

#[test]
fn test_mmr_peaks() {
    let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();

    let forest = Forest::new(0b0001).unwrap();
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[0]]);

    let forest = Forest::new(0b0010).unwrap();
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[2]]);

    let forest = Forest::new(0b0011).unwrap();
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[2], mmr.nodes[3]]);

    let forest = Forest::new(0b0100).unwrap();
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[6]]);

    let forest = Forest::new(0b0101).unwrap();
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[6], mmr.nodes[7]]);

    let forest = Forest::new(0b0110).unwrap();
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[6], mmr.nodes[9]]);

    let forest = Forest::new(0b0111).unwrap();
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[6], mmr.nodes[9], mmr.nodes[10]]);
}

#[test]
fn test_mmr_hash_peaks() {
    let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();
    let peaks = mmr.peaks();

    let first_peak = Poseidon2::merge(&[
        Poseidon2::merge(&[LEAVES[0], LEAVES[1]]),
        Poseidon2::merge(&[LEAVES[2], LEAVES[3]]),
    ]);
    let second_peak = Poseidon2::merge(&[LEAVES[4], LEAVES[5]]);
    let third_peak = LEAVES[6];

    // minimum length is 16
    let mut expected_peaks = [first_peak, second_peak, third_peak].to_vec();
    expected_peaks.resize(16, Word::default());
    assert_eq!(
        peaks.hash_peaks(),
        Poseidon2::hash_elements(&digests_to_elements(&expected_peaks))
    );
}

#[test]
fn test_mmr_peaks_hash_less_than_16() {
    let mut peaks = Vec::new();

    for i in 0..16 {
        peaks.push(int_to_node(i));

        let forest = Forest::new(1 << peaks.len()).unwrap().all_smaller_trees().unwrap();
        let accumulator = MmrPeaks::new(forest, peaks.clone()).unwrap();

        // minimum length is 16
        let mut expected_peaks = peaks.clone();
        expected_peaks.resize(16, Word::default());
        assert_eq!(
            accumulator.hash_peaks(),
            Poseidon2::hash_elements(&digests_to_elements(&expected_peaks))
        );
    }
}

#[test]
fn test_mmr_peaks_hash_odd() {
    let peaks: Vec<_> = (0..=17).map(int_to_node).collect();

    let forest = Forest::new(1 << peaks.len()).unwrap().all_smaller_trees_unchecked();
    let accumulator = MmrPeaks::new(forest, peaks.clone()).unwrap();

    // odd length bigger than 16 is padded to the next even number
    let mut expected_peaks = peaks;
    expected_peaks.resize(18, Word::default());
    assert_eq!(
        accumulator.hash_peaks(),
        Poseidon2::hash_elements(&digests_to_elements(&expected_peaks))
    );
}

#[test]
fn test_mmr_delta() {
    let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();
    let acc = mmr.peaks();

    // original_forest can't have more elements
    assert!(
        mmr.get_delta(Forest::new(LEAVES.len() + 1).unwrap(), mmr.forest()).is_err(),
        "Can not provide updates for a newer Mmr"
    );

    // if the number of elements is the same there is no change
    assert!(
        mmr.get_delta(Forest::new(LEAVES.len()).unwrap(), mmr.forest())
            .unwrap()
            .data
            .is_empty(),
        "There are no updates for the same Mmr version"
    );

    // missing the last element added, which is itself a tree peak
    assert_eq!(
        mmr.get_delta(Forest::new(6).unwrap(), mmr.forest()).unwrap().data,
        vec![acc.peaks()[2]],
        "one peak"
    );

    // missing the sibling to complete the tree of depth 2, and the last element
    assert_eq!(
        mmr.get_delta(Forest::new(5).unwrap(), mmr.forest()).unwrap().data,
        vec![LEAVES[5], acc.peaks()[2]],
        "one sibling, one peak"
    );

    // missing the whole last two trees, only send the peaks
    assert_eq!(
        mmr.get_delta(Forest::new(4).unwrap(), mmr.forest()).unwrap().data,
        vec![acc.peaks()[1], acc.peaks()[2]],
        "two peaks"
    );

    // missing the sibling to complete the first tree, and the two last trees
    assert_eq!(
        mmr.get_delta(Forest::new(3).unwrap(), mmr.forest()).unwrap().data,
        vec![LEAVES[3], acc.peaks()[1], acc.peaks()[2]],
        "one sibling, two peaks"
    );

    // missing half of the first tree, only send the computed element (not the leaves), and the new
    // peaks
    assert_eq!(
        mmr.get_delta(Forest::new(2).unwrap(), mmr.forest()).unwrap().data,
        vec![mmr.nodes[5], acc.peaks()[1], acc.peaks()[2]],
        "one sibling, two peaks"
    );

    assert_eq!(
        mmr.get_delta(Forest::new(1).unwrap(), mmr.forest()).unwrap().data,
        vec![LEAVES[1], mmr.nodes[5], acc.peaks()[1], acc.peaks()[2]],
        "one sibling, two peaks"
    );

    assert_eq!(
        &mmr.get_delta(Forest::empty(), mmr.forest()).unwrap().data,
        acc.peaks(),
        "all peaks"
    );
}

#[test]
fn test_mmr_delta_old_forest() {
    let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();

    // from_forest must be smaller-or-equal to to_forest
    for version in 1..=mmr.forest().num_leaves() {
        assert!(
            mmr.get_delta(Forest::new(version + 1).unwrap(), Forest::new(version).unwrap())
                .is_err()
        );
    }

    // when from_forest and to_forest are equal, there are no updates
    for version in 1..=mmr.forest().num_leaves() {
        let version = Forest::new(version).unwrap();
        let delta = mmr.get_delta(version, version).unwrap();
        assert!(delta.data.is_empty());
        assert_eq!(delta.forest, version);
    }

    // test update which merges the odd peak to the right
    for count in 0..(mmr.forest().num_leaves() / 2) {
        // *2 because every iteration tests a pair
        // +1 because the Mmr is 1-indexed
        let from_forest = Forest::new((count * 2) + 1).unwrap();
        let to_forest = Forest::new((count * 2) + 2).unwrap();
        let delta = mmr.get_delta(from_forest, to_forest).unwrap();

        // *2 because every iteration tests a pair
        // +1 because sibling is the odd element
        let sibling = (count * 2) + 1;
        assert_eq!(delta.data, [LEAVES[sibling]]);
        assert_eq!(delta.forest, to_forest);
    }

    let version = Forest::new(4).unwrap();
    let delta = mmr.get_delta(Forest::new(1).unwrap(), version).unwrap();
    assert_eq!(delta.data, [mmr.nodes[1], mmr.nodes[5]]);
    assert_eq!(delta.forest, version);

    let version = Forest::new(5).unwrap();
    let delta = mmr.get_delta(Forest::new(1).unwrap(), version).unwrap();
    assert_eq!(delta.data, [mmr.nodes[1], mmr.nodes[5], mmr.nodes[7]]);
    assert_eq!(delta.forest, version);
}

#[test]
fn test_partial_mmr_simple() {
    let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();
    let peaks = mmr.peaks();
    let mut partial: PartialMmr = peaks.clone().into();

    // check initial state of the partial mmr
    assert_eq!(partial.peaks(), peaks);
    assert_eq!(partial.num_leaves(), peaks.num_leaves());
    assert_eq!(partial.num_leaves(), LEAVES.len());
    assert_eq!(partial.peaks().num_peaks(), 3);
    assert_eq!(partial.nodes.len(), 0);

    // check state after adding tracking one element
    let proof1 = mmr.open(0).unwrap();
    let el1 = mmr.get(proof1.path().position()).unwrap();
    partial
        .track(proof1.path().position(), el1, proof1.path().merkle_path())
        .unwrap();

    // check the number of nodes: leaf value + authentication path nodes
    assert_eq!(partial.nodes.len(), 1 + proof1.path().merkle_path().len());
    // check the leaf value is stored
    let idx = InOrderIndex::from_leaf_pos(proof1.path().position());
    assert_eq!(partial.nodes[&idx], el1);
    // check the path values match
    assert_eq!(partial.nodes[&idx.sibling()], proof1.path().merkle_path()[0]);
    let idx = idx.parent();
    assert_eq!(partial.nodes[&idx.sibling()], proof1.path().merkle_path()[1]);

    let proof2 = mmr.open(1).unwrap();
    let el2 = mmr.get(proof2.path().position()).unwrap();
    partial
        .track(proof2.path().position(), el2, proof2.path().merkle_path())
        .unwrap();

    // After tracking pos 1: we add leaf1 at its index, but its sibling (pos 0's sibling)
    // was already stored as an auth node. So we only add: leaf1 value.
    // Total: leaf0, leaf1 (=sibling of leaf0), shared path node = 3 unique indices
    assert_eq!(partial.nodes.len(), 3);
    // check the leaf value is stored
    let idx = InOrderIndex::from_leaf_pos(proof2.path().position());
    assert_eq!(partial.nodes[&idx], el2);
    // check the path values match
    assert_eq!(partial.nodes[&idx.sibling()], proof2.path().merkle_path()[0]);
    let idx = idx.parent();
    assert_eq!(partial.nodes[&idx.sibling()], proof2.path().merkle_path()[1]);
}

#[test]
fn test_partial_mmr_update_single() {
    let mut full = Mmr::new();
    let zero = int_to_node(0);
    full.add(zero).unwrap();
    let mut partial: PartialMmr = full.peaks().into();

    let proof = full.open(0).unwrap();
    partial
        .track(proof.path().position(), zero, proof.path().merkle_path())
        .unwrap();

    for i in 1..100 {
        let node = int_to_node(i as u64);
        full.add(node).unwrap();
        let delta = full.get_delta(partial.forest(), full.forest()).unwrap();
        partial.apply(delta).unwrap();

        assert_eq!(partial.forest(), full.forest());
        assert_eq!(partial.peaks(), full.peaks());

        let proof1 = full.open(i).unwrap();
        partial
            .track(proof1.path().position(), node, proof1.path().merkle_path())
            .unwrap();
        let proof2 = partial.open(proof1.path().position()).unwrap().unwrap();
        assert_eq!(proof1.path().merkle_path(), proof2.merkle_path());
    }
}

#[test]
fn test_mmr_add_invalid_odd_leaf() {
    let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();
    let acc = mmr.peaks();
    let mut partial: PartialMmr = acc.into();

    let empty = MerklePath::new(Vec::new());

    // None of the other leaves should work
    for node in LEAVES.iter().cloned().rev().skip(1) {
        let result = partial.track(LEAVES.len() - 1, node, &empty);
        assert!(result.is_err());
    }

    let result = partial.track(LEAVES.len() - 1, LEAVES[6], &empty);
    assert!(result.is_ok());
}

#[test]
fn test_partial_track_rejects_path_depth_too_large() {
    let leaf = int_to_node(1);
    let mut full = Mmr::new();
    full.add(leaf).unwrap();
    let mut partial: PartialMmr = full.peaks().into();

    let deep_path = MerklePath::new(vec![Word::empty(); u8::MAX as usize]);
    let result = partial.track(0, leaf, &deep_path);
    assert_matches!(result, Err(MmrError::UnknownPeak(depth)) if depth == u8::MAX);
}

#[test]
fn test_get_delta_and_apply_never_return_forest_size_exceeded_for_valid_forests() {
    let mut full = Mmr::new();
    full.add(int_to_node(0)).unwrap();
    let mut partial: PartialMmr = full.peaks().into();

    for i in 1..256 {
        full.add(int_to_node(i as u64)).unwrap();

        let delta = match full.get_delta(partial.forest(), full.forest()) {
            Ok(delta) => delta,
            Err(MmrError::ForestSizeExceeded { .. }) => {
                panic!("valid get_delta range should not exceed forest bounds")
            },
            Err(err) => panic!("unexpected get_delta error: {err}"),
        };

        if let Err(err) = partial.apply(delta) {
            match err {
                MmrError::ForestSizeExceeded { .. } => {
                    panic!("applying a valid delta should not exceed forest bounds")
                },
                _ => panic!("unexpected apply error: {err}"),
            }
        }
    }
}

/// Tests that a proof whose peak count exceeds the peak count of the MMR returns an error.
///
/// Here we manipulate the proof to return a peak index of 1 while the MMR only has 1 peak (with
/// index 0).
#[test]
fn test_mmr_proof_num_peaks_exceeds_current_num_peaks() {
    let mmr = Mmr::try_from_iter(LEAVES[0..4].iter().cloned()).unwrap();
    let original_proof = mmr.open(3).unwrap();
    // Create an invalid proof with wrong forest and position
    let invalid_path =
        MmrPath::new(Forest::new(5).unwrap(), 4, original_proof.path().merkle_path().clone());
    let invalid_proof = MmrProof::new(invalid_path, original_proof.leaf());
    let err = mmr.peaks().verify(LEAVES[3], invalid_proof).unwrap_err();
    assert_matches!(
        err,
        MmrError::PeakOutOfBounds { peak_idx, peaks_len }
            if peak_idx == 1 && peaks_len == mmr.peaks().num_peaks()
    );
}

/// Tests that a proof whose peak count exceeds the peak count of the MMR returns an error.
///
/// We create an MmrProof for a leaf whose peak index to verify against is 1.
/// Then we add another leaf which results in an Mmr with just one peak due to trees
/// being merged. If we try to use the old proof against the new Mmr, we should get an error.
#[test]
fn test_mmr_old_proof_num_peaks_exceeds_current_num_peaks() {
    let leaves_len = 3;
    let mut mmr = Mmr::try_from_iter(LEAVES[0..leaves_len].iter().cloned()).unwrap();

    let leaf_idx = leaves_len - 1;
    let proof = mmr.open(leaf_idx).unwrap();
    assert!(mmr.peaks().verify(LEAVES[leaf_idx], proof.clone()).is_ok());

    mmr.add(LEAVES[leaves_len]).unwrap();
    let err = mmr.peaks().verify(LEAVES[leaf_idx], proof).unwrap_err();
    assert_matches!(
        err,
        MmrError::PeakOutOfBounds { peak_idx, peaks_len }
            if peak_idx == 1 && peaks_len == mmr.peaks().num_peaks()
    );
}

mod property_tests {
    use proptest::prelude::*;

    use super::{Forest, leaf_to_corresponding_tree};

    proptest! {
        #[test]
        fn test_last_position_is_always_contained_in_the_last_tree(leaves in 1..=Forest::MAX_LEAVES) {
            let last_pos = leaves - 1;
            let lowest_bit = leaves.trailing_zeros();

            assert_eq!(
                leaf_to_corresponding_tree(last_pos, leaves),
                Some(lowest_bit),
            );
        }
    }

    proptest! {
        #[test]
        fn test_contained_tree_is_always_power_of_two((leaves, pos) in (1..=Forest::MAX_LEAVES).prop_flat_map(|v| (Just(v), 0..v))) {
            let tree_bit = leaf_to_corresponding_tree(pos, leaves).expect("pos is smaller than leaves, there should always be a corresponding tree");
            let mask = 1usize << tree_bit;

            assert!(tree_bit < usize::BITS, "the result must be a bit in usize");
            assert!(mask & leaves != 0, "the result should be a tree in leaves");
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn digests_to_elements(digests: &[Word]) -> Vec<Felt> {
    Word::words_as_elements(digests).to_vec()
}

// short hand for the Poseidon2 hash, used to make test code more concise and easy to read
fn merge(l: Word, r: Word) -> Word {
    Poseidon2::merge(&[l, r])
}

/// Given a leaf index and the current forest, return the tree number responsible for
/// the position.
fn leaf_to_corresponding_tree(leaf_idx: usize, forest: usize) -> Option<u32> {
    Forest::new(forest).unwrap().leaf_to_corresponding_tree(leaf_idx)
}

/// Return the total number of nodes of a given forest
fn nodes_in_forest(forest: usize) -> usize {
    nodes_from_mask(forest)
}
