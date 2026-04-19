//! A fully materialized Merkle mountain range (MMR).
//!
//! A MMR is a forest structure, i.e. it is an ordered set of disjoint rooted trees. The trees are
//! ordered by size, from the most to least number of leaves. Every tree is a perfect binary tree,
//! meaning a tree has all its leaves at the same depth, and every inner node has a branch-factor
//! of 2 with both children set.
//!
//! Additionally the structure only supports adding leaves to the right-most tree, the one with the
//! least number of leaves. The structure preserves the invariant that each tree has different
//! depths, i.e. as part of adding a new element to the forest the trees with same depth are
//! merged, creating a new tree with depth d+1, this process is continued until the property is
//! reestablished.
use alloc::vec::Vec;

use super::{
    super::{InnerNodeInfo, MerklePath},
    MmrDelta, MmrError, MmrPath, MmrPeaks, MmrProof,
    forest::{Forest, TreeSizeIterator},
    nodes_from_mask,
};
use crate::{
    Word,
    hash::poseidon2::Poseidon2,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// MMR
// ===============================================================================================

/// A fully materialized Merkle Mountain Range, with every tree in the forest and all their
/// elements.
///
/// Since this is a full representation of the MMR, elements are never removed and the MMR will
/// grow roughly `O(2n)` in number of leaf elements.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Mmr {
    /// Refer to the `forest` method documentation for details of the semantics of this value.
    pub(super) forest: Forest,

    /// Contains every element of the forest.
    ///
    /// The trees are in postorder sequential representation. This representation allows for all
    /// the elements of every tree in the forest to be stored in the same sequential buffer. It
    /// also means new elements can be added to the forest, and merging of trees is very cheap with
    /// no need to copy elements.
    pub(super) nodes: Vec<Word>,
}

impl Default for Mmr {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmr {
    // CONSTRUCTORS
    // ============================================================================================

    /// Constructor for an empty `Mmr`.
    pub fn new() -> Mmr {
        Mmr {
            forest: Forest::empty(),
            nodes: Vec::new(),
        }
    }

    /// Constructs an MMR from an iterator of leaves.
    ///
    /// # Errors
    /// Returns an error if the maximum forest size is exceeded.
    pub fn try_from_iter<T: IntoIterator<Item = Word>>(values: T) -> Result<Self, MmrError> {
        Self::try_from_iter_with_limit(values, Forest::MAX_LEAVES)
    }

    pub(crate) fn try_from_iter_with_limit<T: IntoIterator<Item = Word>>(
        values: T,
        max_leaves: usize,
    ) -> Result<Self, MmrError> {
        let mut mmr = Mmr::new();
        let iter = values.into_iter();
        let (lower, _) = iter.size_hint();
        if lower > max_leaves {
            return Err(MmrError::ForestSizeExceeded { requested: lower, max: max_leaves });
        }
        let mut count = 0usize;
        for v in iter {
            count += 1;
            if count > max_leaves {
                return Err(MmrError::ForestSizeExceeded { requested: count, max: max_leaves });
            }
            mmr.add(v)?;
        }
        Ok(mmr)
    }

    // ACCESSORS
    // ============================================================================================

    /// Returns the MMR forest representation. See [`Forest`].
    pub const fn forest(&self) -> Forest {
        self.forest
    }

    // FUNCTIONALITY
    // ============================================================================================

    /// Returns an [MmrProof] for the leaf at the specified position.
    ///
    /// Note: The leaf position is the 0-indexed number corresponding to the order the leaves were
    /// added, this corresponds to the MMR size _prior_ to adding the element. So the 1st element
    /// has position 0, the second position 1, and so on.
    ///
    /// # Errors
    /// Returns an error if the specified leaf position is out of bounds for this MMR.
    pub fn open(&self, pos: usize) -> Result<MmrProof, MmrError> {
        self.open_at(pos, self.forest)
    }

    /// Returns an [MmrProof] for the leaf at the specified position using the state of the MMR
    /// at the specified `forest`.
    ///
    /// Note: The leaf position is the 0-indexed number corresponding to the order the leaves were
    /// added, this corresponds to the MMR size _prior_ to adding the element. So the 1st element
    /// has position 0, the second position 1, and so on.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The specified leaf position is out of bounds for this MMR.
    /// - The specified `forest` value is not valid for this MMR.
    pub fn open_at(&self, pos: usize, forest: Forest) -> Result<MmrProof, MmrError> {
        if forest > self.forest {
            return Err(MmrError::ForestOutOfBounds(forest.num_leaves(), self.forest.num_leaves()));
        }
        let (leaf, path) = self.collect_merkle_path_and_value(pos, forest)?;

        let path = MmrPath::new(forest, pos, MerklePath::new(path));

        Ok(MmrProof::new(path, leaf))
    }

    /// Returns the leaf value at position `pos`.
    ///
    /// Note: The leaf position is the 0-indexed number corresponding to the order the leaves were
    /// added, this corresponds to the MMR size _prior_ to adding the element. So the 1st element
    /// has position 0, the second position 1, and so on.
    pub fn get(&self, pos: usize) -> Result<Word, MmrError> {
        let (value, _) = self.collect_merkle_path_and_value(pos, self.forest)?;

        Ok(value)
    }

    /// Adds a new element to the MMR.
    ///
    /// # Errors
    /// Returns an error if the MMR exceeds the maximum supported forest size.
    pub fn add(&mut self, el: Word) -> Result<(), MmrError> {
        // Fail early before mutating nodes.
        let old_forest = self.forest;
        self.forest.append_leaf()?;
        // Note: every node is also a tree of size 1, adding an element to the forest creates a new
        // rooted-tree of size 1. This may temporarily break the invariant that every tree in the
        // forest has different sizes, the loop below will eagerly merge trees of same size and
        // restore the invariant.
        self.nodes.push(el);

        let mut left_offset = self.nodes.len().saturating_sub(2);
        let mut right = el;
        let mut left_tree = 1usize;
        while (old_forest.num_leaves() & left_tree) != 0 {
            right = Poseidon2::merge(&[self.nodes[left_offset], right]);
            self.nodes.push(right);

            debug_assert!(left_tree <= Forest::MAX_LEAVES);
            let left_nodes = left_tree * 2 - 1;
            left_offset = left_offset.saturating_sub(left_nodes);

            match left_tree.checked_shl(1) {
                Some(next) => left_tree = next,
                None => break,
            }
        }

        Ok(())
    }

    /// Returns the current peaks of the MMR.
    pub fn peaks(&self) -> MmrPeaks {
        self.peaks_at(self.forest).expect("failed to get peaks at current forest")
    }

    /// Returns the peaks of the MMR at the state specified by `forest`.
    ///
    /// # Errors
    /// Returns an error if the specified `forest` value is not valid for this MMR.
    pub fn peaks_at(&self, forest: Forest) -> Result<MmrPeaks, MmrError> {
        if forest > self.forest {
            return Err(MmrError::ForestOutOfBounds(forest.num_leaves(), self.forest.num_leaves()));
        }

        let peaks: Vec<Word> = TreeSizeIterator::new(forest)
            .rev()
            .map(Forest::num_nodes)
            .scan(0, |offset, el| {
                *offset += el;
                Some(*offset)
            })
            .map(|offset| self.nodes[offset - 1])
            .collect();

        // Safety: the invariant is maintained by the [Mmr]
        let peaks = MmrPeaks::new(forest, peaks)?;

        Ok(peaks)
    }

    /// Compute the required update to `original_forest`.
    ///
    /// The result is a packed sequence of the authentication elements required to update the trees
    /// that have been merged together, followed by the new peaks of the [Mmr].
    pub fn get_delta(&self, from_forest: Forest, to_forest: Forest) -> Result<MmrDelta, MmrError> {
        if to_forest > self.forest {
            return Err(MmrError::ForestOutOfBounds(
                to_forest.num_leaves(),
                self.forest.num_leaves(),
            ));
        }
        if from_forest > to_forest {
            return Err(MmrError::ForestOutOfBounds(
                from_forest.num_leaves(),
                to_forest.num_leaves(),
            ));
        }

        if from_forest == to_forest {
            return Ok(MmrDelta { forest: to_forest, data: Vec::new() });
        }

        let mut result = Vec::new();

        // Find the largest tree in this [Mmr] which is new to `from_forest`.
        let candidate_mask = to_forest.num_leaves() ^ from_forest.num_leaves();
        let mut new_high = super::forest::largest_tree_from_mask(candidate_mask);

        // Collect authentication nodes used for tree merges
        // ----------------------------------------------------------------------------------------

        // Find the trees from `from_forest` that have been merged into `new_high`.
        let mut merges = from_forest & new_high.all_smaller_trees_unchecked();

        // Find the peaks that are common to `from_forest` and this [Mmr]
        let common_trees = from_forest ^ merges;

        if !merges.is_empty() {
            // Skip the smallest trees unknown to `from_forest`.
            let mut target = merges.smallest_tree_unchecked();

            // Collect siblings required to computed the merged tree's peak
            while target < new_high {
                // Computes the offset to the smallest know peak
                // - common_trees: peaks unchanged in the current update, target comes after these.
                // - merges: peaks that have not been merged so far, target comes after these.
                // - target: tree from which to load the sibling. On the first iteration this is a
                //   value known by the partial mmr, on subsequent iterations this value is to be
                //   computed from the known peaks and provided authentication nodes.
                let known_mask =
                    common_trees.num_leaves() | merges.num_leaves() | target.num_leaves();
                let known = nodes_from_mask(known_mask);
                let sibling = target.num_nodes();
                result.push(self.nodes[known + sibling - 1]);

                // Update the target and account for tree merges
                target = target.next_larger_tree()?;
                while !(merges & target).is_empty() {
                    target = target.next_larger_tree()?;
                }
                // Remove the merges done so far
                merges ^= merges & target.all_smaller_trees_unchecked();
            }
        } else {
            // The new high tree may not be the result of any merges, if it is smaller than all the
            // trees of `from_forest`.
            new_high = Forest::empty();
        }

        // Collect the new [Mmr] peaks
        // ----------------------------------------------------------------------------------------

        let mut new_peaks = to_forest ^ common_trees ^ new_high;
        let old_peaks = to_forest ^ new_peaks;
        let mut offset = old_peaks.num_nodes();
        while !new_peaks.is_empty() {
            let target = new_peaks.largest_tree_unchecked();
            offset += target.num_nodes();
            result.push(self.nodes[offset - 1]);
            new_peaks ^= target;
        }

        Ok(MmrDelta { forest: to_forest, data: result })
    }

    /// An iterator over inner nodes in the MMR. The order of iteration is unspecified.
    pub fn inner_nodes(&self) -> MmrNodes<'_> {
        MmrNodes {
            mmr: self,
            forest: 0,
            last_right: 0,
            index: 0,
        }
    }

    // UTILITIES
    // ============================================================================================

    /// Internal function used to collect the leaf value and its Merkle path.
    ///
    /// The arguments are relative to the target tree. To compute the opening of the second leaf
    /// for a tree with depth 2 in the forest `0b110`:
    ///
    /// - `leaf_idx`: Position corresponding to the order the leaves were added.
    /// - `forest`: State of the MMR.
    fn collect_merkle_path_and_value(
        &self,
        leaf_idx: usize,
        forest: Forest,
    ) -> Result<(Word, Vec<Word>), MmrError> {
        // find the target tree responsible for the MMR position
        let tree_bit = forest
            .leaf_to_corresponding_tree(leaf_idx)
            .ok_or(MmrError::PositionNotFound(leaf_idx))?;

        // isolate the trees before the target
        let forest_before = forest.trees_larger_than(tree_bit);
        let index_offset = forest_before.num_nodes();

        // update the value position from global to the target tree
        let relative_pos = leaf_idx - forest_before.num_leaves();

        // see documentation of `leaf_to_corresponding_tree` for details
        let tree_depth = (tree_bit + 1) as usize;
        let mut path = Vec::with_capacity(tree_depth);

        // The tree walk below goes from the root to the leaf, compute the root index to start
        let mut forest_target: usize = 1usize << tree_bit;
        let mut index = nodes_from_mask(forest_target) - 1;

        // Loop until the leaf is reached
        while forest_target > 1 {
            // Update the depth of the tree to correspond to a subtree
            forest_target >>= 1;

            // compute the indices of the right and left subtrees based on the post-order
            let right_offset = index - 1;
            let left_offset = right_offset - nodes_from_mask(forest_target);

            let left_or_right = relative_pos & forest_target;
            let sibling = if left_or_right != 0 {
                // going down the right subtree, the right child becomes the new root
                index = right_offset;
                // and the left child is the authentication
                self.nodes[index_offset + left_offset]
            } else {
                index = left_offset;
                self.nodes[index_offset + right_offset]
            };

            path.push(sibling);
        }

        debug_assert!(path.len() == tree_depth - 1);

        // the rest of the codebase has the elements going from leaf to root, adjust it here for
        // easy of use/consistency sake
        path.reverse();

        let value = self.nodes[index_offset + index];
        Ok((value, path))
    }
}

// CONVERSIONS
// ================================================================================================

// No TryFrom<T> impl: it conflicts with core’s blanket TryFrom<U> where U: Into<T>.

// SERIALIZATION
// ================================================================================================

impl Serializable for Mmr {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.forest.write_into(target);
        self.nodes.write_into(target);
    }
}

impl Deserializable for Mmr {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let forest = Forest::read_from(source)?;
        let nodes = Vec::<Word>::read_from(source)?;
        Ok(Self { forest, nodes })
    }
}

// ITERATOR
// ===============================================================================================

/// Yields inner nodes of the [Mmr].
pub struct MmrNodes<'a> {
    /// [Mmr] being yielded, when its `forest` value is matched, the iterations is finished.
    mmr: &'a Mmr,
    /// Keeps track of the left nodes yielded so far waiting for a right pair, this matches the
    /// semantics of the [Mmr]'s forest attribute, since that too works as a buffer of left nodes
    /// waiting for a pair to be hashed together.
    forest: usize,
    /// Keeps track of the last right node yielded, after this value is set, the next iteration
    /// will be its parent with its corresponding left node that has been yield already.
    last_right: usize,
    /// The current index in the `nodes` vector.
    index: usize,
}

impl Iterator for MmrNodes<'_> {
    type Item = InnerNodeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        debug_assert!(self.last_right.count_ones() <= 1, "last_right tracks zero or one element");

        // only parent nodes are emitted, remove the single node tree from the forest
        let target = self.mmr.forest.without_single_leaf().num_leaves();

        if self.forest < target {
            if self.last_right == 0 {
                // yield the left leaf
                debug_assert!(self.last_right == 0, "left must be before right");
                self.forest |= 1;
                self.index += 1;

                // yield the right leaf
                debug_assert!((self.forest & 1) == 1, "right must be after left");
                self.last_right |= 1;
                self.index += 1;
            };

            debug_assert!(
                self.forest & self.last_right != 0,
                "parent requires both a left and right",
            );

            // compute the number of nodes in the right tree, this is the offset to the
            // previous left parent
            let right_nodes = Forest::new(self.last_right).unwrap().num_nodes();
            // the next parent position is one above the position of the pair
            let parent = self.last_right << 1;

            // the left node has been paired and the current parent yielded, removed it from the
            // forest
            self.forest ^= self.last_right;
            if self.forest & parent == 0 {
                // this iteration yielded the left parent node
                debug_assert!(self.forest & 1 == 0, "next iteration yields a left leaf");
                self.last_right = 0;
                self.forest ^= parent;
            } else {
                // the left node of the parent level has been yielded already, this iteration
                // was the right parent. Next iteration yields their parent.
                self.last_right = parent;
            }

            // yields a parent
            let value = self.mmr.nodes[self.index];
            let right = self.mmr.nodes[self.index - 1];
            let left = self.mmr.nodes[self.index - 1 - right_nodes];
            self.index += 1;
            let node = InnerNodeInfo { value, left, right };

            Some(node)
        } else {
            None
        }
    }
}

// TESTS
// ================================================================================================
#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::super::nodes_from_mask;
    use crate::{
        Felt, Word, ZERO,
        merkle::mmr::{Forest, Mmr},
        utils::{Deserializable, DeserializationError, Serializable},
    };

    #[test]
    fn test_serialization() {
        let nodes = (0u64..128u64)
            .map(|value| Word::new([ZERO, ZERO, ZERO, Felt::new_unchecked(value)]))
            .collect::<Vec<_>>();

        let mmr = Mmr::try_from_iter(nodes).unwrap();
        let serialized = mmr.to_bytes();
        let deserialized = Mmr::read_from_bytes(&serialized).unwrap();
        assert_eq!(mmr.forest, deserialized.forest);
        assert_eq!(mmr.nodes, deserialized.nodes);
    }

    #[test]
    fn test_deserialization_rejects_large_forest() {
        let mut bytes = (Forest::MAX_LEAVES + 1).to_bytes();
        bytes.extend_from_slice(&0usize.to_bytes()); // empty nodes vector

        let result = Mmr::read_from_bytes(&bytes);
        assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
    }

    #[test]
    fn test_nodes_from_mask_at_max_leaves() {
        let expected = (Forest::MAX_LEAVES as u128)
            .saturating_mul(2)
            .saturating_sub(Forest::MAX_LEAVES.count_ones() as u128);
        assert!(expected <= usize::MAX as u128);
        assert_eq!(nodes_from_mask(Forest::MAX_LEAVES), expected as usize);
    }
}
