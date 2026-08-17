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
use alloc::{string::ToString, sync::Arc, vec::Vec};
use core::{iter::FusedIterator, ops::Index, slice};

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

// NODE STORE
// ===============================================================================================

/// Number of nodes per chunk in [NodeStore]: 1024 nodes * 32 bytes = 32 KiB per chunk.
const NODE_CHUNK_CAPACITY: usize = 1024;

/// Append-only node storage backed by fixed-size chunks shared between clones via [Arc].
///
/// The MMR's postorder node buffer is strictly append-only, so a clone taken at any point is
/// fully described by a frozen prefix of the buffer. Cloning a [NodeStore] copies only the spine
/// of [Arc] pointers, sharing all chunk contents with the original. [NodeStore::push] copies the
/// last chunk before appending if (and only if) it is shared with a clone, bounding the
/// copy-on-write cost at one chunk regardless of how many nodes the store holds.
///
/// Invariant: every chunk except the last contains exactly [NODE_CHUNK_CAPACITY] nodes, and no
/// chunk is empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct NodeStore {
    chunks: Vec<Arc<Vec<Word>>>,
}

impl NodeStore {
    /// Constructor for an empty [NodeStore].
    pub fn new() -> Self {
        Self { chunks: Vec::new() }
    }

    /// Returns the number of nodes in the store.
    pub fn len(&self) -> usize {
        match self.chunks.last() {
            Some(last) => (self.chunks.len() - 1) * NODE_CHUNK_CAPACITY + last.len(),
            None => 0,
        }
    }

    /// Appends a node to the store.
    pub fn push(&mut self, node: Word) {
        match self.chunks.last_mut() {
            Some(last) if last.len() < NODE_CHUNK_CAPACITY => {
                if Arc::get_mut(last).is_none() {
                    // The chunk is shared with a clone; copy it before appending. A plain
                    // `Arc::make_mut` would clone with capacity == len, growing past
                    // NODE_CHUNK_CAPACITY on later pushes, so copy with the full capacity instead.
                    let mut copy = Vec::with_capacity(NODE_CHUNK_CAPACITY);
                    copy.extend_from_slice(last);
                    *last = Arc::new(copy);
                }
                Arc::get_mut(last).expect("chunk is unique").push(node);
            },
            _ => {
                let mut chunk = Vec::with_capacity(NODE_CHUNK_CAPACITY);
                chunk.push(node);
                self.chunks.push(Arc::new(chunk));
            },
        }
    }

    /// Returns an iterator over all nodes in the store, in insertion (postorder) order.
    pub fn iter(&self) -> MmrNodeIter<'_> {
        self.iter_from(0)
    }

    /// Returns an iterator over the nodes at indices `start..`, in insertion (postorder) order.
    ///
    /// Skips directly to the chunk containing `start` instead of walking from the front. Returns
    /// an empty iterator if `start >= self.len()`.
    pub fn iter_from(&self, start: usize) -> MmrNodeIter<'_> {
        let first_chunk = start / NODE_CHUNK_CAPACITY;
        let offset = start % NODE_CHUNK_CAPACITY;
        match self.chunks.get(first_chunk) {
            Some(chunk) => MmrNodeIter {
                current: chunk[offset.min(chunk.len())..].iter(),
                chunks: &self.chunks[first_chunk + 1..],
            },
            None => MmrNodeIter { current: [].iter(), chunks: &[] },
        }
    }
}

impl Index<usize> for NodeStore {
    type Output = Word;

    fn index(&self, index: usize) -> &Word {
        &self.chunks[index / NODE_CHUNK_CAPACITY][index % NODE_CHUNK_CAPACITY]
    }
}

impl FromIterator<Word> for NodeStore {
    fn from_iter<T: IntoIterator<Item = Word>>(iter: T) -> Self {
        let mut store = Self::new();
        for node in iter {
            store.push(node);
        }
        store
    }
}

impl PartialEq<&[Word]> for NodeStore {
    fn eq(&self, other: &&[Word]) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

// MMR
// ===============================================================================================

/// A fully materialized Merkle Mountain Range, with every tree in the forest and all their
/// elements.
///
/// Since this is a full representation of the MMR, elements are never removed and the MMR will
/// grow roughly `O(2n)` in number of leaf elements.
///
/// Cloning is cheap: the nodes are stored in chunks shared between clones, so a clone copies
/// `O(num_nodes / 1024)` pointers instead of the full node buffer, and appending to the original
/// after a clone copies at most one chunk.
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
    pub(super) nodes: NodeStore,
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
            nodes: NodeStore::new(),
        }
    }

    /// Constructs an MMR from an iterator of leaves.
    ///
    /// # Errors
    /// Returns an error if the maximum forest size is exceeded.
    pub fn try_from_iter<T: IntoIterator<Item = Word>>(values: T) -> Result<Self, MmrError> {
        Self::try_from_iter_with_limit(values, Forest::MAX_LEAVES)
    }

    /// Constructs an MMR from its forest and complete node array, in insertion (postorder) order,
    /// e.g. as previously obtained from `mmr.nodes_from(0).copied()` (see [Mmr::nodes_from]).
    ///
    /// The only validation performed is structural: the node count must match `forest`. The
    /// nodes are otherwise taken verbatim — no hashes are recomputed or verified.
    /// Comparing the result's [Mmr::peaks] against a trusted commitment checks the accumulator
    /// state, but because the peaks are read from the stored nodes rather than recomputed, it does
    /// not validate any non-peak nodes. The nodes must therefore come from a trusted source, e.g.
    /// the caller's own previously validated state.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of nodes does not match the node count of `forest`.
    pub fn from_nodes_unchecked(
        forest: Forest,
        nodes: impl IntoIterator<Item = Word>,
    ) -> Result<Self, MmrError> {
        Self::from_store(forest, nodes.into_iter().collect())
    }

    /// Constructs an MMR from its forest and node store, validating the node count.
    fn from_store(forest: Forest, nodes: NodeStore) -> Result<Self, MmrError> {
        if nodes.len() != forest.num_nodes() {
            return Err(MmrError::InvalidNodeCount {
                expected: forest.num_nodes(),
                actual: nodes.len(),
            });
        }
        Ok(Self { forest, nodes })
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

    /// Returns an iterator over the MMR's nodes at indices `start..`, in insertion (postorder)
    /// order. Returns an empty iterator if `start` is greater than or equal to the total node
    /// count, which is given by `self.forest().num_nodes()`.
    ///
    /// The node buffer is strictly append-only, so a consumer that has persisted the first
    /// `start` nodes can incrementally sync by appending only the nodes returned here.
    ///
    /// Positioning is cheap: the iterator starts directly at `start` without walking the
    /// preceding nodes, and it knows its exact remaining length.
    pub fn nodes_from(&self, start: usize) -> impl ExactSizeIterator<Item = &Word> + Clone {
        self.nodes.iter_from(start)
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
        // Matches the wire format of `Vec<Word>`: a `write_usize` length prefix followed by the
        // elements in postorder.
        target.write_usize(self.nodes.len());
        target.write_many(self.nodes.iter());
    }
}

impl Deserializable for Mmr {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let forest = Forest::read_from(source)?;
        let count = source.read_usize()?;
        // Reject a forest/count mismatch before reading the nodes, so malformed input fails fast.
        if count != forest.num_nodes() {
            return Err(DeserializationError::InvalidValue(
                MmrError::InvalidNodeCount {
                    expected: forest.num_nodes(),
                    actual: count,
                }
                .to_string(),
            ));
        }
        let nodes = source.read_many_iter(count)?.collect::<Result<NodeStore, _>>()?;
        Self::from_store(forest, nodes)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

/// [Mmr] used to store its nodes as a flat `Vec<Word>` and derive serde directly, so a flat
/// sequence of words is the wire format previously-serialized data was written in. Deriving serde
/// on [NodeStore] would instead emit its chunked layout (a sequence of 1024-node sequences),
/// breaking compatibility with that data and leaking the chunk size into the wire format. These
/// impls preserve the original format by mirroring `Vec<Word>`'s serde representation — a length-
/// hinted sequence — streaming directly from/into the chunks with no intermediate flat copy.
#[cfg(feature = "serde")]
impl serde::Serialize for NodeStore {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for node in self.iter() {
            seq.serialize_element(node)?;
        }
        seq.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for NodeStore {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SeqVisitor;

        impl<'de> serde::de::Visitor<'de> for SeqVisitor {
            type Value = NodeStore;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a sequence of MMR nodes")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<NodeStore, A::Error> {
                let mut store = NodeStore::new();
                while let Some(node) = seq.next_element::<Word>()? {
                    store.push(node);
                }
                Ok(store)
            }
        }

        deserializer.deserialize_seq(SeqVisitor)
    }
}

// ITERATOR
// ===============================================================================================

/// Iterator over a suffix of the [Mmr]'s node buffer, in insertion (postorder) order.
///
/// Underlies [Mmr::nodes_from], which returns it opaquely. Positioning is cheap: [Iterator::nth]
/// (and therefore [Iterator::skip]) jumps over whole chunks instead of advancing one node at a
/// time, and the iterator knows its exact remaining length ([ExactSizeIterator]).
#[derive(Clone, Debug)]
pub(super) struct MmrNodeIter<'a> {
    /// Remainder of the chunk currently being yielded.
    current: slice::Iter<'a, Word>,
    /// Chunks after the current one; every chunk except the last is full.
    chunks: &'a [Arc<Vec<Word>>],
}

impl<'a> MmrNodeIter<'a> {
    /// Advances `current` to the next chunk, or returns `None` if no chunks remain.
    ///
    /// On `None` the iterator is left exhausted even if `current` still held items, so a caller
    /// skipping past the end (see [Iterator::nth]) doesn't leave the skipped items behind.
    fn advance_chunk(&mut self) -> Option<()> {
        match self.chunks.split_first() {
            Some((chunk, rest)) => {
                self.current = chunk.iter();
                self.chunks = rest;
                Some(())
            },
            None => {
                self.current = [].iter();
                None
            },
        }
    }
}

impl<'a> Iterator for MmrNodeIter<'a> {
    type Item = &'a Word;

    fn next(&mut self) -> Option<&'a Word> {
        loop {
            if let Some(node) = self.current.next() {
                return Some(node);
            }
            self.advance_chunk()?;
        }
    }

    fn nth(&mut self, mut n: usize) -> Option<&'a Word> {
        loop {
            let len = self.current.len();
            if n < len {
                return self.current.nth(n);
            }
            n -= len;
            self.advance_chunk()?;
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }

    fn count(self) -> usize {
        self.len()
    }
}

impl ExactSizeIterator for MmrNodeIter<'_> {
    fn len(&self) -> usize {
        self.current.len()
            + match self.chunks.split_last() {
                Some((last, full)) => full.len() * NODE_CHUNK_CAPACITY + last.len(),
                None => 0,
            }
    }
}

impl FusedIterator for MmrNodeIter<'_> {}

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
    use alloc::{sync::Arc, vec::Vec};

    use super::{super::nodes_from_mask, NODE_CHUNK_CAPACITY};
    use crate::{
        Felt, Word, ZERO,
        merkle::mmr::{Forest, Mmr, MmrError},
        utils::{Deserializable, DeserializationError, Serializable},
    };

    fn leaves(count: u64) -> impl Iterator<Item = Word> {
        (0..count).map(|value| Word::new([ZERO, ZERO, ZERO, Felt::new_unchecked(value)]))
    }

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
    fn test_serialization_matches_vec_format() {
        // Build an MMR spanning multiple chunks (> 2048 nodes) to cover chunk boundaries.
        let num_leaves = NODE_CHUNK_CAPACITY as u64 + NODE_CHUNK_CAPACITY as u64 / 2;
        let mmr = Mmr::try_from_iter(leaves(num_leaves)).unwrap();
        assert!(mmr.nodes.len() > 2 * NODE_CHUNK_CAPACITY);

        let mut expected = mmr.forest.to_bytes();
        let nodes_vec: Vec<Word> = mmr.nodes.iter().copied().collect();
        expected.extend_from_slice(&nodes_vec.to_bytes());

        assert_eq!(mmr.to_bytes(), expected);
        let deserialized = Mmr::read_from_bytes(&expected).unwrap();
        assert_eq!(mmr.forest, deserialized.forest);
        assert_eq!(mmr.nodes, deserialized.nodes);
    }

    /// Verifies the custom serde impls on [NodeStore] produce the exact representation the
    /// pre-[NodeStore] `Mmr` derive did (a flat `Vec<Word>` field), in both a self-describing
    /// format (JSON: struct/field names, flat array shape) and a compact binary format
    /// (postcard: length-prefixed, exercising the `serialize_seq` length hint).
    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_matches_vec_format() {
        /// Replica of `Mmr` as it was when its nodes were a `Vec<Word>` and serde was derived.
        #[derive(serde::Deserialize, serde::Serialize)]
        #[serde(rename = "Mmr")]
        struct VecMmr {
            forest: Forest,
            nodes: Vec<Word>,
        }

        // span multiple chunks to cover chunk boundaries
        let num_leaves = NODE_CHUNK_CAPACITY as u64 + NODE_CHUNK_CAPACITY as u64 / 2;
        let mmr = Mmr::try_from_iter(leaves(num_leaves)).unwrap();
        let vec_mmr = VecMmr {
            forest: mmr.forest,
            nodes: mmr.nodes.iter().copied().collect(),
        };

        let json = serde_json::to_string(&mmr).unwrap();
        assert_eq!(json, serde_json::to_string(&vec_mmr).unwrap());
        let from_json: Mmr = serde_json::from_str(&json).unwrap();
        assert_eq!(mmr.forest, from_json.forest);
        assert_eq!(mmr.nodes, from_json.nodes);

        let bytes = postcard::to_allocvec(&mmr).unwrap();
        assert_eq!(bytes, postcard::to_allocvec(&vec_mmr).unwrap());
        let from_bytes: Mmr = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(mmr.forest, from_bytes.forest);
        assert_eq!(mmr.nodes, from_bytes.nodes);
    }

    #[test]
    fn test_deserialization_rejects_node_count_mismatch() {
        let mmr = Mmr::try_from_iter(leaves(8)).unwrap();
        let mut bytes = mmr.forest.to_bytes();
        let mut nodes_vec: Vec<Word> = mmr.nodes.iter().copied().collect();
        nodes_vec.pop();
        bytes.extend_from_slice(&nodes_vec.to_bytes());

        let result = Mmr::read_from_bytes(&bytes);
        assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
    }

    #[test]
    fn test_clone_stays_frozen_after_push() {
        let num_leaves = 2 * NODE_CHUNK_CAPACITY as u64;
        let mut mmr = Mmr::try_from_iter(leaves(num_leaves)).unwrap();
        let clone = mmr.clone();

        for leaf in leaves(3 * NODE_CHUNK_CAPACITY as u64).skip(num_leaves as usize) {
            mmr.add(leaf).unwrap();
        }

        // The clone is an unchanged snapshot of the original at the time of cloning.
        let reference = Mmr::try_from_iter(leaves(num_leaves)).unwrap();
        assert_eq!(clone.forest, reference.forest);
        assert_eq!(clone.nodes, reference.nodes);
        assert_eq!(clone.peaks(), reference.peaks());

        // The original matches a freshly built MMR of the same size.
        let reference = Mmr::try_from_iter(leaves(3 * NODE_CHUNK_CAPACITY as u64)).unwrap();
        assert_eq!(mmr.forest, reference.forest);
        assert_eq!(mmr.nodes, reference.nodes);
        assert_eq!(mmr.peaks(), reference.peaks());
    }

    #[test]
    fn test_clone_shares_full_chunks() {
        let mut mmr = Mmr::try_from_iter(leaves(NODE_CHUNK_CAPACITY as u64)).unwrap();
        let clone = mmr.clone();
        mmr.add(Word::empty()).unwrap();

        // Pushing into the original diverges only the last (shared) chunk.
        let orig_chunks = &mmr.nodes.chunks;
        let clone_chunks = &clone.nodes.chunks;
        assert_eq!(orig_chunks.len(), clone_chunks.len());
        for (orig, cloned) in orig_chunks.iter().zip(clone_chunks).take(orig_chunks.len() - 1) {
            assert!(Arc::ptr_eq(orig, cloned));
        }
        assert!(!Arc::ptr_eq(orig_chunks.last().unwrap(), clone_chunks.last().unwrap()));
    }

    #[test]
    fn test_nodes_from() {
        // Span multiple chunks to cover chunk boundaries.
        let mmr = Mmr::try_from_iter(leaves(2 * NODE_CHUNK_CAPACITY as u64)).unwrap();
        let num_nodes = mmr.forest().num_nodes();
        let all: Vec<Word> = mmr.nodes_from(0).copied().collect();
        assert_eq!(all.len(), num_nodes);

        // Starts at chunk boundaries, mid-chunk, and in the last (partial) chunk.
        for start in [
            0,
            1,
            NODE_CHUNK_CAPACITY - 1,
            NODE_CHUNK_CAPACITY,
            NODE_CHUNK_CAPACITY + 1,
            num_nodes - 1,
            num_nodes,
            num_nodes + 1,
        ] {
            let suffix: Vec<Word> = mmr.nodes_from(start).copied().collect();
            assert_eq!(suffix, all[start.min(num_nodes)..]);
        }
    }

    #[test]
    fn test_node_iter_skip_matches_nodes_from() {
        // Span multiple chunks so skips cross chunk boundaries.
        let mmr = Mmr::try_from_iter(leaves(2 * NODE_CHUNK_CAPACITY as u64)).unwrap();
        let num_nodes = mmr.forest().num_nodes();
        let all: Vec<Word> = mmr.nodes_from(0).copied().collect();

        for start in [
            0,
            1,
            NODE_CHUNK_CAPACITY - 1,
            NODE_CHUNK_CAPACITY,
            NODE_CHUNK_CAPACITY + 1,
            num_nodes - 1,
            num_nodes,
            num_nodes + 1,
        ] {
            let skipped: Vec<Word> = mmr.nodes_from(0).skip(start).copied().collect();
            assert_eq!(skipped, all[start.min(num_nodes)..]);
        }

        // `nth` positions across a chunk boundary and resumes in order.
        let mut iter = mmr.nodes_from(0);
        assert_eq!(iter.nth(NODE_CHUNK_CAPACITY + 1), Some(&all[NODE_CHUNK_CAPACITY + 1]));
        assert_eq!(iter.next(), Some(&all[NODE_CHUNK_CAPACITY + 2]));

        // `nth` past the end exhausts the iterator.
        let mut iter = mmr.nodes_from(0);
        assert_eq!(iter.nth(num_nodes), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_node_iter_len() {
        let mmr = Mmr::try_from_iter(leaves(2 * NODE_CHUNK_CAPACITY as u64)).unwrap();
        let num_nodes = mmr.forest().num_nodes();

        for start in [0, 1, NODE_CHUNK_CAPACITY, num_nodes - 1, num_nodes, num_nodes + 1] {
            let iter = mmr.nodes_from(start);
            assert_eq!(iter.len(), num_nodes.saturating_sub(start));
            assert_eq!(iter.size_hint(), (iter.len(), Some(iter.len())));
        }

        // The length stays exact as the iterator advances, including across chunks.
        let mut iter = mmr.nodes_from(0);
        iter.next();
        assert_eq!(iter.len(), num_nodes - 1);
        iter.nth(NODE_CHUNK_CAPACITY);
        assert_eq!(iter.len(), num_nodes - NODE_CHUNK_CAPACITY - 2);
        assert_eq!(iter.count(), num_nodes - NODE_CHUNK_CAPACITY - 2);
    }

    #[test]
    fn test_nodes_from_incremental_persistence() {
        // Simulate a flat-file consumer: persist all nodes, grow the MMR, append only the new
        // nodes, and verify the result matches a full dump of the final state.
        let initial_leaves = NODE_CHUNK_CAPACITY as u64 / 2;
        let final_leaves = 2 * NODE_CHUNK_CAPACITY as u64;

        let mut mmr = Mmr::try_from_iter(leaves(initial_leaves)).unwrap();
        let mut persisted: Vec<Word> = mmr.nodes_from(0).copied().collect();

        for leaf in leaves(final_leaves).skip(initial_leaves as usize) {
            mmr.add(leaf).unwrap();
        }
        persisted.extend(mmr.nodes_from(persisted.len()).copied());

        assert_eq!(persisted.len(), mmr.forest().num_nodes());
        assert!(mmr.nodes == persisted.as_slice());
    }

    #[test]
    fn test_from_nodes_unchecked_round_trip() {
        // Sizes: empty forest, single-chunk, and multi-chunk with a partial last chunk.
        let multi_chunk = NODE_CHUNK_CAPACITY as u64 + NODE_CHUNK_CAPACITY as u64 / 2;
        for num_leaves in [0, 1, 8, multi_chunk] {
            let mmr = Mmr::try_from_iter(leaves(num_leaves)).unwrap();
            let rebuilt =
                Mmr::from_nodes_unchecked(mmr.forest(), mmr.nodes_from(0).copied()).unwrap();
            assert_eq!(mmr.forest, rebuilt.forest);
            assert_eq!(mmr.nodes, rebuilt.nodes);
            assert_eq!(mmr.peaks(), rebuilt.peaks());

            // Openings from the rebuilt MMR still verify against its peaks.
            let peaks = rebuilt.peaks();
            for pos in [0, num_leaves.saturating_sub(1) as usize] {
                if num_leaves > 0 {
                    let proof = rebuilt.open(pos).unwrap();
                    let leaf = rebuilt.get(pos).unwrap();
                    peaks.verify(leaf, proof).unwrap();
                }
            }
        }
    }

    #[test]
    fn test_from_nodes_unchecked_rejects_count_mismatch() {
        let mmr = Mmr::try_from_iter(leaves(8)).unwrap();
        let nodes: Vec<Word> = mmr.nodes_from(0).copied().collect();

        let too_few =
            Mmr::from_nodes_unchecked(mmr.forest(), nodes.iter().copied().take(nodes.len() - 1));
        assert!(matches!(
            too_few,
            Err(MmrError::InvalidNodeCount { expected, actual })
                if expected == nodes.len() && actual == nodes.len() - 1
        ));

        let too_many =
            Mmr::from_nodes_unchecked(mmr.forest(), nodes.iter().copied().chain([Word::empty()]));
        assert!(matches!(
            too_many,
            Err(MmrError::InvalidNodeCount { expected, actual })
                if expected == nodes.len() && actual == nodes.len() + 1
        ));
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
