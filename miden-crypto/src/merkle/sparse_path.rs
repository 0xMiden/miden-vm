use alloc::{borrow::Cow, vec::Vec};
use core::{
    iter::{self, FusedIterator},
    num::NonZero,
};

use super::{
    EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath, NodeIndex, Word, smt::SMT_MAX_DEPTH,
};
use crate::{
    hash::poseidon2::Poseidon2,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// A different representation of [`MerklePath`] designed for memory efficiency for Merkle paths
/// with empty nodes.
///
/// Empty nodes in the path are stored only as their position, represented with a bitmask. A
/// maximum of 64 nodes (`SMT_MAX_DEPTH`) can be stored (empty and non-empty). The more nodes in a
/// path are empty, the less memory this struct will use. This type calculates empty nodes on-demand
/// when iterated through, converted to a [MerklePath], or an empty node is retrieved with
/// [`SparseMerklePath::at_depth()`], which will incur overhead.
///
/// NOTE: This type assumes that Merkle paths always span from the root of the tree to a leaf.
/// Partial paths are not supported.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SparseMerklePath {
    /// A bitmask representing empty nodes. The set bit corresponds to the depth of an empty node.
    /// The least significant bit (bit 0) describes depth 1 node (root's children).
    /// The `bit index + 1` is equal to node's depth.
    empty_nodes_mask: u64,
    /// The non-empty nodes, stored in depth-order, but not contiguous across depth.
    nodes: Vec<Word>,
}

impl SparseMerklePath {
    /// Constructs a new sparse Merkle path from a bitmask of empty nodes and a vector of non-empty
    /// nodes.
    ///
    /// The `empty_nodes_mask` is a bitmask where each set bit indicates that the node at that
    /// depth is empty. The least significant bit (bit 0) describes depth 1 node (root's children).
    /// The `bit index + 1` is equal to node's depth.
    /// The `nodes` vector must contain the non-empty nodes in depth order.
    ///
    /// # Errors
    /// - [MerkleError::InvalidPathLength] if the provided `nodes` vector is shorter than the
    ///   minimum length required by the `empty_nodes_mask`.
    /// - [MerkleError::DepthTooBig] if the total depth of the path (calculated from the
    ///   `empty_nodes_mask` and `nodes`) is greater than [SMT_MAX_DEPTH].
    pub fn from_parts(empty_nodes_mask: u64, nodes: Vec<Word>) -> Result<Self, MerkleError> {
        // The most significant set bit in the mask marks the minimum length of the path.
        // For every zero bit before the first set bit, there must be a corresponding node in
        // `nodes`.
        // For example, if the mask is `0b1100`, this means that the first two nodes
        // (depths 1 and 2) are non-empty, and the next two nodes (depths 3 and 4) are empty.
        // The minimum length of the path is 4, and the `nodes` vector must contain at least 2
        // nodes to account for the first two zeroes in the mask (depths 1 and 2).
        let min_path_len = u64::BITS - empty_nodes_mask.leading_zeros();
        let empty_nodes_count = empty_nodes_mask.count_ones();
        let min_non_empty_nodes = (min_path_len - empty_nodes_count) as usize;

        if nodes.len() < min_non_empty_nodes {
            return Err(MerkleError::InvalidPathLength(min_non_empty_nodes));
        }

        let depth = Self::depth_from_parts(empty_nodes_mask, &nodes) as u8;
        if depth > SMT_MAX_DEPTH {
            return Err(MerkleError::DepthTooBig(depth as u64));
        }

        Ok(Self { empty_nodes_mask, nodes })
    }

    /// Constructs a sparse Merkle path from an iterator over Merkle nodes that also knows its
    /// exact size (such as iterators created with [Vec::into_iter]). The iterator must be in order
    /// of deepest to shallowest.
    ///
    /// Knowing the size is necessary to calculate the depth of the tree, which is needed to detect
    /// which nodes are empty nodes.
    ///
    /// # Errors
    /// Returns [MerkleError::DepthTooBig] if `tree_depth` is greater than [SMT_MAX_DEPTH].
    pub fn from_sized_iter<I>(iterator: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<IntoIter: ExactSizeIterator, Item = Word>,
    {
        let iterator = iterator.into_iter();
        let tree_depth = iterator.len() as u8;

        if tree_depth > SMT_MAX_DEPTH {
            return Err(MerkleError::DepthTooBig(tree_depth as u64));
        }

        let mut empty_nodes_mask: u64 = 0;
        let mut nodes: Vec<Word> = Default::default();

        for (depth, node) in iter::zip(path_depth_iter(tree_depth), iterator) {
            let &equivalent_empty_node = EmptySubtreeRoots::entry(tree_depth, depth.get());
            let is_empty = node == equivalent_empty_node;
            let node = if is_empty { None } else { Some(node) };

            match node {
                Some(node) => nodes.push(node),
                None => empty_nodes_mask |= Self::bitmask_for_depth(depth),
            }
        }

        Ok(SparseMerklePath { nodes, empty_nodes_mask })
    }

    /// Returns the total depth of this path, i.e., the number of nodes this path represents.
    pub fn depth(&self) -> u8 {
        Self::depth_from_parts(self.empty_nodes_mask, &self.nodes) as u8
    }

    /// Get a specific node in this path at a given depth.
    ///
    /// The `depth` parameter is defined in terms of `self.depth()`. Merkle paths conventionally do
    /// not include the root, so the shallowest depth is `1`, and the deepest depth is
    /// `self.depth()`.
    ///
    /// # Errors
    /// Returns [MerkleError::DepthTooBig] if `node_depth` is greater than the total depth of this
    /// path.
    pub fn at_depth(&self, node_depth: NonZero<u8>) -> Result<Word, MerkleError> {
        if node_depth.get() > self.depth() {
            return Err(MerkleError::DepthTooBig(node_depth.get().into()));
        }

        let node = if let Some(nonempty_index) = self.get_nonempty_index(node_depth) {
            self.nodes[nonempty_index]
        } else {
            *EmptySubtreeRoots::entry(self.depth(), node_depth.get())
        };

        Ok(node)
    }

    /// Deconstructs this path into its component parts.
    ///
    /// Returns a tuple containing:
    /// - a bitmask where each set bit indicates that the node at that depth is empty. The least
    ///   significant bit (bit 0) describes depth 1 node (root's children).
    /// - a vector of non-empty nodes in depth order.
    pub fn into_parts(self) -> (u64, Vec<Word>) {
        (self.empty_nodes_mask, self.nodes)
    }

    // PROVIDERS
    // ============================================================================================

    /// Constructs a borrowing iterator over the nodes in this path.
    /// Starts from the leaf and iterates toward the root (excluding the root).
    pub fn iter(&self) -> impl ExactSizeIterator<Item = Word> {
        self.into_iter()
    }

    /// Computes the Merkle root for this opening.
    pub fn compute_root(&self, index: u64, node_to_prove: Word) -> Result<Word, MerkleError> {
        let mut index = NodeIndex::new(self.depth(), index)?;
        let root = self.iter().fold(node_to_prove, |node, sibling| {
            // Compute the node and move to the next iteration.
            let children = index.build_node(node, sibling);
            index.move_up();
            Poseidon2::merge(&children)
        });

        Ok(root)
    }

    /// Verifies the Merkle opening proof towards the provided root.
    ///
    /// # Errors
    /// Returns an error if:
    /// - provided node index is invalid.
    /// - root calculated during the verification differs from the provided one.
    pub fn verify(&self, index: u64, node: Word, &expected_root: &Word) -> Result<(), MerkleError> {
        let computed_root = self.compute_root(index, node)?;
        if computed_root != expected_root {
            return Err(MerkleError::ConflictingRoots {
                expected_root,
                actual_root: computed_root,
            });
        }

        Ok(())
    }

    /// Given the node this path opens to, return an iterator of all the nodes that are known via
    /// this path.
    ///
    /// Each item in the iterator is an [InnerNodeInfo], containing the hash of a node as `.value`,
    /// and its two children as `.left` and `.right`. The very first item in that iterator will be
    /// the parent of `node_to_prove` as stored in this [SparseMerklePath].
    ///
    /// From there, the iterator will continue to yield every further parent and both of its
    /// children, up to and including the root node.
    ///
    /// If `node_to_prove` is not the node this path is an opening to, or `index` is not the
    /// correct index for that node, the returned nodes will be meaningless.
    ///
    /// # Errors
    /// Returns an error if the specified index is not valid for this path.
    pub fn authenticated_nodes(
        &self,
        index: u64,
        node_to_prove: Word,
    ) -> Result<InnerNodeIterator<'_>, MerkleError> {
        let index = NodeIndex::new(self.depth(), index)?;
        Ok(InnerNodeIterator { path: self, index, value: node_to_prove })
    }

    // PRIVATE HELPERS
    // ============================================================================================

    const fn bitmask_for_depth(node_depth: NonZero<u8>) -> u64 {
        // - 1 because paths do not include the root.
        1 << (node_depth.get() - 1)
    }

    const fn is_depth_empty(&self, node_depth: NonZero<u8>) -> bool {
        (self.empty_nodes_mask & Self::bitmask_for_depth(node_depth)) != 0
    }

    /// Index of the non-empty node in the `self.nodes` vector. If the specified depth is
    /// empty, None is returned.
    fn get_nonempty_index(&self, node_depth: NonZero<u8>) -> Option<usize> {
        if self.is_depth_empty(node_depth) {
            return None;
        }

        let bit_index = node_depth.get() - 1;
        let without_shallower = self.empty_nodes_mask >> bit_index;
        let empty_deeper = without_shallower.count_ones() as usize;
        // The vec index we would use if we didn't have any empty nodes to account for...
        let normal_index = (self.depth() - node_depth.get()) as usize;
        // subtracted by the number of empty nodes that are deeper than us.
        Some(normal_index - empty_deeper)
    }

    /// Returns the total depth of this path from its parts.
    fn depth_from_parts(empty_nodes_mask: u64, nodes: &[Word]) -> usize {
        nodes.len() + empty_nodes_mask.count_ones() as usize
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for SparseMerklePath {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.depth());
        target.write_u64(self.empty_nodes_mask);
        target.write_many(&self.nodes);
    }
}

impl Deserializable for SparseMerklePath {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let depth = source.read_u8()?;
        if depth > SMT_MAX_DEPTH {
            return Err(DeserializationError::InvalidValue(format!(
                "SparseMerklePath max depth exceeded ({depth} > {SMT_MAX_DEPTH})",
            )));
        }
        let empty_nodes_mask = source.read_u64()?;
        let empty_nodes_count = empty_nodes_mask.count_ones();
        if empty_nodes_count > depth as u32 {
            return Err(DeserializationError::InvalidValue(format!(
                "SparseMerklePath has more empty nodes ({empty_nodes_count}) than its full length ({depth})",
            )));
        }
        let count = depth as u32 - empty_nodes_count;
        let nodes: Vec<Word> = source.read_many_iter(count as usize)?.collect::<Result<_, _>>()?;
        Ok(Self { empty_nodes_mask, nodes })
    }
}

// CONVERSIONS
// ================================================================================================

impl From<SparseMerklePath> for MerklePath {
    fn from(sparse_path: SparseMerklePath) -> Self {
        MerklePath::from_iter(sparse_path)
    }
}

impl TryFrom<MerklePath> for SparseMerklePath {
    type Error = MerkleError;

    /// # Errors
    ///
    /// This conversion returns [MerkleError::DepthTooBig] if the path length is greater than
    /// [`SMT_MAX_DEPTH`].
    fn try_from(path: MerklePath) -> Result<Self, MerkleError> {
        SparseMerklePath::from_sized_iter(path)
    }
}

impl From<SparseMerklePath> for Vec<Word> {
    fn from(path: SparseMerklePath) -> Self {
        Vec::from_iter(path)
    }
}

// ITERATORS
// ================================================================================================

/// Iterator for [`SparseMerklePath`]. Starts from the leaf and iterates toward the root (excluding
/// the root).
pub struct SparseMerklePathIter<'p> {
    /// The "inner" value we're iterating over.
    path: Cow<'p, SparseMerklePath>,

    /// The depth a `next()` call will get. `next_depth == 0` indicates that the iterator has been
    /// exhausted.
    next_depth: u8,
}

impl Iterator for SparseMerklePathIter<'_> {
    type Item = Word;

    fn next(&mut self) -> Option<Word> {
        let this_depth = self.next_depth;
        // Paths don't include the root, so if `this_depth` is 0 then we keep returning `None`.
        let this_depth = NonZero::new(this_depth)?;
        self.next_depth = this_depth.get() - 1;

        // `this_depth` is only ever decreasing, so it can't ever exceed `self.path.depth()`.
        let node = self
            .path
            .at_depth(this_depth)
            .expect("current depth should never exceed the path depth");
        Some(node)
    }

    // SparseMerkleIter always knows its exact size.
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = ExactSizeIterator::len(self);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for SparseMerklePathIter<'_> {
    fn len(&self) -> usize {
        self.next_depth as usize
    }
}

impl FusedIterator for SparseMerklePathIter<'_> {}

// TODO: impl DoubleEndedIterator.

impl IntoIterator for SparseMerklePath {
    type IntoIter = SparseMerklePathIter<'static>;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> SparseMerklePathIter<'static> {
        let tree_depth = self.depth();
        SparseMerklePathIter {
            path: Cow::Owned(self),
            next_depth: tree_depth,
        }
    }
}

impl<'p> IntoIterator for &'p SparseMerklePath {
    type Item = <SparseMerklePathIter<'p> as Iterator>::Item;
    type IntoIter = SparseMerklePathIter<'p>;

    fn into_iter(self) -> SparseMerklePathIter<'p> {
        let tree_depth = self.depth();
        SparseMerklePathIter {
            path: Cow::Borrowed(self),
            next_depth: tree_depth,
        }
    }
}

/// An iterator over nodes known by a [SparseMerklePath]. See
/// [`SparseMerklePath::authenticated_nodes()`].
pub struct InnerNodeIterator<'p> {
    path: &'p SparseMerklePath,
    index: NodeIndex,
    value: Word,
}

impl Iterator for InnerNodeIterator<'_> {
    type Item = InnerNodeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index.is_root() {
            return None;
        }

        let index_depth = NonZero::new(self.index.depth()).expect("non-root depth cannot be 0");
        let path_node = self.path.at_depth(index_depth).unwrap();

        let children = self.index.build_node(self.value, path_node);
        self.value = Poseidon2::merge(&children);
        self.index.move_up();

        Some(InnerNodeInfo {
            value: self.value,
            left: children[0],
            right: children[1],
        })
    }
}

// COMPARISONS
// ================================================================================================
impl PartialEq<MerklePath> for SparseMerklePath {
    fn eq(&self, rhs: &MerklePath) -> bool {
        if self.depth() != rhs.depth() {
            return false;
        }

        for (node, &rhs_node) in iter::zip(self, rhs.iter()) {
            if node != rhs_node {
                return false;
            }
        }

        true
    }
}

impl PartialEq<SparseMerklePath> for MerklePath {
    fn eq(&self, rhs: &SparseMerklePath) -> bool {
        rhs == self
    }
}

// HELPERS
// ================================================================================================

/// Iterator for path depths, which start at the deepest part of the tree and go the shallowest
/// depth before the root (depth 1).
fn path_depth_iter(tree_depth: u8) -> impl ExactSizeIterator<Item = NonZero<u8>> {
    let top_down_iter = (1..=tree_depth).map(|depth| {
        // RangeInclusive<1, _> guarantees depth >= 1
        NonZero::new(depth).expect("range is bounded by 1")
    });

    // Reverse the top-down iterator to get a bottom-up iterator.
    top_down_iter.rev()
}

// TESTS
// ================================================================================================
#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::num::NonZero;

    use assert_matches::assert_matches;

    use super::SparseMerklePath;
    use crate::{
        Felt, ONE, Word,
        merkle::{
            EmptySubtreeRoots, MerkleError, MerklePath, MerkleTree, NodeIndex,
            smt::{LeafIndex, SMT_MAX_DEPTH, SimpleSmt, Smt, SparseMerkleTree},
            sparse_path::path_depth_iter,
        },
    };

    fn make_smt(pair_count: u64) -> Smt {
        let entries: Vec<(Word, Word)> = (0..pair_count)
            .map(|n| {
                let leaf_index = ((n as f64 / pair_count as f64) * 255.0) as u64;
                let key =
                    Word::new([ONE, ONE, Felt::new_unchecked(n), Felt::new_unchecked(leaf_index)]);
                let value = Word::new([ONE, ONE, ONE, ONE]);
                (key, value)
            })
            .collect();

        Smt::with_entries(entries).unwrap()
    }

    /// Manually test the exact bit patterns for a sample path of 8 nodes, including both empty and
    /// non-empty nodes.
    ///
    /// This also offers an overview of what each part of the bit-math involved means and
    /// represents.
    #[test]
    fn test_sparse_bits() {
        const DEPTH: u8 = 8;
        let raw_nodes: [Word; DEPTH as usize] = [
            // Depth 8.
            ([8u8, 8, 8, 8].into()),
            // Depth 7.
            *EmptySubtreeRoots::entry(DEPTH, 7),
            // Depth 6.
            *EmptySubtreeRoots::entry(DEPTH, 6),
            // Depth 5.
            [5u8, 5, 5, 5].into(),
            // Depth 4.
            [4u8, 4, 4, 4].into(),
            // Depth 3.
            *EmptySubtreeRoots::entry(DEPTH, 3),
            // Depth 2.
            *EmptySubtreeRoots::entry(DEPTH, 2),
            // Depth 1.
            *EmptySubtreeRoots::entry(DEPTH, 1),
            // Root is not included.
        ];

        let sparse_nodes: [Option<Word>; DEPTH as usize] = [
            // Depth 8.
            Some([8u8, 8, 8, 8].into()),
            // Depth 7.
            None,
            // Depth 6.
            None,
            // Depth 5.
            Some([5u8, 5, 5, 5].into()),
            // Depth 4.
            Some([4u8, 4, 4, 4].into()),
            // Depth 3.
            None,
            // Depth 2.
            None,
            // Depth 1.
            None,
            // Root is not included.
        ];

        const EMPTY_BITS: u64 = 0b0110_0111;

        let sparse_path = SparseMerklePath::from_sized_iter(raw_nodes).unwrap();

        assert_eq!(sparse_path.empty_nodes_mask, EMPTY_BITS);

        // Keep track of how many non-empty nodes we have seen
        let mut nonempty_idx = 0;

        // Test starting from the deepest nodes (depth 8)
        for depth in (1..=8).rev() {
            let idx = (sparse_path.depth() - depth) as usize;
            let bit = 1 << (depth - 1);

            // Check that the depth bit is set correctly...
            let is_set = (sparse_path.empty_nodes_mask & bit) != 0;
            assert_eq!(is_set, sparse_nodes.get(idx).unwrap().is_none());

            if is_set {
                // Check that we don't return digests for empty nodes
                let &test_node = sparse_nodes.get(idx).unwrap();
                assert_eq!(test_node, None);
            } else {
                // Check that we can calculate non-empty indices correctly.
                let control_node = raw_nodes.get(idx).unwrap();
                assert_eq!(
                    sparse_path.get_nonempty_index(NonZero::new(depth).unwrap()).unwrap(),
                    nonempty_idx
                );
                let test_node = sparse_path.nodes.get(nonempty_idx).unwrap();
                assert_eq!(test_node, control_node);

                nonempty_idx += 1;
            }
        }
    }

    #[test]
    fn from_parts() {
        const DEPTH: u8 = 8;
        let raw_nodes: [Word; DEPTH as usize] = [
            // Depth 8.
            ([8u8, 8, 8, 8].into()),
            // Depth 7.
            *EmptySubtreeRoots::entry(DEPTH, 7),
            // Depth 6.
            *EmptySubtreeRoots::entry(DEPTH, 6),
            // Depth 5.
            [5u8, 5, 5, 5].into(),
            // Depth 4.
            [4u8, 4, 4, 4].into(),
            // Depth 3.
            *EmptySubtreeRoots::entry(DEPTH, 3),
            // Depth 2.
            *EmptySubtreeRoots::entry(DEPTH, 2),
            // Depth 1.
            *EmptySubtreeRoots::entry(DEPTH, 1),
            // Root is not included.
        ];

        let empty_nodes_mask = 0b0110_0111;
        let nodes = vec![[8u8, 8, 8, 8].into(), [5u8, 5, 5, 5].into(), [4u8, 4, 4, 4].into()];
        let insufficient_nodes = vec![[4u8, 4, 4, 4].into()];

        let error = SparseMerklePath::from_parts(empty_nodes_mask, insufficient_nodes).unwrap_err();
        assert_matches!(error, MerkleError::InvalidPathLength(2));

        let iter_sparse_path = SparseMerklePath::from_sized_iter(raw_nodes).unwrap();
        let sparse_path = SparseMerklePath::from_parts(empty_nodes_mask, nodes).unwrap();

        assert_eq!(sparse_path, iter_sparse_path);
    }

    #[test]
    fn from_sized_iter() {
        let tree = make_smt(8192);

        for (key, _value) in tree.entries() {
            let index = NodeIndex::from(Smt::key_to_leaf_index(key));
            let sparse_path = tree.get_path(key);
            for (sparse_node, proof_idx) in
                itertools::zip_eq(sparse_path.clone(), index.proof_indices())
            {
                let proof_node = tree.get_node_hash(proof_idx);
                assert_eq!(sparse_node, proof_node);
            }
        }
    }

    #[test]
    fn test_zero_sized() {
        let nodes: Vec<Word> = Default::default();

        // Sparse paths that don't actually contain any nodes should still be well behaved.
        let sparse_path = SparseMerklePath::from_sized_iter(nodes).unwrap();
        assert_eq!(sparse_path.depth(), 0);
        assert_matches!(
            sparse_path.at_depth(NonZero::new(1).unwrap()),
            Err(MerkleError::DepthTooBig(1))
        );
        assert_eq!(sparse_path.iter().next(), None);
        assert_eq!(sparse_path.into_iter().next(), None);
    }

    use proptest::prelude::*;

    // Arbitrary instance for MerklePath
    impl Arbitrary for MerklePath {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop::collection::vec(any::<Word>(), 0..=SMT_MAX_DEPTH as usize)
                .prop_map(MerklePath::new)
                .boxed()
        }
    }

    // Arbitrary instance for SparseMerklePath
    impl Arbitrary for SparseMerklePath {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            (0..=SMT_MAX_DEPTH as usize)
                .prop_flat_map(|depth| {
                    // Generate a bitmask for empty nodes - avoid overflow
                    let max_mask = if depth > 0 && depth < 64 {
                        (1u64 << depth) - 1
                    } else if depth == 64 {
                        u64::MAX
                    } else {
                        0
                    };
                    let empty_nodes_mask =
                        prop::num::u64::ANY.prop_map(move |mask| mask & max_mask);

                    // Generate non-empty nodes based on the mask
                    empty_nodes_mask.prop_flat_map(move |mask| {
                        let empty_count = mask.count_ones() as usize;
                        let non_empty_count = depth.saturating_sub(empty_count);

                        prop::collection::vec(any::<Word>(), non_empty_count).prop_map(
                            move |nodes| SparseMerklePath::from_parts(mask, nodes).unwrap(),
                        )
                    })
                })
                .boxed()
        }
    }

    proptest! {
        #[test]
        fn sparse_merkle_path_roundtrip_equivalence(path in any::<MerklePath>()) {
            // Convert MerklePath to SparseMerklePath and back
            let sparse_result = SparseMerklePath::try_from(path.clone());
            if path.depth() <= SMT_MAX_DEPTH {
                let sparse = sparse_result.unwrap();
                let reconstructed = MerklePath::from(sparse);
                prop_assert_eq!(path, reconstructed);
            } else {
                prop_assert!(sparse_result.is_err());
            }
        }
    }
    proptest! {

        #[test]
        fn merkle_path_roundtrip_equivalence(sparse in any::<SparseMerklePath>()) {
            // Convert SparseMerklePath to MerklePath and back
            let merkle = MerklePath::from(sparse.clone());
            let reconstructed = SparseMerklePath::try_from(merkle.clone()).unwrap();
            prop_assert_eq!(sparse, reconstructed);
        }
    }
    proptest! {

        #[test]
        fn path_equivalence_tests(path in any::<MerklePath>(), path2 in any::<MerklePath>()) {
            if path.depth() > SMT_MAX_DEPTH {
                return Ok(());
            }

            let sparse = SparseMerklePath::try_from(path.clone()).unwrap();

            // Depth consistency
            prop_assert_eq!(path.depth(), sparse.depth());

            // Node access consistency including path_depth_iter
            if path.depth() > 0 {
                for depth in path_depth_iter(path.depth()) {
                    let merkle_node = path.at_depth(depth);
                    let sparse_node = sparse.at_depth(depth);

                    match (merkle_node, sparse_node) {
                        (Some(m), Ok(s)) => prop_assert_eq!(m, s),
                        (None, Err(_)) => {},
                        _ => prop_assert!(false, "Inconsistent node access at depth {}", depth.get()),
                    }
                }
            }

            // Iterator consistency
            if path.depth() > 0 {
                let merkle_nodes: Vec<_> = path.iter().collect();
                let sparse_nodes: Vec<_> = sparse.iter().collect();

                prop_assert_eq!(merkle_nodes.len(), sparse_nodes.len());
                for (m, s) in merkle_nodes.iter().zip(sparse_nodes.iter()) {
                    prop_assert_eq!(*m, s);
                }
            }

            // Test equality between different representations
            if path2.depth() <= SMT_MAX_DEPTH {
                let sparse2 = SparseMerklePath::try_from(path2.clone()).unwrap();
                prop_assert_eq!(path == path2, sparse == sparse2);
                prop_assert_eq!(path == sparse2, sparse == path2);
            }
        }
    }
    // rather heavy tests
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn compute_root_consistency(
            tree_data in any::<RandomMerkleTree>(),
            node in any::<Word>()
        ) {
            let RandomMerkleTree { tree, leaves: _,  indices } = tree_data;

            for &leaf_index in indices.iter() {
                let path = tree.get_path(NodeIndex::new(tree.depth(), leaf_index).unwrap()).unwrap();
                let sparse = SparseMerklePath::from_sized_iter(path.clone().into_iter()).unwrap();

                let merkle_root = path.compute_root(leaf_index, node);
                let sparse_root = sparse.compute_root(leaf_index, node);

                match (merkle_root, sparse_root) {
                    (Ok(m), Ok(s)) => prop_assert_eq!(m, s),
                    (Err(e1), Err(e2)) => {
                        // Both should have the same error type
                        prop_assert_eq!(format!("{:?}", e1), format!("{:?}", e2));
                    },
                    _ => prop_assert!(false, "Inconsistent compute_root results"),
                }
            }
        }

        #[test]
        fn verify_consistency(
            tree_data in any::<RandomMerkleTree>(),
            node in any::<Word>()
        ) {
            let RandomMerkleTree { tree, leaves, indices } = tree_data;

            for (i, &leaf_index) in indices.iter().enumerate() {
                let leaf = leaves[i];
                let path = tree.get_path(NodeIndex::new(tree.depth(), leaf_index).unwrap()).unwrap();
                let sparse = SparseMerklePath::from_sized_iter(path.clone().into_iter()).unwrap();

                let root = tree.root();

                let merkle_verify = path.verify(leaf_index, leaf, &root);
                let sparse_verify = sparse.verify(leaf_index, leaf, &root);

                match (merkle_verify, sparse_verify) {
                    (Ok(()), Ok(())) => {},
                    (Err(e1), Err(e2)) => {
                        // Both should have the same error type
                        prop_assert_eq!(format!("{:?}", e1), format!("{:?}", e2));
                    },
                    _ => prop_assert!(false, "Inconsistent verify results"),
                }

                // Test with wrong node - both should fail
                let wrong_verify = path.verify(leaf_index, node, &root);
                let wrong_sparse_verify = sparse.verify(leaf_index, node, &root);

                match (wrong_verify, wrong_sparse_verify) {
                    (Ok(()), Ok(())) => prop_assert!(false, "Verification should have failed with wrong node"),
                    (Err(_), Err(_)) => {},
                    _ => prop_assert!(false, "Inconsistent verification results with wrong node"),
                }
            }
        }

        #[test]
        fn authenticated_nodes_consistency(
            tree_data in any::<RandomMerkleTree>()
        ) {
            let RandomMerkleTree { tree, leaves, indices } = tree_data;

            for (i, &leaf_index) in indices.iter().enumerate() {
                let leaf = leaves[i];
                let path = tree.get_path(NodeIndex::new(tree.depth(), leaf_index).unwrap()).unwrap();
                let sparse = SparseMerklePath::from_sized_iter(path.clone().into_iter()).unwrap();

                let merkle_result = path.authenticated_nodes(leaf_index, leaf);
                let sparse_result = sparse.authenticated_nodes(leaf_index, leaf);

                match (merkle_result, sparse_result) {
                    (Ok(m_iter), Ok(s_iter)) => {
                        let merkle_nodes: Vec<_> = m_iter.collect();
                        let sparse_nodes: Vec<_> = s_iter.collect();
                        prop_assert_eq!(merkle_nodes.len(), sparse_nodes.len());
                        for (m, s) in merkle_nodes.iter().zip(sparse_nodes.iter()) {
                            prop_assert_eq!(m, s);
                        }
                    },
                    (Err(e1), Err(e2)) => {
                        prop_assert_eq!(format!("{:?}", e1), format!("{:?}", e2));
                    },
                    _ => prop_assert!(false, "Inconsistent authenticated_nodes results"),
                }
            }
        }
    }

    #[test]
    fn test_api_differences() {
        // This test documents API differences between MerklePath and SparseMerklePath

        // 1. MerklePath has Deref/DerefMut to Vec<Word> - SparseMerklePath does not
        let merkle = MerklePath::new(vec![Word::default(); 3]);
        let _vec_ref: &Vec<Word> = &merkle; // This works due to Deref
        let _vec_mut: &mut Vec<Word> = &mut merkle.clone(); // This works due to DerefMut

        // 2. SparseMerklePath has from_parts() - MerklePath uses new() or from_iter()
        let sparse = SparseMerklePath::from_parts(0b101, vec![Word::default(); 2]).unwrap();
        assert_eq!(sparse.depth(), 4); // depth is 4 because mask has bits set up to depth 4

        // 3. SparseMerklePath has from_sized_iter() - MerklePath uses from_iter()
        let nodes = vec![Word::default(); 3];
        let sparse_from_iter = SparseMerklePath::from_sized_iter(nodes.clone()).unwrap();
        let merkle_from_iter = MerklePath::from_iter(nodes);
        assert_eq!(sparse_from_iter.depth(), merkle_from_iter.depth());
    }

    // Arbitrary instance for MerkleTree with random leaves
    #[derive(Debug, Clone)]
    struct RandomMerkleTree {
        tree: MerkleTree,
        leaves: Vec<Word>,
        indices: Vec<u64>,
    }

    impl Arbitrary for RandomMerkleTree {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // Generate trees with power-of-2 leaves up to 1024 (2^10)
            prop::sample::select(&[2, 4, 8, 16, 32, 64, 128, 256, 512, 1024])
                .prop_flat_map(|num_leaves| {
                    prop::collection::vec(any::<Word>(), num_leaves).prop_map(|leaves| {
                        let tree = MerkleTree::new(leaves.clone()).unwrap();
                        let indices: Vec<u64> = (0..leaves.len() as u64).collect();
                        RandomMerkleTree { tree, leaves, indices }
                    })
                })
                .boxed()
        }
    }

    // Arbitrary instance for SimpleSmt with random entries
    #[derive(Debug, Clone)]
    struct RandomSimpleSmt {
        tree: SimpleSmt<10>, // Depth 10 = 1024 leaves
        entries: Vec<(u64, Word)>,
    }

    impl Arbitrary for RandomSimpleSmt {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            (1..=100usize) // 1-100 entries in an 1024-leaf tree
                .prop_flat_map(|num_entries| {
                    prop::collection::vec(
                        (
                            0..1024u64, // Valid indices for 1024-leaf tree
                            any::<Word>(),
                        ),
                        num_entries,
                    )
                    .prop_map(|mut entries| {
                        // Ensure unique indices to avoid duplicates
                        let mut seen = alloc::collections::BTreeSet::new();
                        entries.retain(|(idx, _)| seen.insert(*idx));

                        let mut tree = SimpleSmt::new().unwrap();
                        for (idx, value) in &entries {
                            let leaf_idx = LeafIndex::new(*idx).unwrap();
                            tree.insert(leaf_idx, *value);
                        }
                        RandomSimpleSmt { tree, entries }
                    })
                })
                .boxed()
        }
    }

    // Arbitrary instance for Smt with random entries
    #[derive(Debug, Clone)]
    struct RandomSmt {
        tree: Smt,
        entries: Vec<(Word, Word)>,
    }

    impl Arbitrary for RandomSmt {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            (1..=100usize) // 1-100 entries in a sparse tree
                .prop_flat_map(|num_entries| {
                    prop::collection::vec((any::<u64>(), any::<Word>()), num_entries).prop_map(
                        |indices_n_values| {
                            let entries: Vec<(Word, Word)> = indices_n_values
                                .into_iter()
                                .enumerate()
                                .map(|(n, (leaf_index, value))| {
                                    // SMT uses the most significant element (index 3) as leaf index
                                    // Ensure we use valid leaf indices for the SMT depth
                                    let valid_leaf_index = leaf_index % (1u64 << 60); // Use large but valid range
                                    let key = Word::new([
                                        Felt::new_unchecked(n as u64),         // element 0
                                        Felt::new_unchecked(n as u64 + 1),     // element 1
                                        Felt::new_unchecked(n as u64 + 2),     // element 2
                                        Felt::new_unchecked(valid_leaf_index), // element 3 (leaf index)
                                    ]);
                                    (key, value)
                                })
                                .collect();

                            // Ensure unique keys to avoid duplicates
                            let mut seen = alloc::collections::BTreeSet::new();
                            let unique_entries: Vec<_> =
                                entries.into_iter().filter(|(key, _)| seen.insert(*key)).collect();

                            let tree = Smt::with_entries(unique_entries.clone()).unwrap();
                            RandomSmt { tree, entries: unique_entries }
                        },
                    )
                })
                .boxed()
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        #[test]
        fn simple_smt_path_consistency(tree_data in any::<RandomSimpleSmt>()) {
            let RandomSimpleSmt { tree, entries } = tree_data;

            for (leaf_index, value) in &entries {
                let merkle_path = tree.get_path(&LeafIndex::new(*leaf_index).unwrap());
                let sparse_path = SparseMerklePath::from_sized_iter(merkle_path.clone().into_iter()).unwrap();

                // Verify both paths have same depth
                prop_assert_eq!(merkle_path.depth(), sparse_path.depth());

                // Verify both paths produce same root for the same value
                let merkle_root = merkle_path.compute_root(*leaf_index, *value).unwrap();
                let sparse_root = sparse_path.compute_root(*leaf_index, *value).unwrap();
                prop_assert_eq!(merkle_root, sparse_root);

                // Verify both paths verify correctly
                let tree_root = tree.root();
                prop_assert!(merkle_path.verify(*leaf_index, *value, &tree_root).is_ok());
                prop_assert!(sparse_path.verify(*leaf_index, *value, &tree_root).is_ok());

                // Test with random additional leaf
                let random_leaf = Word::new([Felt::ONE; 4]);
                let random_index = *leaf_index ^ 1; // Ensure it's a sibling

                // Both should fail verification with wrong leaf
                let merkle_wrong = merkle_path.verify(random_index, random_leaf, &tree_root);
                let sparse_wrong = sparse_path.verify(random_index, random_leaf, &tree_root);
                prop_assert_eq!(merkle_wrong.is_err(), sparse_wrong.is_err());
            }
        }

        #[test]
        fn smt_path_consistency(tree_data in any::<RandomSmt>()) {
            let RandomSmt { tree, entries } = tree_data;

            for (key, _value) in &entries {
                let (merkle_path, leaf) = tree.open(key).into_parts();
                let sparse_path = SparseMerklePath::from_sized_iter(merkle_path.clone().into_iter()).unwrap();

                let leaf_index = Smt::key_to_leaf_index(key).position();
                let actual_value = leaf.hash(); // Use the actual leaf hash

                // Verify both paths have same depth
                prop_assert_eq!(merkle_path.depth(), sparse_path.depth());

                // Verify both paths produce same root for the same value
                let merkle_root = merkle_path.compute_root(leaf_index, actual_value).unwrap();
                let sparse_root = sparse_path.compute_root(leaf_index, actual_value).unwrap();
                prop_assert_eq!(merkle_root, sparse_root);

                // Verify both paths verify correctly
                let tree_root = tree.root();
                prop_assert!(merkle_path.verify(leaf_index, actual_value, &tree_root).is_ok());
                prop_assert!(sparse_path.verify(leaf_index, actual_value, &tree_root).is_ok());

                // Test authenticated nodes consistency
                let merkle_auth = merkle_path.authenticated_nodes(leaf_index, actual_value).unwrap().collect::<Vec<_>>();
                let sparse_auth = sparse_path.authenticated_nodes(leaf_index, actual_value).unwrap().collect::<Vec<_>>();
                prop_assert_eq!(merkle_auth, sparse_auth);
            }
        }

        #[test]
        fn reverse_conversion_from_sparse(tree_data in any::<RandomMerkleTree>()) {
            let RandomMerkleTree { tree, leaves, indices } = tree_data;

            for (i, &leaf_index) in indices.iter().enumerate() {
                let leaf = leaves[i];
                let merkle_path = tree.get_path(NodeIndex::new(tree.depth(), leaf_index).unwrap()).unwrap();

                // Create SparseMerklePath first, then convert to MerklePath
                let sparse_path = SparseMerklePath::from_sized_iter(merkle_path.clone().into_iter()).unwrap();
                let converted_merkle = MerklePath::from(sparse_path.clone());

                // Verify conversion back and forth works
                let back_to_sparse = SparseMerklePath::try_from(converted_merkle.clone()).unwrap();
                prop_assert_eq!(sparse_path, back_to_sparse);

                // Verify all APIs work identically
                prop_assert_eq!(merkle_path.depth(), converted_merkle.depth());

                let merkle_root = merkle_path.compute_root(leaf_index, leaf).unwrap();
                let converted_root = converted_merkle.compute_root(leaf_index, leaf).unwrap();
                prop_assert_eq!(merkle_root, converted_root);
            }
        }
    }
}
