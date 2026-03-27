use alloc::{string::String, vec::Vec};
use core::{fmt, slice};

use super::{InnerNodeInfo, MerkleError, MerklePath, NodeIndex, Poseidon2, Word};
use crate::utils::{assume_init_vec, uninit_vector, word_to_hex};

// MERKLE TREE
// ================================================================================================

/// A fully-balanced binary Merkle tree (i.e., a tree where the number of leaves is a power of two).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MerkleTree {
    nodes: Vec<Word>,
}

impl MerkleTree {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a Merkle tree instantiated from the provided leaves.
    ///
    /// # Errors
    /// Returns an error if the number of leaves is smaller than two or is not a power of two.
    pub fn new<T>(leaves: T) -> Result<Self, MerkleError>
    where
        T: AsRef<[Word]>,
    {
        let leaves = leaves.as_ref();
        let n = leaves.len();
        if n <= 1 {
            return Err(MerkleError::DepthTooSmall(n as u8));
        } else if !n.is_power_of_two() {
            return Err(MerkleError::NumLeavesNotPowerOfTwo(n));
        }

        // Create an uninitialized vector to avoid eagerly zeroing `2 * n` words. This is a
        // hot path during tree construction; see benches in `miden-crypto/benches/merkle.rs`
        // (e.g. `merkle_tree_construction`) for performance motivation.
        // SAFETY: All elements are written before being read (leaves copied, then computed).
        let mut nodes = uninit_vector::<Word>(2 * n);
        nodes[0].write(Word::default());

        // copy leaves into the second part of the nodes vector
        nodes[n..].iter_mut().zip(leaves).for_each(|(node, leaf)| {
            node.write(*leaf);
        });

        // calculate all internal tree nodes
        for i in (1..n).rev() {
            // SAFETY: We fill leaves first, then iterate from the bottom up. At this point,
            // nodes[2 * i] and nodes[2 * i + 1] have already been written.
            let left = unsafe { nodes[2 * i].assume_init_read() };
            let right = unsafe { nodes[2 * i + 1].assume_init_read() };
            nodes[i].write(Poseidon2::merge(&[left, right]));
        }

        // SAFETY: all elements were written above.
        let nodes = unsafe { assume_init_vec(nodes) };

        Ok(Self { nodes })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of this Merkle tree.
    pub fn root(&self) -> Word {
        self.nodes[1]
    }

    /// Returns the depth of this Merkle tree.
    ///
    /// Merkle tree of depth 1 has two leaves, depth 2 has four leaves etc.
    pub fn depth(&self) -> u8 {
        (self.nodes.len() / 2).ilog2() as u8
    }

    /// Returns a node at the specified depth and index value.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The specified depth is greater than the depth of the tree.
    /// * The specified index is not valid for the specified depth.
    pub fn get_node(&self, index: NodeIndex) -> Result<Word, MerkleError> {
        if index.is_root() {
            return Err(MerkleError::DepthTooSmall(index.depth()));
        } else if index.depth() > self.depth() {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        }

        let pos = index.to_scalar_index()? as usize;
        Ok(self.nodes[pos])
    }

    /// Returns a Merkle path to the node at the specified depth and index value. The node itself
    /// is not included in the path.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The specified depth is greater than the depth of the tree.
    /// * The specified value is not valid for the specified depth.
    pub fn get_path(&self, index: NodeIndex) -> Result<MerklePath, MerkleError> {
        if index.is_root() {
            return Err(MerkleError::DepthTooSmall(index.depth()));
        } else if index.depth() > self.depth() {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        }

        Ok(MerklePath::from(Vec::from_iter(
            index.proof_indices().map(|index| self.get_node(index).unwrap()),
        )))
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [MerkleTree].
    pub fn leaves(&self) -> impl Iterator<Item = (u64, &Word)> {
        let leaves_start = self.nodes.len() / 2;
        self.nodes.iter().skip(leaves_start).enumerate().map(|(i, v)| (i as u64, v))
    }

    /// Returns n iterator over every inner node of this [MerkleTree].
    ///
    /// The iterator order is unspecified.
    pub fn inner_nodes(&self) -> InnerNodeIterator<'_> {
        InnerNodeIterator {
            nodes: &self.nodes,
            index: 1, // index 0 is just padding, start at 1
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Replaces the leaf at the specified index with the provided value.
    ///
    /// # Errors
    /// Returns an error if the specified index value is not a valid leaf value for this tree.
    pub fn update_leaf<'a>(&'a mut self, index_value: u64, value: Word) -> Result<(), MerkleError> {
        let mut index = NodeIndex::new(self.depth(), index_value)?;

        // Performance note: We use unsafe pointer casts here for ~2-2.5% performance improvement
        // at scale. See benches/merkle.rs for benchmarks. The safe alternative uses index
        // arithmetic (`nodes[pos*2]`, `nodes[pos*2+1]`) which is measurably slower on large
        // trees.

        // we don't need to copy the pairs into a new address as we are logically guaranteed to not
        // overlap write instructions. however, it's important to bind the lifetime of pairs to
        // `self.nodes` so the compiler will never move one without moving the other.
        debug_assert_eq!(self.nodes.len() & 1, 0);
        let n = self.nodes.len() / 2;

        // Safety: the length of nodes is guaranteed to contain pairs of words; hence, pairs of
        // digests. we explicitly bind the lifetime here so we add an extra layer of guarantee that
        // `self.nodes` will be moved only if `pairs` is moved as well. also, the algorithm is
        // logically guaranteed to not overlap write positions as the write index is always half
        // the index from which we read the digest input.
        let ptr = self.nodes.as_ptr() as *const [Word; 2];
        let pairs: &'a [[Word; 2]] = unsafe { slice::from_raw_parts(ptr, n) };

        // update the current node
        let pos = index.to_scalar_index()? as usize;
        self.nodes[pos] = value;

        // traverse to the root, updating each node with the merged values of its parents
        for _ in 0..index.depth() {
            index.move_up();
            let pos = index.to_scalar_index()? as usize;
            let value = Poseidon2::merge(&pairs[pos]);
            self.nodes[pos] = value;
        }

        Ok(())
    }
}

// CONVERSIONS
// ================================================================================================

impl TryFrom<&[Word]> for MerkleTree {
    type Error = MerkleError;

    fn try_from(value: &[Word]) -> Result<Self, Self::Error> {
        MerkleTree::new(value)
    }
}

// ITERATORS
// ================================================================================================

/// An iterator over every inner node of the [MerkleTree].
///
/// Use this to extract the data of the tree, there is no guarantee on the order of the elements.
pub struct InnerNodeIterator<'a> {
    nodes: &'a Vec<Word>,
    index: usize,
}

impl Iterator for InnerNodeIterator<'_> {
    type Item = InnerNodeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.nodes.len() / 2 {
            let value = self.index;
            let left = self.index * 2;
            let right = left + 1;

            self.index += 1;

            Some(InnerNodeInfo {
                value: self.nodes[value],
                left: self.nodes[left],
                right: self.nodes[right],
            })
        } else {
            None
        }
    }
}

// UTILITY FUNCTIONS
// ================================================================================================

/// Utility to visualize a [MerkleTree] in text.
pub fn tree_to_text(tree: &MerkleTree) -> Result<String, fmt::Error> {
    let indent = "  ";
    let mut s = String::new();
    s.push_str(&word_to_hex(&tree.root())?);
    s.push('\n');
    for d in 1..=tree.depth() {
        let entries = 2u64.pow(d.into());
        for i in 0..entries {
            let index = NodeIndex::new(d, i).expect("The index must always be valid");
            let node = tree.get_node(index).expect("The node must always be found");

            for _ in 0..d {
                s.push_str(indent);
            }
            s.push_str(&word_to_hex(&node)?);
            s.push('\n');
        }
    }

    Ok(s)
}

/// Utility to visualize a [MerklePath] in text.
pub fn path_to_text(path: &MerklePath) -> Result<String, fmt::Error> {
    let mut s = String::new();
    s.push('[');

    for el in path.iter() {
        s.push_str(&word_to_hex(el)?);
        s.push_str(", ");
    }

    // remove the last ", "
    if !path.is_empty() {
        s.pop();
        s.pop();
    }
    s.push(']');

    Ok(s)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use proptest::prelude::*;

    use super::*;
    use crate::{
        Felt,
        merkle::{int_to_leaf, int_to_node},
    };

    const LEAVES4: [Word; Word::NUM_ELEMENTS] =
        [int_to_node(1), int_to_node(2), int_to_node(3), int_to_node(4)];

    const LEAVES8: [Word; 8] = [
        int_to_node(1),
        int_to_node(2),
        int_to_node(3),
        int_to_node(4),
        int_to_node(5),
        int_to_node(6),
        int_to_node(7),
        int_to_node(8),
    ];

    #[test]
    fn build_merkle_tree() {
        let tree = super::MerkleTree::new(LEAVES4).unwrap();
        assert_eq!(8, tree.nodes.len());

        // leaves were copied correctly
        for (a, b) in tree.nodes.iter().skip(4).zip(LEAVES4.iter()) {
            assert_eq!(a, b);
        }

        let (root, node2, node3) = compute_internal_nodes();

        assert_eq!(root, tree.nodes[1]);
        assert_eq!(node2, tree.nodes[2]);
        assert_eq!(node3, tree.nodes[3]);

        assert_eq!(root, tree.root());
    }

    #[test]
    fn get_leaf() {
        let tree = super::MerkleTree::new(LEAVES4).unwrap();

        // check depth 2
        assert_eq!(LEAVES4[0], tree.get_node(NodeIndex::make(2, 0)).unwrap());
        assert_eq!(LEAVES4[1], tree.get_node(NodeIndex::make(2, 1)).unwrap());
        assert_eq!(LEAVES4[2], tree.get_node(NodeIndex::make(2, 2)).unwrap());
        assert_eq!(LEAVES4[3], tree.get_node(NodeIndex::make(2, 3)).unwrap());

        // check depth 1
        let (_, node2, node3) = compute_internal_nodes();

        assert_eq!(node2, tree.get_node(NodeIndex::make(1, 0)).unwrap());
        assert_eq!(node3, tree.get_node(NodeIndex::make(1, 1)).unwrap());
    }

    #[test]
    fn get_path() {
        let tree = super::MerkleTree::new(LEAVES4).unwrap();

        let (_, node2, node3) = compute_internal_nodes();

        // check depth 2
        assert_eq!(vec![LEAVES4[1], node3], *tree.get_path(NodeIndex::make(2, 0)).unwrap());
        assert_eq!(vec![LEAVES4[0], node3], *tree.get_path(NodeIndex::make(2, 1)).unwrap());
        assert_eq!(vec![LEAVES4[3], node2], *tree.get_path(NodeIndex::make(2, 2)).unwrap());
        assert_eq!(vec![LEAVES4[2], node2], *tree.get_path(NodeIndex::make(2, 3)).unwrap());

        // check depth 1
        assert_eq!(vec![node3], *tree.get_path(NodeIndex::make(1, 0)).unwrap());
        assert_eq!(vec![node2], *tree.get_path(NodeIndex::make(1, 1)).unwrap());
    }

    #[test]
    fn update_leaf() {
        let mut tree = super::MerkleTree::new(LEAVES8).unwrap();

        // update one leaf
        let value = 3;
        let new_node = int_to_leaf(9);
        let mut expected_leaves = LEAVES8.to_vec();
        expected_leaves[value as usize] = new_node;
        let expected_tree = super::MerkleTree::new(expected_leaves.clone()).unwrap();

        tree.update_leaf(value, new_node).unwrap();
        assert_eq!(expected_tree.nodes, tree.nodes);

        // update another leaf
        let value = 6;
        let new_node = int_to_leaf(10);
        expected_leaves[value as usize] = new_node;
        let expected_tree = super::MerkleTree::new(expected_leaves.clone()).unwrap();

        tree.update_leaf(value, new_node).unwrap();
        assert_eq!(expected_tree.nodes, tree.nodes);
    }

    #[test]
    fn nodes() -> Result<(), MerkleError> {
        let tree = super::MerkleTree::new(LEAVES4).unwrap();
        let root = tree.root();
        let l1n0 = tree.get_node(NodeIndex::make(1, 0))?;
        let l1n1 = tree.get_node(NodeIndex::make(1, 1))?;
        let l2n0 = tree.get_node(NodeIndex::make(2, 0))?;
        let l2n1 = tree.get_node(NodeIndex::make(2, 1))?;
        let l2n2 = tree.get_node(NodeIndex::make(2, 2))?;
        let l2n3 = tree.get_node(NodeIndex::make(2, 3))?;

        let nodes: Vec<InnerNodeInfo> = tree.inner_nodes().collect();
        let expected = vec![
            InnerNodeInfo { value: root, left: l1n0, right: l1n1 },
            InnerNodeInfo { value: l1n0, left: l2n0, right: l2n1 },
            InnerNodeInfo { value: l1n1, left: l2n2, right: l2n3 },
        ];
        assert_eq!(nodes, expected);

        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_word_can_be_represented_as_digest(
            a in prop::num::u64::ANY,
            b in prop::num::u64::ANY,
            c in prop::num::u64::ANY,
            d in prop::num::u64::ANY,
        ) {
            // this test will assert the memory equivalence between word and digest.
            // it is used to safeguard the `[MerkleTee::update_leaf]` implementation
            // that assumes this equivalence.

            // build a word and copy it to another address as digest
            let word = [Felt::new(a), Felt::new(b), Felt::new(c), Felt::new(d)];
            let digest = Word::from(word);

            // assert the addresses are different
            let word_ptr = word.as_ptr() as *const u8;
            let digest_ptr = digest.as_ptr() as *const u8;
            assert_ne!(word_ptr, digest_ptr);

            // compare the bytes representation
            let word_bytes = unsafe { slice::from_raw_parts(word_ptr, size_of::<Word>()) };
            let digest_bytes = unsafe { slice::from_raw_parts(digest_ptr, size_of::<Word>()) };
            assert_eq!(word_bytes, digest_bytes);
        }
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    fn compute_internal_nodes() -> (Word, Word, Word) {
        let node2 = Poseidon2::hash_elements(&[*LEAVES4[0], *LEAVES4[1]].concat());
        let node3 = Poseidon2::hash_elements(&[*LEAVES4[2], *LEAVES4[3]].concat());
        let root = Poseidon2::merge(&[node2, node3]);

        (root, node2, node3)
    }
}
