use alloc::vec::Vec;
use core::{
    num::NonZero,
    ops::{Deref, DerefMut},
};

use super::{InnerNodeInfo, MerkleError, NodeIndex, Poseidon2, Word};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// MERKLE PATH
// ================================================================================================

/// A merkle path container, composed of a sequence of nodes of a Merkle tree.
///
/// Indexing into this type starts at the deepest part of the path and gets shallower. That is,
/// the node at index `0` is deeper than the node at index `self.len() - 1`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MerklePath {
    nodes: Vec<Word>,
}

impl MerklePath {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new Merkle path from a list of nodes.
    ///
    /// The list must be in order of deepest to shallowest.
    pub fn new(nodes: Vec<Word>) -> Self {
        assert!(nodes.len() <= u8::MAX.into(), "MerklePath may have at most 256 items");
        Self { nodes }
    }

    // PROVIDERS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the path node at the specified depth.
    ///
    /// The `depth` parameter is defined in terms of `self.depth()`. Merkle paths conventionally do
    /// not include the root, so the shallowest depth is `1`, and the deepest depth is
    /// `self.depth()`.
    pub fn at_depth(&self, depth: NonZero<u8>) -> Option<Word> {
        let index = u8::checked_sub(self.depth(), depth.get())?;
        self.nodes.get(index as usize).copied()
    }

    /// Returns the depth in which this Merkle path proof is valid.
    pub fn depth(&self) -> u8 {
        self.nodes.len() as u8
    }

    /// Returns a reference to the [MerklePath]'s nodes, in order of deepest to shallowest.
    pub fn nodes(&self) -> &[Word] {
        &self.nodes
    }

    /// Computes the merkle root for this opening.
    pub fn compute_root(&self, index: u64, node: Word) -> Result<Word, MerkleError> {
        let mut index = NodeIndex::new(self.depth(), index)?;
        let root = self.nodes.iter().copied().fold(node, |node, sibling| {
            // compute the node and move to the next iteration.
            let input = index.build_node(node, sibling);
            index.move_up();
            Poseidon2::merge(&input)
        });
        Ok(root)
    }

    /// Verifies the Merkle opening proof towards the provided root.
    ///
    /// # Errors
    /// Returns an error if:
    /// - provided node index is invalid.
    /// - root calculated during the verification differs from the provided one.
    pub fn verify(&self, index: u64, node: Word, root: &Word) -> Result<(), MerkleError> {
        let computed_root = self.compute_root(index, node)?;
        if &computed_root != root {
            return Err(MerkleError::ConflictingRoots {
                expected_root: *root,
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
    /// the parent of `node_to_prove`, either `left` or `right` will be `node_to_prove` itself, and
    /// the other child will be `node_to_prove` as stored in this [MerklePath].
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
        Ok(InnerNodeIterator {
            nodes: &self.nodes,
            index: NodeIndex::new(self.depth(), index)?,
            value: node_to_prove,
        })
    }
}

// CONVERSIONS
// ================================================================================================

impl From<MerklePath> for Vec<Word> {
    fn from(path: MerklePath) -> Self {
        path.nodes
    }
}

impl From<Vec<Word>> for MerklePath {
    fn from(path: Vec<Word>) -> Self {
        Self::new(path)
    }
}

impl From<&[Word]> for MerklePath {
    fn from(path: &[Word]) -> Self {
        Self::new(path.to_vec())
    }
}

impl Deref for MerklePath {
    // we use `Vec` here instead of slice so we can call vector mutation methods directly from the
    // merkle path (example: `Vec::remove`).
    type Target = Vec<Word>;

    fn deref(&self) -> &Self::Target {
        &self.nodes
    }
}

impl DerefMut for MerklePath {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.nodes
    }
}

// ITERATORS
// ================================================================================================

impl FromIterator<Word> for MerklePath {
    fn from_iter<T: IntoIterator<Item = Word>>(iter: T) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

impl IntoIterator for MerklePath {
    type Item = Word;
    type IntoIter = alloc::vec::IntoIter<Word>;

    fn into_iter(self) -> Self::IntoIter {
        self.nodes.into_iter()
    }
}

/// An iterator over internal nodes of a [MerklePath]. See [`MerklePath::authenticated_nodes()`]
pub struct InnerNodeIterator<'a> {
    nodes: &'a Vec<Word>,
    index: NodeIndex,
    value: Word,
}

impl Iterator for InnerNodeIterator<'_> {
    type Item = InnerNodeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.index.is_root() {
            let sibling_pos = self.nodes.len() - self.index.depth() as usize;
            let (left, right) = if self.index.is_position_odd() {
                (self.nodes[sibling_pos], self.value)
            } else {
                (self.value, self.nodes[sibling_pos])
            };

            self.value = Poseidon2::merge(&[left, right]);
            self.index.move_up();

            Some(InnerNodeInfo { value: self.value, left, right })
        } else {
            None
        }
    }
}

// MERKLE PATH CONTAINERS
// ================================================================================================

/// A container for a [crate::Word] value and its [MerklePath] opening.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MerkleProof {
    /// The node value opening for `path`.
    pub value: Word,
    /// The path from `value` to `root` (exclusive).
    pub path: MerklePath,
}

impl MerkleProof {
    /// Returns a new [MerkleProof] instantiated from the specified value and path.
    pub fn new(value: Word, path: MerklePath) -> Self {
        Self { value, path }
    }
}

impl From<(MerklePath, Word)> for MerkleProof {
    fn from((path, value): (MerklePath, Word)) -> Self {
        MerkleProof::new(value, path)
    }
}

/// A container for a [MerklePath] and its [crate::Word] root.
///
/// This structure does not provide any guarantees regarding the correctness of the path to the
/// root. For more information, check [MerklePath::verify].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RootPath {
    /// The node value opening for `path`.
    pub root: Word,
    /// The path from `value` to `root` (exclusive).
    pub path: MerklePath,
}

// SERIALIZATION
// ================================================================================================

impl Serializable for MerklePath {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        assert!(self.nodes.len() <= u8::MAX.into(), "Length enforced in the constructor");
        target.write_u8(self.nodes.len() as u8);
        target.write_many(&self.nodes);
    }
}

impl Deserializable for MerklePath {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = source.read_u8()?.into();
        let nodes: Vec<Word> = source.read_many_iter(count)?.collect::<Result<_, _>>()?;
        Ok(Self { nodes })
    }
}

impl Serializable for MerkleProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.value.write_into(target);
        self.path.write_into(target);
    }
}

impl Deserializable for MerkleProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = Word::read_from(source)?;
        let path = MerklePath::read_from(source)?;
        Ok(Self { value, path })
    }
}

impl Serializable for RootPath {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.root.write_into(target);
        self.path.write_into(target);
    }
}

impl Deserializable for RootPath {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let root = Word::read_from(source)?;
        let path = MerklePath::read_from(source)?;
        Ok(Self { root, path })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use crate::merkle::{MerklePath, int_to_node};

    #[test]
    fn test_inner_nodes() {
        let nodes = vec![int_to_node(1), int_to_node(2), int_to_node(3), int_to_node(4)];
        let merkle_path = MerklePath::new(nodes);

        let index = 6;
        let node = int_to_node(5);
        let root = merkle_path.compute_root(index, node).unwrap();

        let inner_root =
            merkle_path.authenticated_nodes(index, node).unwrap().last().unwrap().value;

        assert_eq!(root, inner_root);
    }
}
