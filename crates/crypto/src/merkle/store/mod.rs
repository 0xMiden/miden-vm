//! Merkle store for efficiently storing multiple Merkle trees with common subtrees.

use alloc::vec::Vec;
use core::borrow::Borrow;

use super::{
    EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath, MerkleProof, MerkleTree, NodeIndex,
    PartialMerkleTree, Poseidon2, RootPath, Word,
    mmr::Mmr,
    smt::{SimpleSmt, Smt},
};
use crate::{
    Map,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

#[cfg(test)]
mod tests;

// MERKLE STORE
// ================================================================================================

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StoreNode {
    left: Word,
    right: Word,
}

/// An in-memory data store for Merkelized data.
///
/// This is a in memory data store for Merkle trees, this store allows all the nodes of multiple
/// trees to live as long as necessary and without duplication, this allows the implementation of
/// space efficient persistent data structures.
///
/// Example usage:
///
/// ```rust
/// # use miden_crypto::{ZERO, Felt, Word};
/// # use miden_crypto::merkle::{NodeIndex, MerkleTree, store::MerkleStore};
/// # use miden_crypto::hash::poseidon2::Poseidon2;
/// # use miden_crypto::field::PrimeCharacteristicRing;
/// # const fn int_to_node(value: u64) -> Word {
/// #     Word::new([Felt::new_unchecked(value), ZERO, ZERO, ZERO])
/// # }
/// # let A = int_to_node(1);
/// # let B = int_to_node(2);
/// # let C = int_to_node(3);
/// # let D = int_to_node(4);
/// # let E = int_to_node(5);
/// # let F = int_to_node(6);
/// # let G = int_to_node(7);
/// # let H0 = int_to_node(8);
/// # let H1 = int_to_node(9);
/// # let T0 = MerkleTree::new([A, B, C, D, E, F, G, H0].to_vec()).expect("even number of leaves provided");
/// # let T1 = MerkleTree::new([A, B, C, D, E, F, G, H1].to_vec()).expect("even number of leaves provided");
/// # let ROOT0 = T0.root();
/// # let ROOT1 = T1.root();
/// let mut store: MerkleStore = MerkleStore::new();
///
/// // the store is initialized with the SMT empty nodes
/// assert_eq!(store.num_internal_nodes(), 255);
///
/// let tree1 = MerkleTree::new(vec![A, B, C, D, E, F, G, H0]).unwrap();
/// let tree2 = MerkleTree::new(vec![A, B, C, D, E, F, G, H1]).unwrap();
///
/// // populates the store with two merkle trees, common nodes are shared
/// store.extend(tree1.inner_nodes());
/// store.extend(tree2.inner_nodes());
///
/// // every leaf except the last are the same
/// for i in 0..7 {
///     let idx0 = NodeIndex::new(3, i).unwrap();
///     let d0 = store.get_node(ROOT0, idx0).unwrap();
///     let idx1 = NodeIndex::new(3, i).unwrap();
///     let d1 = store.get_node(ROOT1, idx1).unwrap();
///     assert_eq!(d0, d1, "Both trees have the same leaf at pos {i}");
/// }
///
/// // The leaves A-B-C-D are the same for both trees, so are their 2 immediate parents
/// for i in 0..4 {
///     let idx0 = NodeIndex::new(3, i).unwrap();
///     let d0 = store.get_path(ROOT0, idx0).unwrap();
///     let idx1 = NodeIndex::new(3, i).unwrap();
///     let d1 = store.get_path(ROOT1, idx1).unwrap();
///     assert_eq!(d0.path[0..2], d1.path[0..2], "Both sub-trees are equal up to two levels");
/// }
///
/// // Common internal nodes are shared, the two added trees have a total of 30, but the store has
/// // only 10 new entries, corresponding to the 10 unique internal nodes of these trees.
/// assert_eq!(store.num_internal_nodes() - 255, 10);
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MerkleStore {
    nodes: Map<Word, StoreNode>,
}

impl Default for MerkleStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleStore {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an empty `MerkleStore` instance.
    pub fn new() -> MerkleStore {
        // pre-populate the store with the empty hashes
        let nodes = empty_hashes().collect();
        MerkleStore { nodes }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Return a count of the non-leaf nodes in the store.
    pub fn num_internal_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the node at `index` rooted on the tree `root`.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the
    ///   store.
    pub fn get_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleError> {
        let mut hash = root;

        // corner case: check the root is in the store when called with index `NodeIndex::root()`
        self.nodes.get(&hash).ok_or(MerkleError::RootNotInStore(hash))?;

        for i in (0..index.depth()).rev() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeIndexNotFoundInStore(hash, index))?;

            let is_right = index.is_nth_bit_odd(i);
            hash = if is_right { node.right } else { node.left };
        }

        Ok(hash)
    }

    /// Returns the node at the specified `index` and its opening to the `root`.
    ///
    /// The path starts at the sibling of the target leaf.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the
    ///   store.
    pub fn get_path(&self, root: Word, index: NodeIndex) -> Result<MerkleProof, MerkleError> {
        let mut hash = root;
        let mut path = Vec::with_capacity(index.depth().into());

        // corner case: check the root is in the store when called with index `NodeIndex::root()`
        self.nodes.get(&hash).ok_or(MerkleError::RootNotInStore(hash))?;

        for i in (0..index.depth()).rev() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeIndexNotFoundInStore(hash, index))?;

            let is_right = index.is_nth_bit_odd(i);
            hash = if is_right {
                path.push(node.left);
                node.right
            } else {
                path.push(node.right);
                node.left
            }
        }

        // the path is computed from root to leaf, so it must be reversed
        path.reverse();

        Ok(MerkleProof::new(hash, MerklePath::new(path)))
    }

    /// Returns `true` if a valid path exists from `root` to the specified `index`, `false`
    /// otherwise.
    ///
    /// This method checks if all nodes needed to traverse from `root` to `index` are present in the
    /// store, without building the actual path. It is more efficient than `get_path` when only
    /// existence verification is needed.
    pub fn has_path(&self, root: Word, index: NodeIndex) -> bool {
        // check if the root exists
        if !self.nodes.contains_key(&root) {
            return false;
        }

        // traverse from root to index
        let mut hash = root;
        for i in (0..index.depth()).rev() {
            let node = match self.nodes.get(&hash) {
                Some(node) => node,
                None => return false,
            };

            let is_right = index.is_nth_bit_odd(i);
            hash = if is_right { node.right } else { node.left };
        }

        true
    }

    // LEAF TRAVERSAL
    // --------------------------------------------------------------------------------------------

    /// Returns the depth of the first leaf or an empty node encountered while traversing the tree
    /// from the specified root down according to the provided index.
    ///
    /// The `tree_depth` parameter specifies the depth of the tree rooted at `root`. The
    /// maximum value the argument accepts is [u64::BITS].
    ///
    /// # Errors
    /// Will return an error if:
    /// - The provided root is not found.
    /// - The provided `tree_depth` is greater than 64.
    /// - The provided `index` is not valid for a depth equivalent to `tree_depth`.
    /// - No leaf or an empty node was found while traversing the tree down to `tree_depth`.
    pub fn get_leaf_depth(
        &self,
        root: Word,
        tree_depth: u8,
        index: u64,
    ) -> Result<u8, MerkleError> {
        // validate depth and index
        if tree_depth > 64 {
            return Err(MerkleError::DepthTooBig(tree_depth as u64));
        }
        NodeIndex::new(tree_depth, index)?;

        // check if the root exists, providing the proper error report if it doesn't
        let empty = EmptySubtreeRoots::empty_hashes(tree_depth);
        let mut hash = root;
        if !self.nodes.contains_key(&hash) {
            return Err(MerkleError::RootNotInStore(hash));
        }

        // we traverse from root to leaf, so the path is reversed
        let mut path = (index << (64 - tree_depth)).reverse_bits();

        // iterate every depth and reconstruct the path from root to leaf
        for depth in 0..=tree_depth {
            // we short-circuit if an empty node has been found
            if hash == empty[depth as usize] {
                return Ok(depth);
            }

            // fetch the children pair, mapped by its parent hash
            let children = match self.nodes.get(&hash) {
                Some(node) => node,
                None => return Ok(depth),
            };

            // traverse down
            hash = if path & 1 == 0 { children.left } else { children.right };
            path >>= 1;
        }

        // return an error because we exhausted the index but didn't find either a leaf or an
        // empty node
        Err(MerkleError::DepthTooBig(tree_depth as u64 + 1))
    }

    /// Returns index and value of a leaf node which is the only leaf node in a subtree defined by
    /// the provided root. If the subtree contains zero or more than one leaf nodes None is
    /// returned.
    ///
    /// The `tree_depth` parameter specifies the depth of the parent tree such that `root` is
    /// located in this tree at `root_index`. The maximum value the argument accepts is
    /// [u64::BITS].
    ///
    /// # Errors
    /// Will return an error if:
    /// - The provided root is not found.
    /// - The provided `tree_depth` is greater than 64.
    /// - The provided `root_index` has depth greater than `tree_depth`.
    /// - A lone node at depth `tree_depth` is not a leaf node.
    pub fn find_lone_leaf(
        &self,
        root: Word,
        root_index: NodeIndex,
        tree_depth: u8,
    ) -> Result<Option<(NodeIndex, Word)>, MerkleError> {
        // we set max depth at u64::BITS as this is the largest meaningful value for a 64-bit index
        const MAX_DEPTH: u8 = u64::BITS as u8;
        if tree_depth > MAX_DEPTH {
            return Err(MerkleError::DepthTooBig(tree_depth as u64));
        }
        let empty = EmptySubtreeRoots::empty_hashes(MAX_DEPTH);

        let mut node = root;
        if !self.nodes.contains_key(&node) {
            return Err(MerkleError::RootNotInStore(node));
        }

        let mut index = root_index;
        if index.depth() > tree_depth {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        }

        // traverse down following the path of single non-empty nodes; this works because if a
        // node has two empty children it cannot contain a lone leaf. similarly if a node has
        // two non-empty children it must contain at least two leaves.
        for depth in index.depth()..tree_depth {
            // if the node is a leaf, return; otherwise, examine the node's children
            let children = match self.nodes.get(&node) {
                Some(node) => node,
                None => return Ok(Some((index, node))),
            };

            let empty_node = empty[depth as usize + 1];
            node = if children.left != empty_node && children.right == empty_node {
                index = index.left_child();
                children.left
            } else if children.left == empty_node && children.right != empty_node {
                index = index.right_child();
                children.right
            } else {
                return Ok(None);
            };
        }

        // if we are here, we got to `tree_depth`; thus, either the current node is a leaf node,
        // and so we return it, or it is an internal node, and then we return an error
        if self.nodes.contains_key(&node) {
            Err(MerkleError::DepthTooBig(tree_depth as u64 + 1))
        } else {
            Ok(Some((index, node)))
        }
    }

    // DATA EXTRACTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a subset of this Merkle store such that the returned Merkle store contains all
    /// nodes which are descendants of the specified roots.
    ///
    /// The roots for which no descendants exist in this Merkle store are ignored.
    pub fn subset<I, R>(&self, roots: I) -> MerkleStore
    where
        I: Iterator<Item = R>,
        R: Borrow<Word>,
    {
        let mut store = MerkleStore::new();
        for root in roots {
            let root = *root.borrow();
            store.clone_tree_from(root, self);
        }
        store
    }

    /// Iterator over the inner nodes of the [MerkleStore].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.nodes
            .iter()
            .map(|(r, n)| InnerNodeInfo { value: *r, left: n.left, right: n.right })
    }

    /// Iterator over the non-empty leaves of the Merkle tree associated with the specified `root`
    /// and `max_depth`.
    pub fn non_empty_leaves(
        &self,
        root: Word,
        max_depth: u8,
    ) -> impl Iterator<Item = (NodeIndex, Word)> + '_ {
        let empty_roots = EmptySubtreeRoots::empty_hashes(max_depth);
        let mut stack = Vec::new();
        stack.push((NodeIndex::new_unchecked(0, 0), root));

        core::iter::from_fn(move || {
            while let Some((index, node_hash)) = stack.pop() {
                // if we are at the max depth then we have reached a leaf
                if index.depth() == max_depth {
                    return Some((index, node_hash));
                }

                // fetch the nodes children and push them onto the stack if they are not the roots
                // of empty subtrees
                if let Some(node) = self.nodes.get(&node_hash) {
                    if !empty_roots.contains(&node.left) {
                        stack.push((index.left_child(), node.left));
                    }
                    if !empty_roots.contains(&node.right) {
                        stack.push((index.right_child(), node.right));
                    }

                // if the node is not in the store assume it is a leaf
                } else {
                    return Some((index, node_hash));
                }
            }

            None
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds all the nodes of a Merkle path represented by `path`, opening to `node`. Returns the
    /// new root.
    ///
    /// This will compute the sibling elements determined by the Merkle `path` and `node`, and
    /// include all the nodes into the store.
    pub fn add_merkle_path(
        &mut self,
        index: u64,
        node: Word,
        path: MerklePath,
    ) -> Result<Word, MerkleError> {
        let root = path.authenticated_nodes(index, node)?.fold(Word::default(), |_, node| {
            let value: Word = node.value;
            let left: Word = node.left;
            let right: Word = node.right;

            debug_assert_eq!(Poseidon2::merge(&[left, right]), value);
            self.nodes.insert(value, StoreNode { left, right });

            node.value
        });
        Ok(root)
    }

    /// Adds all the nodes of multiple Merkle paths into the store.
    ///
    /// This will compute the sibling elements for each Merkle `path` and include all the nodes
    /// into the store.
    ///
    /// For further reference, check [MerkleStore::add_merkle_path].
    pub fn add_merkle_paths<I>(&mut self, paths: I) -> Result<(), MerkleError>
    where
        I: IntoIterator<Item = (u64, Word, MerklePath)>,
    {
        for (index_value, node, path) in paths.into_iter() {
            self.add_merkle_path(index_value, node, path)?;
        }
        Ok(())
    }

    /// Sets a node to `value`.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the
    ///   store.
    pub fn set_node(
        &mut self,
        mut root: Word,
        index: NodeIndex,
        value: Word,
    ) -> Result<RootPath, MerkleError> {
        let node = value;
        let MerkleProof { value, path } = self.get_path(root, index)?;

        // performs the update only if the node value differs from the opening
        if node != value {
            root = self.add_merkle_path(index.position(), node, path.clone())?;
        }

        Ok(RootPath { root, path })
    }

    /// Merges two elements and adds the resulting node into the store.
    ///
    /// Merges arbitrary values. They may be leaves, nodes, or a mixture of both.
    pub fn merge_roots(&mut self, left_root: Word, right_root: Word) -> Result<Word, MerkleError> {
        let parent = Poseidon2::merge(&[left_root, right_root]);
        self.nodes.insert(parent, StoreNode { left: left_root, right: right_root });

        Ok(parent)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the inner storage of this MerkleStore while consuming `self`.
    pub fn into_inner(self) -> Map<Word, StoreNode> {
        self.nodes
    }

    /// Recursively clones a tree with the specified root from the specified source into self.
    ///
    /// If the source store does not contain a tree with the specified root, this is a noop.
    fn clone_tree_from(&mut self, root: Word, source: &Self) {
        // process the node only if it is in the source
        if let Some(node) = source.nodes.get(&root) {
            // if the node has already been inserted, no need to process it further as all of its
            // descendants should be already cloned from the source store
            if self.nodes.insert(root, *node).is_none() {
                self.clone_tree_from(node.left, source);
                self.clone_tree_from(node.right, source);
            }
        }
    }
}

// CONVERSIONS
// ================================================================================================

impl From<&MerkleTree> for MerkleStore {
    fn from(value: &MerkleTree) -> Self {
        let nodes = combine_nodes_with_empty_hashes(value.inner_nodes()).collect();
        Self { nodes }
    }
}

impl<const DEPTH: u8> From<&SimpleSmt<DEPTH>> for MerkleStore {
    fn from(value: &SimpleSmt<DEPTH>) -> Self {
        let nodes = combine_nodes_with_empty_hashes(value.inner_nodes()).collect();
        Self { nodes }
    }
}

impl From<&Smt> for MerkleStore {
    fn from(value: &Smt) -> Self {
        let nodes = combine_nodes_with_empty_hashes(value.inner_nodes()).collect();
        Self { nodes }
    }
}

impl From<&Mmr> for MerkleStore {
    fn from(value: &Mmr) -> Self {
        let nodes = combine_nodes_with_empty_hashes(value.inner_nodes()).collect();
        Self { nodes }
    }
}

impl From<&PartialMerkleTree> for MerkleStore {
    fn from(value: &PartialMerkleTree) -> Self {
        let nodes = combine_nodes_with_empty_hashes(value.inner_nodes()).collect();
        Self { nodes }
    }
}

impl FromIterator<InnerNodeInfo> for MerkleStore {
    fn from_iter<I: IntoIterator<Item = InnerNodeInfo>>(iter: I) -> Self {
        let nodes = combine_nodes_with_empty_hashes(iter).collect();
        Self { nodes }
    }
}

impl FromIterator<(Word, StoreNode)> for MerkleStore {
    fn from_iter<I: IntoIterator<Item = (Word, StoreNode)>>(iter: I) -> Self {
        let nodes = iter.into_iter().chain(empty_hashes()).collect();
        Self { nodes }
    }
}

// ITERATORS
// ================================================================================================
impl Extend<InnerNodeInfo> for MerkleStore {
    fn extend<I: IntoIterator<Item = InnerNodeInfo>>(&mut self, iter: I) {
        self.nodes.extend(
            iter.into_iter()
                .map(|info| (info.value, StoreNode { left: info.left, right: info.right })),
        );
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for StoreNode {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.left.write_into(target);
        self.right.write_into(target);
    }
}

impl Deserializable for StoreNode {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let left = Word::read_from(source)?;
        let right = Word::read_from(source)?;
        Ok(StoreNode { left, right })
    }
}

impl Serializable for MerkleStore {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(self.nodes.len() as u64);

        for (k, v) in self.nodes.iter() {
            k.write_into(target);
            v.write_into(target);
        }
    }
}

impl Deserializable for MerkleStore {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len_u64 = source.read_u64()?;
        let len = usize::try_from(len_u64).map_err(|_| {
            DeserializationError::InvalidValue("MerkleStore node count too large".into())
        })?;

        let element_size = <(Word, StoreNode) as Deserializable>::min_serialized_size();
        let required_bytes = len.checked_mul(element_size).ok_or_else(|| {
            DeserializationError::InvalidValue("MerkleStore node count too large".into())
        })?;
        source.check_eor(required_bytes)?;

        // Use read_many_iter to avoid eager allocation and respect BudgetedReader limits
        let nodes: Vec<(Word, StoreNode)> =
            source.read_many_iter(len)?.collect::<Result<_, _>>()?;

        Ok(nodes.into_iter().collect())
    }

    /// Minimum serialized size: u64 length prefix (0 entries).
    fn min_serialized_size() -> usize {
        8
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates empty hashes for all the subtrees of a tree with a max depth of 255.
fn empty_hashes() -> impl Iterator<Item = (Word, StoreNode)> {
    let subtrees = EmptySubtreeRoots::empty_hashes(255);
    subtrees
        .iter()
        .rev()
        .copied()
        .zip(subtrees.iter().rev().skip(1).copied())
        .map(|(child, parent)| (parent, StoreNode { left: child, right: child }))
}

/// Consumes an iterator of [InnerNodeInfo] and returns an iterator of `(value, node)` tuples
/// which includes the nodes associate with roots of empty subtrees up to a depth of 255.
fn combine_nodes_with_empty_hashes(
    nodes: impl IntoIterator<Item = InnerNodeInfo>,
) -> impl Iterator<Item = (Word, StoreNode)> {
    nodes
        .into_iter()
        .map(|info| (info.value, StoreNode { left: info.left, right: info.right }))
        .chain(empty_hashes())
}
