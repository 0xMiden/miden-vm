use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use core::fmt;

use super::{
    EMPTY_WORD, InnerNodeInfo, MerkleError, MerklePath, MerkleProof, NodeIndex, Poseidon2, Word,
};
use crate::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, word_to_hex,
};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Index of the root node.
const ROOT_INDEX: NodeIndex = NodeIndex::root();

/// An Word consisting of 4 ZERO elements.
const EMPTY_DIGEST: Word = EMPTY_WORD;

// PARTIAL MERKLE TREE
// ================================================================================================

/// A partial Merkle tree with NodeIndex keys and 4-element [Word] leaf values. Partial Merkle
/// Tree allows to create Merkle Tree by providing Merkle paths of different lengths.
///
/// The root of the tree is recomputed on each new leaf update.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PartialMerkleTree {
    max_depth: u8,
    nodes: BTreeMap<NodeIndex, Word>,
    leaves: BTreeSet<NodeIndex>,
}

impl Default for PartialMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialMerkleTree {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Minimum supported depth.
    pub const MIN_DEPTH: u8 = 1;

    /// Maximum supported depth.
    pub const MAX_DEPTH: u8 = 64;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new empty [PartialMerkleTree].
    pub fn new() -> Self {
        PartialMerkleTree {
            max_depth: 0,
            nodes: BTreeMap::new(),
            leaves: BTreeSet::new(),
        }
    }

    /// Appends the provided paths iterator into the set.
    ///
    /// Analogous to [Self::add_path].
    pub fn with_paths<I>(paths: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = (u64, Word, MerklePath)>,
    {
        // create an empty tree
        let tree = PartialMerkleTree::new();

        paths.into_iter().try_fold(tree, |mut tree, (index, value, path)| {
            tree.add_path(index, value, path)?;
            Ok(tree)
        })
    }

    /// Returns a new [PartialMerkleTree] instantiated with leaves map as specified by the provided
    /// entries.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Any entry has depth 0 or is greater than 64.
    /// - The number of entries exceeds the maximum tree capacity, that is 2^{depth}.
    /// - The provided entries contain an insufficient set of nodes.
    /// - Any entry is an ancestor of another entry (creates hash ambiguity).
    ///
    /// An empty input returns an empty tree.
    pub fn with_leaves<R, I>(entries: R) -> Result<Self, MerkleError>
    where
        R: IntoIterator<IntoIter = I>,
        I: Iterator<Item = (NodeIndex, Word)> + ExactSizeIterator,
    {
        let entries = entries.into_iter();
        if entries.len() == 0 {
            return Ok(PartialMerkleTree::new());
        }

        let mut layers: BTreeMap<u8, Vec<u64>> = BTreeMap::new();
        let mut leaves = BTreeSet::new();
        let mut nodes = BTreeMap::new();

        // add data to the leaves and nodes maps and also fill layers map, where the key is the
        // depth of the node and value is its index.
        for (node_index, hash) in entries {
            leaves.insert(node_index);
            nodes.insert(node_index, hash);
            layers
                .entry(node_index.depth())
                .and_modify(|layer_vec| layer_vec.push(node_index.position()))
                .or_insert(vec![node_index.position()]);
        }

        // make sure the depth of the last layer is 64 or smaller
        if let Some(last_layer) = layers.last_entry() {
            let last_layer_depth = *last_layer.key();
            if last_layer_depth > 64 {
                return Err(MerkleError::TooManyEntries(last_layer_depth));
            }
        }

        // Get maximum depth
        let max_depth = *layers.keys().next_back().unwrap_or(&0);

        // fill layers without nodes with empty vector
        for depth in 0..max_depth {
            layers.entry(depth).or_default();
        }

        let mut layer_iter = layers.into_values().rev();
        let mut parent_layer = layer_iter.next().unwrap();
        let mut current_layer;

        for depth in (1..max_depth + 1).rev() {
            // set current_layer = parent_layer and parent_layer = layer_iter.next()
            current_layer = layer_iter.next().unwrap();
            core::mem::swap(&mut current_layer, &mut parent_layer);

            for index_value in current_layer {
                // get the parent node index
                let parent_node = NodeIndex::new(depth - 1, index_value / 2)?;

                // If parent already exists, check if it's user-provided (invalid) or computed
                // (skip)
                if parent_layer.contains(&parent_node.position()) {
                    // If the parent was provided as a leaf, that's invalid - we can't have both
                    // a node and its descendant in the input set.
                    if leaves.contains(&parent_node) {
                        return Err(MerkleError::EntryIsNotLeaf { node: parent_node });
                    }
                    continue;
                }

                // create current node index
                let index = NodeIndex::new(depth, index_value)?;

                // get hash of the current node
                let node = nodes.get(&index).ok_or(MerkleError::NodeIndexNotFoundInTree(index))?;
                // get hash of the sibling node
                let sibling = nodes
                    .get(&index.sibling())
                    .ok_or(MerkleError::NodeIndexNotFoundInTree(index.sibling()))?;
                // get parent hash
                let parent = Poseidon2::merge(&index.build_node(*node, *sibling));

                // add index value of the calculated node to the parents layer
                parent_layer.push(parent_node.position());
                // add index and hash to the nodes map
                nodes.insert(parent_node, parent);
            }
        }

        Ok(PartialMerkleTree { max_depth, nodes, leaves })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of this Merkle tree.
    pub fn root(&self) -> Word {
        self.nodes.get(&ROOT_INDEX).cloned().unwrap_or(EMPTY_DIGEST)
    }

    /// Returns the depth of this Merkle tree.
    pub fn max_depth(&self) -> u8 {
        self.max_depth
    }

    /// Returns a node at the specified NodeIndex.
    ///
    /// # Errors
    /// Returns an error if the specified NodeIndex is not contained in the nodes map.
    pub fn get_node(&self, index: NodeIndex) -> Result<Word, MerkleError> {
        self.nodes
            .get(&index)
            .ok_or(MerkleError::NodeIndexNotFoundInTree(index))
            .copied()
    }

    /// Returns true if provided index contains in the leaves set, false otherwise.
    pub fn is_leaf(&self, index: NodeIndex) -> bool {
        self.leaves.contains(&index)
    }

    /// Returns a vector of paths from every leaf to the root.
    pub fn to_paths(&self) -> Vec<(NodeIndex, MerkleProof)> {
        let mut paths = Vec::new();
        self.leaves.iter().for_each(|&leaf| {
            paths.push((
                leaf,
                MerkleProof {
                    value: self.get_node(leaf).expect("Failed to get leaf node"),
                    path: self.get_path(leaf).expect("Failed to get path"),
                },
            ));
        });
        paths
    }

    /// Returns a Merkle path from the node at the specified index to the root.
    ///
    /// The node itself is not included in the path.
    ///
    /// # Errors
    /// Returns an error if:
    /// - the specified index has depth set to 0 or the depth is greater than the depth of this
    ///   Merkle tree.
    /// - the specified index is not contained in the nodes map.
    pub fn get_path(&self, mut index: NodeIndex) -> Result<MerklePath, MerkleError> {
        if index.is_root() {
            return Err(MerkleError::DepthTooSmall(index.depth()));
        } else if index.depth() > self.max_depth() {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        }

        if !self.nodes.contains_key(&index) {
            return Err(MerkleError::NodeIndexNotFoundInTree(index));
        }

        let mut path = Vec::new();
        for _ in 0..index.depth() {
            let sibling_index = index.sibling();
            index.move_up();
            let sibling =
                self.nodes.get(&sibling_index).cloned().expect("Sibling node not in the map");
            path.push(sibling);
        }
        Ok(MerklePath::new(path))
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [PartialMerkleTree].
    pub fn leaves(&self) -> impl Iterator<Item = (NodeIndex, Word)> + '_ {
        self.leaves.iter().map(|&leaf| {
            (
                leaf,
                self.get_node(leaf)
                    .unwrap_or_else(|_| panic!("Leaf with {leaf} is not in the nodes map")),
            )
        })
    }

    /// Returns an iterator over the inner nodes of this Merkle tree.
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        let inner_nodes = self.nodes.iter().filter(|(index, _)| !self.leaves.contains(index));
        inner_nodes.map(|(index, digest)| {
            let left_hash =
                self.nodes.get(&index.left_child()).expect("Failed to get left child hash");
            let right_hash =
                self.nodes.get(&index.right_child()).expect("Failed to get right child hash");
            InnerNodeInfo {
                value: *digest,
                left: *left_hash,
                right: *right_hash,
            }
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the nodes of the specified Merkle path to this [PartialMerkleTree]. The `index_value`
    /// and `value` parameters specify the leaf node at which the path starts.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The depth of the specified node_index is greater than 64 or smaller than 1.
    /// - The specified path is not consistent with other paths in the set (i.e., resolves to a
    ///   different root).
    pub fn add_path(
        &mut self,
        index_value: u64,
        value: Word,
        path: MerklePath,
    ) -> Result<(), MerkleError> {
        let index_value = NodeIndex::new(path.len() as u8, index_value)?;

        Self::check_depth(index_value.depth())?;
        self.update_depth(index_value.depth());

        // add provided node and its sibling to the leaves set
        self.leaves.insert(index_value);
        let sibling_node_index = index_value.sibling();
        self.leaves.insert(sibling_node_index);

        // add provided node and its sibling to the nodes map
        self.nodes.insert(index_value, value);
        self.nodes.insert(sibling_node_index, path[0]);

        // traverse to the root, updating the nodes
        let mut index_value = index_value;
        let node = Poseidon2::merge(&index_value.build_node(value, path[0]));
        let root = path.iter().skip(1).copied().fold(node, |node, hash| {
            index_value.move_up();
            // insert calculated node to the nodes map
            self.nodes.insert(index_value, node);

            // if the calculated node was a leaf, remove it from leaves set.
            self.leaves.remove(&index_value);

            let sibling_node = index_value.sibling();

            // Insert node from Merkle path to the nodes map. This sibling node becomes a leaf only
            // if it is a new node (it wasn't in nodes map).
            // Node can be in 3 states: internal node, leaf of the tree and not a tree node at all.
            // - Internal node can only stay in this state -- addition of a new path can't make it
            // a leaf or remove it from the tree.
            // - Leaf node can stay in the same state (remain a leaf) or can become an internal
            // node. In the first case we don't need to do anything, and the second case is handled
            // by the call of `self.leaves.remove(&index_value);`
            // - New node can be a calculated node or a "sibling" node from a Merkle Path:
            // --- Calculated node, obviously, never can be a leaf.
            // --- Sibling node can be only a leaf, because otherwise it is not a new node.
            if self.nodes.insert(sibling_node, hash).is_none() {
                self.leaves.insert(sibling_node);
            }

            Poseidon2::merge(&index_value.build_node(node, hash))
        });

        // if the path set is empty (the root is all ZEROs), set the root to the root of the added
        // path; otherwise, the root of the added path must be identical to the current root
        if self.root() == EMPTY_DIGEST {
            self.nodes.insert(ROOT_INDEX, root);
        } else if self.root() != root {
            return Err(MerkleError::ConflictingRoots {
                expected_root: self.root(),
                actual_root: root,
            });
        }

        Ok(())
    }

    /// Updates value of the leaf at the specified index returning the old leaf value.
    ///
    /// By default the specified index is assumed to belong to the deepest layer. If the considered
    /// node does not belong to the tree, the first node on the way to the root will be changed.
    ///
    /// This also recomputes all hashes between the leaf and the root, updating the root itself.
    ///
    /// # Errors
    /// Returns an error if:
    /// - No entry exists at the specified index.
    /// - The specified index is greater than the maximum number of nodes on the deepest layer.
    pub fn update_leaf(&mut self, index: u64, value: Word) -> Result<Word, MerkleError> {
        let mut node_index = NodeIndex::new(self.max_depth(), index)?;

        // proceed to the leaf
        for _ in 0..node_index.depth() {
            if !self.leaves.contains(&node_index) {
                node_index.move_up();
            }
        }

        // add node value to the nodes Map
        let old_value = self
            .nodes
            .insert(node_index, value)
            .ok_or(MerkleError::NodeIndexNotFoundInTree(node_index))?;

        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return Ok(old_value);
        }

        let mut value = value;
        for _ in 0..node_index.depth() {
            let sibling = self.nodes.get(&node_index.sibling()).expect("sibling should exist");
            value = Poseidon2::merge(&node_index.build_node(value, *sibling));
            node_index.move_up();
            self.nodes.insert(node_index, value);
        }

        Ok(old_value)
    }

    // UTILITY FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Utility to visualize a [PartialMerkleTree] in text.
    pub fn print(&self) -> Result<String, fmt::Error> {
        let indent = "  ";
        let mut s = String::new();
        s.push_str("root: ");
        s.push_str(&word_to_hex(&self.root())?);
        s.push('\n');
        for d in 1..=self.max_depth() {
            let entries = 2u64.pow(d.into());
            for i in 0..entries {
                let index = NodeIndex::new(d, i).expect("The index must always be valid");
                let node = self.get_node(index);
                let node = match node {
                    Err(_) => continue,
                    Ok(node) => node,
                };

                for _ in 0..d {
                    s.push_str(indent);
                }
                s.push_str(&format!("({}, {}): ", index.depth(), index.position()));
                s.push_str(&word_to_hex(&node)?);
                s.push('\n');
            }
        }

        Ok(s)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Updates depth value with the maximum of current and provided depth.
    fn update_depth(&mut self, new_depth: u8) {
        self.max_depth = new_depth.max(self.max_depth);
    }

    /// Returns an error if the depth is 0 or is greater than 64.
    fn check_depth(depth: u8) -> Result<(), MerkleError> {
        // validate the range of the depth.
        if depth < Self::MIN_DEPTH {
            return Err(MerkleError::DepthTooSmall(depth));
        } else if Self::MAX_DEPTH < depth {
            return Err(MerkleError::DepthTooBig(depth as u64));
        }
        Ok(())
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PartialMerkleTree {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // write leaf nodes
        target.write_u64(self.leaves.len() as u64);
        for leaf_index in self.leaves.iter() {
            leaf_index.write_into(target);
            self.get_node(*leaf_index).expect("Leaf hash not found").write_into(target);
        }
    }
}

impl Deserializable for PartialMerkleTree {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let leaves_len_u64 = source.read_u64()?;
        let leaves_len = usize::try_from(leaves_len_u64).map_err(|_| {
            DeserializationError::InvalidValue("PartialMerkleTree leaf count too large".into())
        })?;

        // Use read_many_iter to avoid eager allocation and respect BudgetedReader limits
        let leaf_nodes: Vec<(NodeIndex, Word)> =
            source.read_many_iter(leaves_len)?.collect::<Result<_, _>>()?;

        let pmt = PartialMerkleTree::with_leaves(leaf_nodes).map_err(|_| {
            DeserializationError::InvalidValue("Invalid data for PartialMerkleTree creation".into())
        })?;

        Ok(pmt)
    }

    /// Minimum serialized size: u64 length prefix (0 entries).
    fn min_serialized_size() -> usize {
        8
    }
}
