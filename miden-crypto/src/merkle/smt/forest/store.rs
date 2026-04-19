use alloc::vec::Vec;

use crate::{
    Map, Word,
    hash::poseidon2::Poseidon2,
    merkle::{EmptySubtreeRoots, MerkleError, MerklePath, MerkleProof, NodeIndex, smt::SMT_DEPTH},
};

// SMT FOREST STORE
// ================================================================================================

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
struct ForestInnerNode {
    left: Word,
    right: Word,
    rc: usize,
}

impl ForestInnerNode {
    pub fn hash(&self) -> Word {
        Poseidon2::merge(&[self.left, self.right])
    }
}

/// An in-memory data store for SmtForest data.
///
/// This is an internal memory data store for SmtForest data. Similarly to the `MerkleStore`, it
/// allows all the nodes of multiple trees to live as long as necessary and without duplication,
/// this allows the implementation of space efficient persistent data structures.
///
/// Unlike `MerkleStore`, unused nodes can be easily removed from the store by leveraing
/// reference counting.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub(super) struct SmtStore {
    nodes: Map<Word, ForestInnerNode>,
}

impl SmtStore {
    /// Creates a new, empty in-memory store for SmtForest data.
    pub fn new() -> Self {
        // pre-populate the store with the empty hashes
        let nodes = empty_hashes().collect();
        Self { nodes }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the node at `index` rooted on the tree `root`.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeIndexNotFoundInStore` if a node needed to traverse from `root` to `index` is not
    ///   present in the store.
    pub fn get_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleError> {
        let mut hash = root;

        // corner case: check the root is in the store when called with index `NodeIndex::root()`
        self.nodes.get(&hash).ok_or(MerkleError::RootNotInStore(hash))?;

        // traverse from root to index
        for i in (0..index.depth()).rev() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeIndexNotFoundInStore(hash, index))?;

            hash = if index.is_nth_bit_odd(i) { node.right } else { node.left }
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
    /// - `NodeIndexNotFoundInStore` if a node needed to traverse from `root` to `index` is not
    ///   present in the store.
    pub fn get_path(&self, root: Word, index: NodeIndex) -> Result<MerkleProof, MerkleError> {
        let IndexedPath { value, path } = self.get_indexed_path(root, index)?;
        let path_iter = path.into_iter().rev().map(|(_, value)| value);

        Ok(MerkleProof::new(value, MerklePath::from_iter(path_iter)))
    }

    /// Returns the node at the specified `index` and its opening to the `root`.
    ///
    /// The path starts below the root and contains all nodes in the opening
    /// all the way to the sibling of the target leaf.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeIndexNotFoundInStore` if a node needed to traverse from `root` to `index` is not
    ///   present in the store.
    fn get_indexed_path(&self, root: Word, index: NodeIndex) -> Result<IndexedPath, MerkleError> {
        let mut hash = root;
        let mut path = Vec::with_capacity(index.depth().into());

        // corner case: check the root is in the store when called with index `NodeIndex::root()`
        self.nodes.get(&hash).ok_or(MerkleError::RootNotInStore(hash))?;

        // Build sibling node index at each level as we traverse from root to leaf
        let mut current_index = NodeIndex::root();
        for i in (0..index.depth()).rev() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeIndexNotFoundInStore(hash, index))?;

            hash = if index.is_nth_bit_odd(i) {
                path.push((current_index.left_child(), node.left));
                current_index = current_index.right_child();
                node.right
            } else {
                path.push((current_index.right_child(), node.right));
                current_index = current_index.left_child();
                node.left
            }
        }

        Ok(IndexedPath { value: hash, path })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Sets multiple leaf values at once with a single root transition.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeIndexNotFoundInStore` if a node needed to traverse from `root` to `index` is not
    ///   present in the store.
    pub fn set_leaves(
        &mut self,
        root: Word,
        leaves: impl IntoIterator<Item = (NodeIndex, Word)>,
    ) -> Result<Word, MerkleError> {
        self.nodes.get(&root).ok_or(MerkleError::RootNotInStore(root))?;

        // Collect opening nodes and updated leaves
        let mut nodes_by_index = Map::<NodeIndex, Word>::new();
        let mut leaves_by_index = Map::<NodeIndex, Word>::new();
        for (index, leaf_hash) in leaves {
            // Record all sibling nodes along the path from root to this index
            let indexed_path = self.get_indexed_path(root, index)?;

            // See if we are actually updating the leaf value. If not, we can skip processing it.
            if indexed_path.value == leaf_hash {
                continue;
            }
            nodes_by_index.extend(indexed_path.path);

            // Record the updated leaf value at this index
            leaves_by_index.insert(index, leaf_hash);
        }

        if leaves_by_index.is_empty() {
            // No leaves were updated, return the original root
            return Ok(root);
        }

        #[allow(unused_mut)]
        let mut sorted_leaf_indices = leaves_by_index.keys().cloned().collect::<Vec<_>>();

        #[cfg(feature = "std")]
        // Sort leaves by NodeIndex to easily detect when leaves share a parent (only neighboring
        // leaves can share a parent). std::collections::HashMap doesn't maintain key ordering, so
        // we need to sort the indices.
        sorted_leaf_indices.sort();

        // Ensure new leaf values override current opening values.
        nodes_by_index.extend(leaves_by_index);

        // Keep track of affected ancestors to avoid recomputing nodes multiple times
        let mut ancestors: Vec<NodeIndex> = Vec::new();
        // Start with a guard value, all ancestors have depth < SMT_DEPTH
        let mut last_ancestor = NodeIndex::new_unchecked(SMT_DEPTH, 0);

        for leaf_index in sorted_leaf_indices {
            let parent = leaf_index.parent();

            // Check if we already processed the sibling of this leaf. If so, the parent is already
            // added to the ancestors list. This works because leaves are sorted by index.
            if parent != last_ancestor {
                last_ancestor = parent;
                ancestors.push(last_ancestor);
            }
        }

        // Gather all ancestors up to the root (deduplicated)
        // `ancestors` behaves as both a BFS queue (starting at all updated leaves' parents) and
        // provides a way of checking if we are not processing the same ancestor multiple times.
        let mut index = 0;
        while index < ancestors.len() {
            let node = ancestors[index];
            if node.is_root() {
                break;
            }
            // if we haven't processed node's sibling yet, it will be a new parent
            let parent = node.parent();
            if parent != last_ancestor {
                last_ancestor = parent;
                ancestors.push(last_ancestor);
            }
            index += 1;
        }

        // Stash all new nodes until we know there are no errors
        let mut new_nodes: Map<Word, ForestInnerNode> = Map::new();

        for index in ancestors {
            let left_index = index.left_child();
            let right_index = index.right_child();

            let left_value = *nodes_by_index
                .get(&left_index)
                .ok_or(MerkleError::NodeIndexNotFoundInTree(left_index))?;
            let right_value = *nodes_by_index
                .get(&right_index)
                .ok_or(MerkleError::NodeIndexNotFoundInTree(right_index))?;

            let node = ForestInnerNode {
                left: left_value,
                right: right_value,
                rc: 0,
            };
            let new_key = node.hash();
            new_nodes.insert(new_key, node);
            nodes_by_index.insert(index, new_key);
        }

        let new_root = nodes_by_index
            .get(&NodeIndex::root())
            .cloned()
            .ok_or(MerkleError::NodeIndexNotFoundInStore(root, NodeIndex::root()))?;

        // The update was computed successfully, update ref counts and insert into the store
        fn dfs(
            node: Word,
            store: &mut Map<Word, ForestInnerNode>,
            new_nodes: &mut Map<Word, ForestInnerNode>,
        ) {
            if node == Word::empty() {
                return;
            }
            if let Some(node) = store.get_mut(&node) {
                // This node already exists in the store, increase its reference count.
                // Stops the dfs descent here to leave children ref counts unchanged.
                node.rc += 1;
            } else if let Some(mut smt_node) = new_nodes.remove(&node) {
                // This is a non-leaf node, insert it into the store and process its children.
                smt_node.rc = 1;
                store.insert(node, smt_node);
                dfs(smt_node.left, store, new_nodes);
                dfs(smt_node.right, store, new_nodes);
            }
        }
        dfs(new_root, &mut self.nodes, &mut new_nodes);

        Ok(new_root)
    }

    /// Decreases the reference count of the specified node and releases memory if the count
    /// reached zero.
    ///
    /// Returns the terminal nodes (leaves) that were removed.
    fn remove_node(&mut self, node: Word) -> Vec<Word> {
        if node == Word::empty() {
            return vec![];
        }
        let Some(smt_node) = self.nodes.get_mut(&node) else {
            return vec![node];
        };
        smt_node.rc -= 1;
        if smt_node.rc > 0 {
            return vec![];
        }

        let left = smt_node.left;
        let right = smt_node.right;
        self.nodes.remove(&node);

        let mut result = Vec::new();
        result.extend(self.remove_node(left));
        result.extend(self.remove_node(right));
        result
    }

    /// Removes the specified roots from the store and releases memory used by now
    /// unreachable nodes.
    ///
    /// Returns the terminal nodes (leaves) that were removed.
    pub fn remove_roots(&mut self, roots: impl IntoIterator<Item = Word>) -> Vec<Word> {
        let mut removed_leaves = Vec::new();
        for root in roots {
            removed_leaves.extend(self.remove_node(root));
        }
        removed_leaves
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates empty hashes for all the subtrees of a tree with a max depth of [`SMT_DEPTH`].
fn empty_hashes() -> impl Iterator<Item = (Word, ForestInnerNode)> {
    let subtrees = EmptySubtreeRoots::empty_hashes(SMT_DEPTH);
    subtrees
        .iter()
        .rev()
        .copied()
        .zip(subtrees.iter().rev().skip(1).copied())
        .map(|(child, parent)| (parent, ForestInnerNode { left: child, right: child, rc: 1 }))
}

/// A Merkle opening that starts below the root and ends at the sibling of the target leaf.
/// Indexed by the NodeIndex at each level to efficiently query all the hashes needed for a batch
/// update.
struct IndexedPath {
    value: Word,
    path: Vec<(NodeIndex, Word)>,
}
