use alloc::vec::Vec;

use super::{
    IN_MEMORY_DEPTH, LargeSmt, NUM_SUBTREE_LEVELS, ROOT_MEMORY_INDEX, SMT_DEPTH, SmtStorage,
    StorageError, Subtree,
};
use crate::{
    EMPTY_WORD, Word,
    merkle::smt::{
        EmptySubtreeRoots, InnerNode, LargeSmtError, LeafIndex, Map, MerkleError, NodeIndex,
        SmtLeaf, SmtLeafError, SmtProof, SparseMerklePath, SparseMerkleTree,
        large::{is_empty_parent, to_memory_index},
    },
};

impl<S: SmtStorage> SparseMerkleTree<SMT_DEPTH> for LargeSmt<S> {
    type Key = Word;
    type Value = Word;
    type Leaf = SmtLeaf;
    type Opening = SmtProof;

    const EMPTY_VALUE: Self::Value = EMPTY_WORD;
    const EMPTY_ROOT: Word = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    fn from_raw_parts(
        _inner_nodes: super::InnerNodes,
        _leaves: super::Leaves,
        _root: Word,
    ) -> Result<Self, MerkleError> {
        // This method is not supported
        panic!("LargeSmt::from_raw_parts is not supported");
    }

    fn root(&self) -> Word {
        self.in_memory_nodes[ROOT_MEMORY_INDEX]
    }

    fn set_root(&mut self, root: Word) {
        self.in_memory_nodes[ROOT_MEMORY_INDEX] = root;
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        if index.depth() < IN_MEMORY_DEPTH {
            let memory_index = to_memory_index(&index);
            // Reconstruct InnerNode from flat layout: left at 2*i, right at 2*i+1
            return InnerNode {
                left: self.in_memory_nodes[memory_index * 2],
                right: self.in_memory_nodes[memory_index * 2 + 1],
            };
        }

        self.storage
            .get_inner_node(index)
            .expect("Failed to get inner node")
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        if index.depth() < IN_MEMORY_DEPTH {
            let i = to_memory_index(&index);
            // Get the old node before replacing
            let old_left = self.in_memory_nodes[i * 2];
            let old_right = self.in_memory_nodes[i * 2 + 1];

            // Store new node in flat layout
            self.in_memory_nodes[i * 2] = inner_node.left;
            self.in_memory_nodes[i * 2 + 1] = inner_node.right;

            // Check if the old node was empty
            if is_empty_parent(old_left, old_right, index.depth() + 1) {
                return None;
            }

            return Some(InnerNode { left: old_left, right: old_right });
        }
        self.storage
            .set_inner_node(index, inner_node)
            .expect("Failed to store inner node")
    }

    fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        if index.depth() < IN_MEMORY_DEPTH {
            let memory_index = to_memory_index(&index);
            // Get the old node before replacing with empty hashes
            let old_left = self.in_memory_nodes[memory_index * 2];
            let old_right = self.in_memory_nodes[memory_index * 2 + 1];

            // Replace with empty hashes
            let child_depth = index.depth() + 1;
            let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth);
            self.in_memory_nodes[memory_index * 2] = empty_hash;
            self.in_memory_nodes[memory_index * 2 + 1] = empty_hash;

            // Return the old node if it wasn't already empty
            if is_empty_parent(old_left, old_right, child_depth) {
                return None;
            }

            return Some(InnerNode { left: old_left, right: old_right });
        }
        self.storage.remove_inner_node(index).expect("Failed to remove inner node")
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) -> Result<Self::Value, MerkleError> {
        let old_value = self.get_value(&key);
        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return Ok(value);
        }

        let mutations = self.compute_mutations([(key, value)])?;
        self.apply_mutations(mutations).expect("Failed to apply mutations in insert");

        Ok(old_value)
    }

    fn insert_value(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Result<Option<Self::Value>, MerkleError> {
        // inserting an `EMPTY_VALUE` is equivalent to removing any value associated with `key`
        let index = Self::key_to_leaf_index(&key).position();
        if value != Self::EMPTY_VALUE {
            match self.storage.insert_value(index, key, value) {
                Ok(prev) => Ok(prev),
                Err(StorageError::Leaf(SmtLeafError::TooManyLeafEntries { actual })) => {
                    Err(MerkleError::TooManyLeafEntries { actual })
                },
                Err(_) => {
                    panic!("Storage error during insert_value");
                },
            }
        } else {
            Ok(self.storage.remove_value(index, key).map_err(LargeSmtError::from)?)
        }
    }

    fn get_value(&self, key: &Self::Key) -> Self::Value {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key);
        match self.storage.get_leaf(leaf_pos.position()) {
            Ok(Some(leaf)) => leaf.get_value(key).unwrap_or_default(),
            Ok(None) => EMPTY_WORD,
            Err(_) => {
                panic!("Storage error during get_leaf in get_value");
            },
        }
    }

    fn get_leaf(&self, key: &Word) -> Self::Leaf {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).position();
        match self.storage.get_leaf(leaf_pos) {
            Ok(Some(leaf)) => leaf,
            Ok(None) => SmtLeaf::new_empty((*key).into()),
            Err(_) => {
                panic!("Storage error during get_leaf in get_leaf");
            },
        }
    }

    fn hash_leaf(leaf: &Self::Leaf) -> Word {
        leaf.hash()
    }

    fn construct_prospective_leaf(
        &self,
        mut existing_leaf: SmtLeaf,
        key: &Word,
        value: &Word,
    ) -> Result<SmtLeaf, SmtLeafError> {
        debug_assert_eq!(existing_leaf.index(), Self::key_to_leaf_index(key));

        match existing_leaf {
            SmtLeaf::Empty(_) => Ok(SmtLeaf::new_single(*key, *value)),
            _ => {
                if *value != EMPTY_WORD {
                    existing_leaf.insert(*key, *value)?;
                } else {
                    existing_leaf.remove(*key);
                }

                Ok(existing_leaf)
            },
        }
    }

    fn open(&self, key: &Self::Key) -> Self::Opening {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key);

        let mut idx: NodeIndex = leaf_pos.into();

        let subtree_roots: Vec<NodeIndex> = (0..NUM_SUBTREE_LEVELS)
            .scan(idx.parent(), |cursor, _| {
                let subtree_root = Subtree::find_subtree_root(*cursor);
                *cursor = subtree_root.parent();
                Some(subtree_root)
            })
            .collect();

        // Fetch leaf and all subtrees in a single batched call. This method can be overridden to
        // be more efficient by the storage, but defaults to a simple sequential set of calls.
        let (leaf_opt, subtree_opts) = self
            .storage
            .get_leaf_and_subtrees(leaf_pos.position(), &subtree_roots)
            .expect("Fetching leaf and subtrees succeeds");

        let leaf = leaf_opt.unwrap_or_else(|| SmtLeaf::new_empty((*key).into()));

        let mut cache = Map::<NodeIndex, Subtree>::new();
        for (&root, subtree_opt) in subtree_roots.iter().zip(subtree_opts) {
            let subtree = subtree_opt.unwrap_or_else(|| Subtree::new(root));
            cache.insert(root, subtree);
        }
        let mut path = Vec::with_capacity(idx.depth() as usize);
        while idx.depth() > 0 {
            let is_right = idx.is_position_odd();
            idx = idx.parent();

            let sibling_hash = if idx.depth() < IN_MEMORY_DEPTH {
                // top levels in memory
                let InnerNode { left, right } = self.get_inner_node(idx);
                if is_right { left } else { right }
            } else {
                // deep levels come from our 5 preloaded subtrees
                let root = Subtree::find_subtree_root(idx);
                let subtree = &cache[&root];
                let InnerNode { left, right } = subtree
                    .get_inner_node(idx)
                    .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, idx.depth()));
                if is_right { left } else { right }
            };

            path.push(sibling_hash);
        }

        let merkle_path =
            SparseMerklePath::from_sized_iter(path).expect("failed to convert to SparseMerklePath");
        Self::path_and_leaf_to_opening(merkle_path, leaf)
    }

    fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_canonical_u64())
    }

    fn path_and_leaf_to_opening(path: SparseMerklePath, leaf: SmtLeaf) -> SmtProof {
        SmtProof::new_unchecked(path, leaf)
    }
}
