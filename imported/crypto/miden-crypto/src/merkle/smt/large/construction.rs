use alloc::vec::Vec;
use core::mem;

use p3_maybe_rayon::prelude::*;

use super::{
    CONSTRUCTION_SUBTREE_BATCH_SIZE, IN_MEMORY_DEPTH, LargeSmt, LargeSmtError, NUM_IN_MEMORY_NODES,
    ROOT_MEMORY_INDEX, SMT_DEPTH, SmtStorage, SmtStorageReader, StorageError, Subtree,
};
use crate::{
    EMPTY_WORD, Word,
    hash::poseidon2::Poseidon2,
    merkle::smt::{
        EmptySubtreeRoots, InnerNode, Map, MerkleError, NodeIndex, Smt, SmtLeaf, SparseMerkleTree,
        SparseMerkleTreeReader,
        full::concurrent::{
            PairComputations, SUBTREE_DEPTH, SubtreeLeaf, SubtreeLeavesIter, build_subtree,
        },
        large::{LargeSmtResult, to_memory_index},
    },
};

// CONSTRUCTION
// ================================================================================================

impl<S: SmtStorageReader> LargeSmt<S> {
    /// Creates a new empty [LargeSmt] backed by the provided storage.
    ///
    /// This method is intended for creating a fresh tree with empty storage. If the storage
    /// already contains data, use [`Self::load_with_root()`] or [`Self::load()`]
    /// instead.
    ///
    /// # Errors
    /// - Returns [`LargeSmtError::StorageNotEmpty`] if the storage already contains data.
    /// - Returns a storage error if checking the storage state fails.
    ///
    /// # Example
    /// ```
    /// # use miden_crypto::merkle::smt::{LargeSmt, MemoryStorage};
    /// let storage = MemoryStorage::new();
    /// let smt = LargeSmt::new(storage).expect("Failed to create SMT");
    /// ```
    pub fn new(storage: S) -> LargeSmtResult<Self> {
        if storage.has_leaves()? {
            return Err(LargeSmtError::StorageNotEmpty);
        }
        Self::initialize_from_storage(storage)
    }

    /// Loads an existing [LargeSmt] from storage without validating the root.
    ///
    /// If the storage is empty, the SMT is initialized with the root of an empty tree.
    /// Otherwise, the in-memory top of the tree is reconstructed from the cached in-memory-depth
    /// subtree hashes stored in the backend.
    ///
    /// **Note:** This method does not validate the reconstructed root. Use this only when
    /// you explicitly want to skip validation. For normal reloading, prefer
    /// [`Self::load_with_root()`].
    ///
    /// # Errors
    /// Returns an error if fetching data from storage fails.
    ///
    /// # Example
    /// ```no_run
    /// # #[cfg(feature = "rocksdb")]
    /// # {
    /// use miden_crypto::merkle::smt::{LargeSmt, RocksDbConfig, RocksDbStorage};
    /// let storage = RocksDbStorage::open(RocksDbConfig::new("/path/to/db")).unwrap();
    /// let smt = LargeSmt::load(storage).expect("Failed to load SMT");
    /// # }
    /// ```
    pub fn load(storage: S) -> LargeSmtResult<Self> {
        Self::initialize_from_storage(storage)
    }

    /// Loads an existing [LargeSmt] from storage and validates it against the expected root.
    ///
    /// This method reconstructs the in-memory top of the tree from the cached in-memory-depth
    /// subtree hashes, computes the root, and validates it against `expected_root`.
    ///
    /// Use this method when reloading a tree to ensure the storage contains the expected
    /// data and hasn't been corrupted or tampered with.
    ///
    /// # Errors
    /// - Returns [`LargeSmtError::RootMismatch`] if the reconstructed root does not match
    ///   `expected_root`.
    /// - Returns a storage error if fetching data from storage fails.
    ///
    /// # Example
    /// ```no_run
    /// # #[cfg(feature = "rocksdb")]
    /// # {
    /// use miden_crypto::{
    ///     Word,
    ///     merkle::smt::{LargeSmt, RocksDbConfig, RocksDbStorage},
    /// };
    /// # let expected_root: Word = miden_crypto::EMPTY_WORD;
    /// let storage = RocksDbStorage::open(RocksDbConfig::new("/path/to/db")).unwrap();
    /// let smt = LargeSmt::load_with_root(storage, expected_root)
    ///     .expect("Failed to load SMT with expected root");
    /// # }
    /// ```
    pub fn load_with_root(storage: S, expected_root: Word) -> LargeSmtResult<Self> {
        let smt = Self::load(storage)?;

        let actual_root = smt.root();
        if actual_root != expected_root {
            return Err(LargeSmtError::RootMismatch {
                expected: expected_root,
                actual: actual_root,
            });
        }

        Ok(smt)
    }

    /// Internal method that initializes the in-memory tree from storage.
    ///
    /// For empty storage, returns an empty tree. For non-empty storage,
    /// rebuilds the in-memory top from cached in-memory-depth hashes.
    fn initialize_from_storage(storage: S) -> LargeSmtResult<Self> {
        // Initialize in-memory nodes
        let mut in_memory_nodes: Vec<Word> = vec![EMPTY_WORD; NUM_IN_MEMORY_NODES];

        // Root
        in_memory_nodes[ROOT_MEMORY_INDEX] = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
        // Inner nodes
        for depth in 0..IN_MEMORY_DEPTH {
            let child_empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, depth + 1);
            let start = 2 * (1 << depth);
            let end = 2 * (1 << (depth + 1));
            in_memory_nodes[start..end].fill(child_empty_hash);
        }

        let is_empty = !storage.has_leaves()?;
        // If the tree is empty, return it
        if is_empty {
            return Ok(Self {
                storage,
                in_memory_nodes: in_memory_nodes.into(),
                leaf_count: 0,
                entry_count: 0,
            });
        }

        // Initialize counts from storage
        let leaf_count = storage.leaf_count()?;
        let entry_count = storage.entry_count()?;

        // Get the tops of subtrees from storage; these become the leaves of the in-memory tree
        let in_memory_tree_leaves = storage.get_top_subtree_roots()?;

        // Convert in-memory top of tree leaves to SubtreeLeaf
        let mut leaf_subtrees: Vec<SubtreeLeaf> = in_memory_tree_leaves
            .into_iter()
            .map(|(index, hash)| SubtreeLeaf { col: index, hash })
            .collect();
        leaf_subtrees.sort_by_key(|leaf| leaf.col);
        let mut subtree_leaves: Vec<Vec<SubtreeLeaf>> =
            SubtreeLeavesIter::from_leaves(&mut leaf_subtrees).collect();

        // build in-memory top of the tree
        for current_depth in (SUBTREE_DEPTH..=IN_MEMORY_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            let (nodes, mut subtree_roots): (Vec<Map<_, _>>, Vec<SubtreeLeaf>) = subtree_leaves
                .into_par_iter()
                .map(|subtree| {
                    debug_assert!(subtree.is_sorted());
                    debug_assert!(!subtree.is_empty());
                    let (nodes, subtree_root) = build_subtree(subtree, SMT_DEPTH, current_depth);
                    (nodes, subtree_root)
                })
                .unzip();
            subtree_leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
            debug_assert!(!subtree_leaves.is_empty());

            for subtree_nodes in nodes {
                for (index, node) in subtree_nodes {
                    let memory_index = to_memory_index(&index);
                    // Store left and right children in flat layout
                    in_memory_nodes[memory_index * 2] = node.left;
                    in_memory_nodes[memory_index * 2 + 1] = node.right;
                }
            }
        }

        // Compute the root from children at indices 2 and 3
        let calculated_root = Poseidon2::merge(&[in_memory_nodes[2], in_memory_nodes[3]]);

        // Set the root node
        in_memory_nodes[ROOT_MEMORY_INDEX] = calculated_root;

        Ok(Self {
            storage,
            in_memory_nodes: in_memory_nodes.into(),
            leaf_count,
            entry_count,
        })
    }
}

impl<S: SmtStorage> LargeSmt<S> {
    /// Returns a new [Smt] instantiated with leaves set as specified by the provided entries.
    ///
    /// If the `concurrent` feature is enabled, this function uses a parallel implementation to
    /// process the entries efficiently, otherwise it defaults to the sequential implementation.
    ///
    /// All leaves omitted from the entries list are set to [Self::EMPTY_VALUE].
    ///
    /// # Errors
    /// Returns an error if the provided entries contain multiple values for the same key.
    pub fn with_entries(
        storage: S,
        entries: impl IntoIterator<Item = (Word, Word)>,
    ) -> LargeSmtResult<Self> {
        let entries: Vec<(Word, Word)> = entries.into_iter().collect();

        if storage.has_leaves()? {
            return Err(StorageError::Unsupported(
                "Cannot create SMT with non-empty storage".into(),
            )
            .into());
        }
        let mut tree = LargeSmt::new(storage)?;
        if entries.is_empty() {
            return Ok(tree);
        }
        tree.build_subtrees(entries)?;
        Ok(tree)
    }

    fn build_subtrees(&mut self, mut entries: Vec<(Word, Word)>) -> Result<(), MerkleError> {
        entries.par_sort_unstable_by_key(|item| {
            let index = Self::key_to_leaf_index(&item.0);
            index.position()
        });
        self.build_subtrees_from_sorted_entries(entries)?;
        Ok(())
    }

    fn build_subtrees_from_sorted_entries(
        &mut self,
        entries: Vec<(Word, Word)>,
    ) -> Result<(), MerkleError> {
        let PairComputations {
            leaves: mut leaf_subtrees,
            nodes: initial_leaves,
        } = Smt::sorted_pairs_to_leaves(entries)?;

        if initial_leaves.is_empty() {
            return Ok(());
        }

        // Update cached counts before storing leaves
        self.leaf_count = initial_leaves.len();
        self.entry_count = initial_leaves.values().map(SmtLeaf::num_entries).sum();

        // Store the initial leaves
        self.storage.set_leaves(initial_leaves).expect("Failed to store initial leaves");

        // build deep (disk-backed) subtrees
        leaf_subtrees = std::thread::scope(|scope| {
            let (sender, receiver) = flume::bounded(CONSTRUCTION_SUBTREE_BATCH_SIZE);
            let storage = &mut self.storage;

            scope.spawn(move || -> Result<(), MerkleError> {
                let mut subtrees: Vec<Subtree> =
                    Vec::with_capacity(CONSTRUCTION_SUBTREE_BATCH_SIZE);
                for subtree in receiver.iter() {
                    subtrees.push(subtree);
                    if subtrees.len() == CONSTRUCTION_SUBTREE_BATCH_SIZE {
                        let subtrees_clone = mem::take(&mut subtrees);
                        storage
                            .set_subtrees(subtrees_clone)
                            .expect("Writer thread failed to set subtrees");
                    }
                }
                storage.set_subtrees(subtrees).expect("Writer thread failed to set subtrees");
                Ok(())
            });

            for bottom_depth in (IN_MEMORY_DEPTH + SUBTREE_DEPTH..=SMT_DEPTH)
                .step_by(SUBTREE_DEPTH as usize)
                .rev()
            {
                let mut subtree_roots: Vec<SubtreeLeaf> = leaf_subtrees
                    .into_par_iter()
                    .map(|subtree_leaves| {
                        debug_assert!(subtree_leaves.is_sorted());
                        debug_assert!(!subtree_leaves.is_empty());
                        let (nodes, subtree_root) =
                            build_subtree(subtree_leaves, SMT_DEPTH, bottom_depth);

                        let subtree_root_index =
                            NodeIndex::new(bottom_depth - SUBTREE_DEPTH, subtree_root.col).unwrap();
                        let mut subtree = Subtree::new(subtree_root_index);
                        for (index, node) in nodes {
                            subtree.insert_inner_node(index, node);
                        }
                        sender.send(subtree).expect("Flume channel disconnected unexpectedly");
                        subtree_root
                    })
                    .collect();
                leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
                debug_assert!(!leaf_subtrees.is_empty());
            }

            drop(sender);
            leaf_subtrees
        });

        // build top of the tree (in-memory only, normal insert)
        for bottom_depth in (SUBTREE_DEPTH..=IN_MEMORY_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            let (nodes, mut subtree_roots): (Vec<Map<_, _>>, Vec<SubtreeLeaf>) = leaf_subtrees
                .into_par_iter()
                .map(|subtree| {
                    debug_assert!(subtree.is_sorted());
                    debug_assert!(!subtree.is_empty());
                    let (nodes, subtree_root) = build_subtree(subtree, SMT_DEPTH, bottom_depth);
                    (nodes, subtree_root)
                })
                .unzip();
            leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
            debug_assert!(!leaf_subtrees.is_empty());

            for subtree_nodes in nodes {
                self.insert_inner_nodes_batch(subtree_nodes.into_iter());
            }
        }
        self.set_root(self.get_inner_node(NodeIndex::root()).hash());
        Ok(())
    }

    // Inserts batch of upper inner nodes
    fn insert_inner_nodes_batch(
        &mut self,
        nodes: impl IntoIterator<Item = (NodeIndex, InnerNode)>,
    ) {
        for (index, node) in nodes {
            if index.depth() < IN_MEMORY_DEPTH {
                let memory_index = to_memory_index(&index);
                let in_memory_nodes = self.in_memory_nodes_mut();
                // Store in flat layout: left at 2*i, right at 2*i+1
                in_memory_nodes[memory_index * 2] = node.left;
                in_memory_nodes[memory_index * 2 + 1] = node.right;
            }
        }
    }
}
