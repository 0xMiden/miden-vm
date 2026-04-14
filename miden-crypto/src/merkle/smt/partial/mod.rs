use super::{EmptySubtreeRoots, LeafIndex, SMT_DEPTH};
use crate::{
    EMPTY_WORD, Word,
    merkle::{
        InnerNodeInfo, MerkleError, NodeIndex, SparseMerklePath,
        smt::{InnerNode, InnerNodes, Leaves, SmtLeaf, SmtLeafError, SmtProof},
    },
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

#[cfg(test)]
mod tests;

/// A partial version of an [`super::Smt`].
///
/// This type can track a subset of the key-value pairs of a full [`super::Smt`] and allows for
/// updating those pairs to compute the new root of the tree, as if the updates had been done on the
/// full tree. This is useful so that not all leaves have to be present and loaded into memory to
/// compute an update.
///
/// A key is considered "tracked" if either:
/// 1. Its merkle path was explicitly added to the tree (via [`PartialSmt::add_path`] or
///    [`PartialSmt::add_proof`]), or
/// 2. The path from the leaf to the root goes through empty subtrees that are consistent with the
///    stored inner nodes (provably empty with zero hash computations).
///
/// The second condition allows updating keys in empty subtrees without explicitly adding their
/// merkle paths. This is verified by walking up from the leaf and checking that any stored
/// inner node has an empty subtree root as the child on our path.
///
/// An important caveat is that only tracked keys can be updated. Attempting to update an
/// untracked key will result in an error. See [`PartialSmt::insert`] for more details.
///
/// Once a partial SMT has been constructed, its root is set in stone. All subsequently added proofs
/// or merkle paths must match that root, otherwise an error is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PartialSmt {
    root: Word,
    num_entries: usize,
    leaves: Leaves<SmtLeaf>,
    inner_nodes: InnerNodes,
}

impl PartialSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The default value used to compute the hash of empty leaves.
    pub const EMPTY_VALUE: Word = EMPTY_WORD;

    /// The root of an empty tree.
    pub const EMPTY_ROOT: Word = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a [`PartialSmt`] from a root.
    ///
    /// All subsequently added proofs or paths must have the same root.
    pub fn new(root: Word) -> Self {
        Self {
            root,
            num_entries: 0,
            leaves: Leaves::<SmtLeaf>::default(),
            inner_nodes: InnerNodes::default(),
        }
    }

    /// Instantiates a new [`PartialSmt`] by calling [`PartialSmt::add_proof`] for all [`SmtProof`]s
    /// in the provided iterator.
    ///
    /// If the provided iterator is empty, an empty [`PartialSmt`] is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the roots of the provided proofs are not the same.
    pub fn from_proofs<I>(proofs: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = SmtProof>,
    {
        let mut proofs = proofs.into_iter();

        let Some(first_proof) = proofs.next() else {
            return Ok(Self::default());
        };

        // Add the first path to an empty partial SMT without checking that the existing root
        // matches the new one. This sets the expected root to the root of the first proof and all
        // subsequently added proofs must match it.
        let mut partial_smt = Self::default();
        let (path, leaf) = first_proof.into_parts();
        let path_root = partial_smt.add_path_unchecked(leaf, path);
        partial_smt.root = path_root;

        for proof in proofs {
            partial_smt.add_proof(proof)?;
        }

        Ok(partial_smt)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the tree.
    pub fn root(&self) -> Word {
        self.root
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn open(&self, key: &Word) -> Result<SmtProof, MerkleError> {
        let leaf = self.get_leaf(key)?;
        let merkle_path = self.get_path(key);
        Ok(SmtProof::new_unchecked(merkle_path, leaf))
    }

    /// Returns the leaf to which `key` maps.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get_leaf(&self, key: &Word) -> Result<SmtLeaf, MerkleError> {
        self.get_tracked_leaf(key).ok_or(MerkleError::UntrackedKey(*key))
    }

    /// Returns the value associated with `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get_value(&self, key: &Word) -> Result<Word, MerkleError> {
        self.get_tracked_leaf(key)
            .map(|leaf| leaf.get_value(key).unwrap_or_default())
            .ok_or(MerkleError::UntrackedKey(*key))
    }

    /// Returns an iterator over the inner nodes of the [`PartialSmt`].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.inner_nodes.values().map(|e| InnerNodeInfo {
            value: e.hash(),
            left: e.left,
            right: e.right,
        })
    }

    /// Returns an iterator over the [`InnerNode`] and the respective [`NodeIndex`] of the
    /// [`PartialSmt`].
    pub fn inner_node_indices(&self) -> impl Iterator<Item = (NodeIndex, InnerNode)> + '_ {
        self.inner_nodes.iter().map(|(idx, inner)| (*idx, inner.clone()))
    }

    /// Returns an iterator over the explicitly stored leaves of the [`PartialSmt`] in arbitrary
    /// order.
    ///
    /// Note: This only returns leaves that were explicitly added via [`Self::add_path`] or
    /// [`Self::add_proof`], or created through [`Self::insert`]. It does not include implicitly
    /// trackable leaves in empty subtrees.
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.leaves
            .iter()
            .map(|(leaf_index, leaf)| (LeafIndex::new_max_depth(*leaf_index), leaf))
    }

    /// Returns an iterator over the tracked, non-empty key-value pairs of the [`PartialSmt`] in
    /// arbitrary order.
    pub fn entries(&self) -> impl Iterator<Item = &(Word, Word)> {
        self.leaves().flat_map(|(_, leaf)| leaf.entries())
    }

    /// Returns the number of non-empty leaves in this tree.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Returns the number of tracked, non-empty key-value pairs in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_entries(&self) -> usize {
        self.num_entries
    }

    /// Returns a boolean value indicating whether the [`PartialSmt`] tracks any leaves.
    ///
    /// Note that if a partial SMT does not track leaves, its root is not necessarily the empty SMT
    /// root, since it could have been constructed from a different root but without tracking any
    /// leaves.
    pub fn tracks_leaves(&self) -> bool {
        !self.leaves.is_empty()
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Self::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked (see the type documentation for the definition of "tracked"). If an
    ///   error is returned the tree is in the same state as before.
    /// - inserting the key-value pair would exceed [`super::MAX_LEAF_ENTRIES`] (1024 entries) in
    ///   the leaf.
    pub fn insert(&mut self, key: Word, value: Word) -> Result<Word, MerkleError> {
        let current_leaf = self.get_tracked_leaf(&key).ok_or(MerkleError::UntrackedKey(key))?;
        let leaf_index = current_leaf.index();
        let previous_value = current_leaf.get_value(&key).unwrap_or(EMPTY_WORD);
        let prev_entries = current_leaf.num_entries();

        let leaf = self
            .leaves
            .entry(leaf_index.position())
            .or_insert_with(|| SmtLeaf::new_empty(leaf_index));

        if value != EMPTY_WORD {
            leaf.insert(key, value).map_err(|e| match e {
                SmtLeafError::TooManyLeafEntries { actual } => {
                    MerkleError::TooManyLeafEntries { actual }
                },
                other => panic!("unexpected SmtLeaf::insert error: {:?}", other),
            })?;
        } else {
            leaf.remove(key);
        }
        let current_entries = leaf.num_entries();
        let new_leaf_hash = leaf.hash();
        self.num_entries = self.num_entries + current_entries - prev_entries;

        // Remove empty leaf
        if current_entries == 0 {
            self.leaves.remove(&leaf_index.position());
        }

        // Recompute the path from leaf to root
        self.recompute_nodes_from_leaf_to_root(leaf_index, new_leaf_hash);

        Ok(previous_value)
    }

    /// Adds an [`SmtProof`] to this [`PartialSmt`].
    ///
    /// This is a convenience method which calls [`Self::add_path`] on the proof. See its
    /// documentation for details on errors.
    pub fn add_proof(&mut self, proof: SmtProof) -> Result<(), MerkleError> {
        let (path, leaf) = proof.into_parts();
        self.add_path(leaf, path)
    }

    /// Adds a leaf and its sparse merkle path to this [`PartialSmt`].
    ///
    /// If this function was called, any key that is part of the `leaf` can subsequently be updated
    /// to a new value and produce a correct new tree root.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the new root after the insertion of the leaf and the path does not match the existing
    ///   root. If an error is returned, the tree is left in an inconsistent state.
    pub fn add_path(&mut self, leaf: SmtLeaf, path: SparseMerklePath) -> Result<(), MerkleError> {
        let path_root = self.add_path_unchecked(leaf, path);

        // Check if the newly added merkle path is consistent with the existing tree. If not, the
        // merkle path was invalid or computed against another tree.
        if self.root() != path_root {
            return Err(MerkleError::ConflictingRoots {
                expected_root: self.root(),
                actual_root: path_root,
            });
        }

        Ok(())
    }

    // PRIVATE HELPERS
    // --------------------------------------------------------------------------------------------

    /// Adds a leaf and its sparse merkle path to this [`PartialSmt`] and returns the root of the
    /// inserted path.
    ///
    /// This does not check that the path root matches the existing root of the tree and if so, the
    /// tree is left in an inconsistent state. This state can be made consistent again by setting
    /// the root of the SMT to the path root.
    fn add_path_unchecked(&mut self, leaf: SmtLeaf, path: SparseMerklePath) -> Word {
        let mut current_index = leaf.index().index;

        let mut node_hash_at_current_index = leaf.hash();

        let prev_entries = self
            .leaves
            .get(&current_index.position())
            .map(SmtLeaf::num_entries)
            .unwrap_or(0);
        let current_entries = leaf.num_entries();
        // Only store non-empty leaves
        if current_entries > 0 {
            self.leaves.insert(current_index.position(), leaf);
        } else {
            self.leaves.remove(&current_index.position());
        }

        // Guaranteed not to over/underflow. All variables are <= MAX_LEAF_ENTRIES and result > 0.
        self.num_entries = self.num_entries + current_entries - prev_entries;

        for sibling_hash in path {
            // Find the index of the sibling node and compute whether it is a left or right child.
            let is_sibling_right = current_index.sibling().is_position_odd();

            // Move the index up so it points to the parent of the current index and the sibling.
            current_index.move_up();

            // Construct the new parent node from the child that was updated and the sibling from
            // the merkle path.
            let new_parent_node = if is_sibling_right {
                InnerNode {
                    left: node_hash_at_current_index,
                    right: sibling_hash,
                }
            } else {
                InnerNode {
                    left: sibling_hash,
                    right: node_hash_at_current_index,
                }
            };

            node_hash_at_current_index = new_parent_node.hash();

            self.insert_inner_node(current_index, new_parent_node);
        }

        node_hash_at_current_index
    }

    /// Returns the leaf for a key if it can be tracked.
    ///
    /// A key is trackable if:
    /// 1. It was explicitly added via `add_path`/`add_proof`, OR
    /// 2. The path to the leaf goes through empty subtrees (provably empty)
    ///
    /// Returns `None` if the key cannot be tracked (path goes through non-empty
    /// subtrees we don't have data for).
    fn get_tracked_leaf(&self, key: &Word) -> Option<SmtLeaf> {
        let leaf_index = Self::key_to_leaf_index(key);

        // Explicitly stored leaves are always trackable
        if let Some(leaf) = self.leaves.get(&leaf_index.position()) {
            return Some(leaf.clone());
        }

        // Empty tree - all leaves implicitly trackable
        if self.root == Self::EMPTY_ROOT {
            return Some(SmtLeaf::new_empty(leaf_index));
        }

        // Walk from root down towards the leaf
        let target: NodeIndex = leaf_index.into();
        let mut index = NodeIndex::root();

        for i in (0..SMT_DEPTH).rev() {
            let inner_node = self.get_inner_node(index)?;

            let is_right = target.is_nth_bit_odd(i);
            let child_hash = if is_right { inner_node.right } else { inner_node.left };

            // If child is empty subtree root, leaf is implicitly trackable
            if child_hash == *EmptySubtreeRoots::entry(SMT_DEPTH, SMT_DEPTH - i) {
                return Some(SmtLeaf::new_empty(leaf_index));
            }

            index = if is_right {
                index.right_child()
            } else {
                index.left_child()
            };
        }

        // Reached leaf level without finding empty subtree - can't track
        None
    }

    /// Converts a key to a leaf index.
    fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_canonical_u64())
    }

    /// Returns the inner node at the specified index, or `None` if not stored.
    fn get_inner_node(&self, index: NodeIndex) -> Option<InnerNode> {
        self.inner_nodes.get(&index).cloned()
    }

    /// Returns the inner node at the specified index, falling back to the empty subtree root
    /// if not stored.
    fn get_inner_node_or_empty(&self, index: NodeIndex) -> InnerNode {
        self.get_inner_node(index)
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    /// Inserts an inner node at the specified index, or removes it if it equals the empty
    /// subtree root.
    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) {
        if inner_node == EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()) {
            self.inner_nodes.remove(&index);
        } else {
            self.inner_nodes.insert(index, inner_node);
        }
    }

    /// Returns the merkle path for a key by walking up the tree from the leaf.
    fn get_path(&self, key: &Word) -> SparseMerklePath {
        let index = NodeIndex::from(Self::key_to_leaf_index(key));

        // Use proof_indices to get sibling indices from leaf to root,
        // and get each sibling's hash
        SparseMerklePath::from_sized_iter(index.proof_indices().map(|idx| self.get_node_hash(idx)))
            .expect("path should be valid since it's from a valid SMT")
    }

    /// Get the hash of a node at an arbitrary index, including the root or leaf hashes.
    ///
    /// The root index simply returns the root. Other hashes are retrieved by looking at
    /// the parent inner node and returning the respective child hash.
    fn get_node_hash(&self, index: NodeIndex) -> Word {
        if index.is_root() {
            return self.root;
        }

        let InnerNode { left, right } = self.get_inner_node_or_empty(index.parent());

        if index.is_position_odd() { right } else { left }
    }

    /// Recomputes all inner nodes from a leaf up to the root after a leaf value change.
    fn recompute_nodes_from_leaf_to_root(
        &mut self,
        leaf_index: LeafIndex<SMT_DEPTH>,
        leaf_hash: Word,
    ) {
        use crate::hash::poseidon2::Poseidon2;

        let mut index: NodeIndex = leaf_index.into();
        let mut node_hash = leaf_hash;

        for _ in (0..index.depth()).rev() {
            let is_right = index.is_position_odd();
            index.move_up();
            let InnerNode { left, right } = self.get_inner_node_or_empty(index);
            let (left, right) = if is_right {
                (left, node_hash)
            } else {
                (node_hash, right)
            };
            node_hash = Poseidon2::merge(&[left, right]);

            // insert_inner_node handles removing empty subtree roots
            self.insert_inner_node(index, InnerNode { left, right });
        }
        self.root = node_hash;
    }

    /// Validates the internal structure during deserialization.
    ///
    /// Checks that:
    /// - Each inner node's hash is consistent with its parent.
    /// - Each leaf's hash is consistent with its parent inner node's left/right child.
    fn validate(&self) -> Result<(), DeserializationError> {
        // Validate each inner node is consistent with its parent
        for (&idx, node) in &self.inner_nodes {
            let node_hash = node.hash();
            let expected_hash = self.get_node_hash(idx);

            if node_hash != expected_hash {
                return Err(DeserializationError::InvalidValue(
                    "inner node hash is inconsistent with parent".into(),
                ));
            }
        }

        // Validate each leaf's hash is consistent with its parent inner node
        for (&leaf_pos, leaf) in &self.leaves {
            let leaf_index = LeafIndex::<SMT_DEPTH>::new_max_depth(leaf_pos);
            let node_index: NodeIndex = leaf_index.into();
            let leaf_hash = leaf.hash();
            let expected_hash = self.get_node_hash(node_index);

            if leaf_hash != expected_hash {
                return Err(DeserializationError::InvalidValue(
                    "leaf hash is inconsistent with parent inner node".into(),
                ));
            }
        }

        Ok(())
    }
}

impl Default for PartialSmt {
    /// Returns a new, empty [`PartialSmt`].
    ///
    /// All leaves in the returned tree are set to [`Self::EMPTY_VALUE`].
    fn default() -> Self {
        Self::new(Self::EMPTY_ROOT)
    }
}

// CONVERSIONS
// ================================================================================================

impl From<super::Smt> for PartialSmt {
    fn from(smt: super::Smt) -> Self {
        Self {
            root: smt.root(),
            num_entries: smt.num_entries(),
            leaves: smt.leaves().map(|(idx, leaf)| (idx.position(), leaf.clone())).collect(),
            inner_nodes: smt.inner_node_indices().collect(),
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PartialSmt {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.root());
        target.write_usize(self.leaves.len());
        for (i, leaf) in &self.leaves {
            target.write_u64(*i);
            target.write(leaf);
        }
        target.write_usize(self.inner_nodes.len());
        for (idx, node) in &self.inner_nodes {
            target.write(idx);
            target.write(node);
        }
    }
}

impl Deserializable for PartialSmt {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let root: Word = source.read()?;

        let mut leaves = Leaves::<SmtLeaf>::default();
        for _ in 0..source.read_usize()? {
            let pos: u64 = source.read()?;
            let leaf: SmtLeaf = source.read()?;
            leaves.insert(pos, leaf);
        }

        let mut inner_nodes = InnerNodes::default();
        for _ in 0..source.read_usize()? {
            let idx: NodeIndex = source.read()?;
            let node: InnerNode = source.read()?;
            inner_nodes.insert(idx, node);
        }

        let num_entries = leaves.values().map(SmtLeaf::num_entries).sum();

        let partial = Self { root, num_entries, leaves, inner_nodes };
        partial.validate()?;

        Ok(partial)
    }
}
