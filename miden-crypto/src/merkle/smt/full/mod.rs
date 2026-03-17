use alloc::{string::ToString, vec::Vec};

use super::{
    EMPTY_WORD, EmptySubtreeRoots, InnerNode, InnerNodeInfo, InnerNodes, LeafIndex, MerkleError,
    MutationSet, NodeIndex, SparseMerklePath, SparseMerkleTree, Word,
};

mod error;
pub use error::{SmtLeafError, SmtProofError};

mod leaf;
pub use leaf::SmtLeaf;

mod proof;
pub use proof::SmtProof;

use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// Concurrent implementation
#[cfg(feature = "concurrent")]
pub(in crate::merkle::smt) mod concurrent;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// The depth of the sparse Merkle tree.
///
/// All leaves in this SMT are located at depth 64.
pub const SMT_DEPTH: u8 = 64;

/// The maximum number of entries allowed in a multiple leaf.
pub const MAX_LEAF_ENTRIES: usize = 1024;

// SMT
// ================================================================================================

type Leaves = super::Leaves<SmtLeaf>;

/// Sparse Merkle tree mapping 256-bit keys to 256-bit values. Both keys and values are represented
/// by 4 field elements.
///
/// All leaves sit at depth 64. The most significant element of the key is used to identify the leaf
/// to which the key maps.
///
/// A leaf is either empty, or holds one or more key-value pairs. An empty leaf hashes to the empty
/// word. Otherwise, a leaf hashes to the hash of its key-value pairs, ordered by key first, value
/// second.
///
/// ```text
/// depth
/// T  0                  Root
/// │  .                  /  \
/// │  1              left   right
/// │  .             /  \    /  \
/// │
/// │          .. .. .. .. .. .. .. ..
/// │
/// │  63
/// │           /  \        /   \           \
/// │  ￬       /    \      /     \           \
/// │  64   Leaf₀  Leaf₁  Leaf₂  Leaf₃  ...  Leaf₂⁶⁴₋₂³²
///        0x0..0 0x0..1 0x0..2 0x0..3      0xFFFFFFFF00000000
///
/// The digest is 256 bits, or 4 field elements:
/// [elem₀, elem₁, elem₂, elem₃]
///                         ↑
///         Most significant element determines leaf
///         index, mapping into the actual Leaf lookup
///         table where the values are stored.
///
/// Zooming into a leaf, i.e. Leaf₁:
/// ┌─────────────────────────────────────────────────┐
/// │            Leaf₁ (index: 0x0..1)                │
/// ├─────────────────────────────────────────────────┤
/// │ Possible states:                                │
/// │                                                 │
/// │ 1. Empty leaf:                                  │
/// │    └─ hash = EMPTY_WORD                         │
/// │                                                 │
/// │ 2. Single entry:                                │
/// │    └─ (key₁, value₁)                            │
/// │    └─ hash = H(key₁, value₁)                    │
/// │                                                 │
/// │ 3. Multiple entries:                            │
/// │    └─ (key₁, value₁)                            │
/// │    └─ (key₂, value₂)                            │
/// │    └─ ...                                       │
/// │    └─ hash = H(key₁, value₁, key₂, value₂, ...) │
/// └─────────────────────────────────────────────────┘
///
/// Leaf states:
/// - Empty: hashes to EMPTY_WORD
/// - Non-empty: contains (key, value) pairs
///              hash = H(key₁, value₁, key₂, value₂, ...)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Smt {
    root: Word,
    num_entries: usize,
    leaves: Leaves,
    inner_nodes: InnerNodes,
}

impl Smt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// The default value used to compute the hash of empty leaves
    pub const EMPTY_VALUE: Word = <Self as SparseMerkleTree<SMT_DEPTH>>::EMPTY_VALUE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [Smt].
    ///
    /// All leaves in the returned tree are set to [Self::EMPTY_VALUE].
    pub fn new() -> Self {
        let root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

        Self {
            root,
            num_entries: 0,
            inner_nodes: Default::default(),
            leaves: Default::default(),
        }
    }

    /// Returns a new [Smt] instantiated with leaves set as specified by the provided entries.
    ///
    /// If the `concurrent` feature is enabled, this function uses a parallel implementation to
    /// process the entries efficiently, otherwise it defaults to the sequential implementation.
    ///
    /// All leaves omitted from the entries list are set to [Self::EMPTY_VALUE].
    ///
    /// # Errors
    /// Returns an error if:
    /// - the provided entries contain multiple values for the same key.
    /// - inserting a key-value pair would exceed [`MAX_LEAF_ENTRIES`] (1024 entries) in a leaf.
    pub fn with_entries(
        entries: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<Self, MerkleError> {
        #[cfg(feature = "concurrent")]
        {
            Self::with_entries_concurrent(entries)
        }
        #[cfg(not(feature = "concurrent"))]
        {
            Self::with_entries_sequential(entries)
        }
    }

    /// Similar to `with_entries` but avoids the overhead of sorting if the entries are already
    /// sorted.
    ///
    /// This only applies if the "concurrent" feature is enabled. Without the feature, the behavior
    /// is equivalent to `with_entiries`.
    ///
    /// # Errors
    /// Returns an error if inserting a key-value pair would exceed [`MAX_LEAF_ENTRIES`] (1024
    /// entries) in a leaf.
    pub fn with_sorted_entries(
        entries: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<Self, MerkleError> {
        #[cfg(feature = "concurrent")]
        {
            Self::with_sorted_entries_concurrent(entries)
        }
        #[cfg(not(feature = "concurrent"))]
        {
            Self::with_entries_sequential(entries)
        }
    }

    /// Returns a new [Smt] instantiated with leaves set as specified by the provided entries.
    ///
    /// This sequential implementation processes entries one at a time to build the tree.
    /// All leaves omitted from the entries list are set to [Self::EMPTY_VALUE].
    ///
    /// # Errors
    /// Returns an error if:
    /// - the provided entries contain multiple values for the same key.
    /// - inserting a key-value pair would exceed [`MAX_LEAF_ENTRIES`] (1024 entries) in a leaf.
    #[cfg(any(not(feature = "concurrent"), fuzzing, feature = "fuzzing", test))]
    fn with_entries_sequential(
        entries: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<Self, MerkleError> {
        use alloc::collections::BTreeSet;

        // create an empty tree
        let mut tree = Self::new();

        // This being a sparse data structure, the EMPTY_WORD is not assigned to the `BTreeMap`, so
        // entries with the empty value need additional tracking.
        let mut key_set_to_zero = BTreeSet::new();

        for (key, value) in entries {
            let old_value = tree.insert(key, value)?;

            if old_value != EMPTY_WORD || key_set_to_zero.contains(&key) {
                return Err(MerkleError::DuplicateValuesForIndex(
                    LeafIndex::<SMT_DEPTH>::from(key).position(),
                ));
            }

            if value == EMPTY_WORD {
                key_set_to_zero.insert(key);
            };
        }
        Ok(tree)
    }

    /// Returns a new [`Smt`] instantiated from already computed leaves and nodes.
    ///
    /// This function performs minimal consistency checking. It is the caller's responsibility to
    /// ensure the passed arguments are correct and consistent with each other.
    ///
    /// # Panics
    /// With debug assertions on, this function panics if `root` does not match the root node in
    /// `inner_nodes`.
    pub fn from_raw_parts(inner_nodes: InnerNodes, leaves: Leaves, root: Word) -> Self {
        // Our particular implementation of `from_raw_parts()` never returns `Err`.
        <Self as SparseMerkleTree<SMT_DEPTH>>::from_raw_parts(inner_nodes, leaves, root).unwrap()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the depth of the tree
    pub const fn depth(&self) -> u8 {
        SMT_DEPTH
    }

    /// Returns the root of the tree
    pub fn root(&self) -> Word {
        <Self as SparseMerkleTree<SMT_DEPTH>>::root(self)
    }

    /// Returns the number of non-empty leaves in this tree.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Returns the number of key-value pairs with non-default values in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_entries(&self) -> usize {
        self.num_entries
    }

    /// Returns the leaf to which `key` maps
    pub fn get_leaf(&self, key: &Word) -> SmtLeaf {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_leaf(self, key)
    }

    /// Returns the leaf corresponding to the provided `index`.
    pub fn get_leaf_by_index(&self, index: LeafIndex<SMT_DEPTH>) -> Option<SmtLeaf> {
        self.leaves.get(&index.position()).cloned()
    }

    /// Returns the value associated with `key`
    pub fn get_value(&self, key: &Word) -> Word {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_value(self, key)
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    pub fn open(&self, key: &Word) -> SmtProof {
        <Self as SparseMerkleTree<SMT_DEPTH>>::open(self, key)
    }

    /// Returns a boolean value indicating whether the SMT is empty.
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.leaves.is_empty(), self.root == Self::EMPTY_ROOT);
        self.root == Self::EMPTY_ROOT
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [`Smt`] in arbitrary order.
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.leaves
            .iter()
            .map(|(leaf_index, leaf)| (LeafIndex::new_max_depth(*leaf_index), leaf))
    }

    /// Returns an iterator over the key-value pairs of this [Smt] in arbitrary order.
    pub fn entries(&self) -> impl Iterator<Item = &(Word, Word)> {
        self.leaves().flat_map(|(_, leaf)| leaf.entries())
    }

    /// Returns an iterator over the inner nodes of this [Smt].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.inner_nodes.values().map(|e| InnerNodeInfo {
            value: e.hash(),
            left: e.left,
            right: e.right,
        })
    }

    /// Returns an iterator over the [`InnerNode`] and the respective [`NodeIndex`] of the [`Smt`].
    pub fn inner_node_indices(&self) -> impl Iterator<Item = (NodeIndex, InnerNode)> + '_ {
        self.inner_nodes.iter().map(|(idx, inner)| (*idx, inner.clone()))
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
    /// Returns an error if inserting the key-value pair would exceed [`MAX_LEAF_ENTRIES`] (1024
    /// entries) in the leaf.
    pub fn insert(&mut self, key: Word, value: Word) -> Result<Word, MerkleError> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::insert(self, key, value)
    }

    /// Computes what changes are necessary to insert the specified key-value pairs into this Merkle
    /// tree, allowing for validation before applying those changes.
    ///
    /// This method returns a [`MutationSet`], which contains all the information for inserting
    /// `kv_pairs` into this Merkle tree already calculated, including the new root hash, which can
    /// be queried with [`MutationSet::root()`]. Once a mutation set is returned,
    /// [`Smt::apply_mutations()`] can be called in order to commit these changes to the Merkle
    /// tree, or [`drop()`] to discard them.
    ///
    /// # Errors
    ///
    /// - [`MerkleError::DuplicateValuesForIndex`] if `kv_pairs` contains the same key more than
    ///   once.
    /// - [`MerkleError::TooManyLeafEntries`] if mutations would exceed 1024 entries in a leaf.
    ///
    /// # Example
    ///
    /// ```
    /// # use miden_crypto::{Felt, Word};
    /// # use miden_crypto::merkle::{EmptySubtreeRoots, smt::{Smt, SMT_DEPTH}};
    /// let mut smt = Smt::new();
    /// let pair = (Word::default(), Word::default());
    /// let mutations = smt.compute_mutations(vec![pair]).unwrap();
    /// assert_eq!(mutations.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// smt.apply_mutations(mutations).unwrap();
    /// assert_eq!(smt.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// ```
    pub fn compute_mutations(
        &self,
        kv_pairs: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, MerkleError> {
        #[cfg(feature = "concurrent")]
        {
            self.compute_mutations_concurrent(kv_pairs)
        }
        #[cfg(not(feature = "concurrent"))]
        {
            <Self as SparseMerkleTree<SMT_DEPTH>>::compute_mutations(self, kv_pairs)
        }
    }

    /// Applies the prospective mutations computed with [`Smt::compute_mutations()`] to this tree.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    pub fn apply_mutations(
        &mut self,
        mutations: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), MerkleError> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::apply_mutations(self, mutations)
    }

    /// Applies the prospective mutations computed with [`Smt::compute_mutations()`] to this tree
    /// and returns the reverse mutation set.
    ///
    /// Applying the reverse mutation sets to the updated tree will revert the changes.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    pub fn apply_mutations_with_reversion(
        &mut self,
        mutations: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, MerkleError> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::apply_mutations_with_reversion(self, mutations)
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Inserts `value` at leaf index pointed to by `key`. `value` is guaranteed to not be the empty
    /// value, such that this is indeed an insertion.
    ///
    /// # Errors
    /// Returns an error if inserting the key-value pair would exceed [`MAX_LEAF_ENTRIES`] (1024
    /// entries) in the leaf.
    fn perform_insert(&mut self, key: Word, value: Word) -> Result<Option<Word>, MerkleError> {
        debug_assert_ne!(value, Self::EMPTY_VALUE);

        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        match self.leaves.get_mut(&leaf_index.position()) {
            Some(leaf) => {
                let prev_entries = leaf.num_entries();
                let result = leaf.insert(key, value).map_err(|e| match e {
                    SmtLeafError::TooManyLeafEntries { actual } => {
                        MerkleError::TooManyLeafEntries { actual }
                    },
                    other => panic!("unexpected SmtLeaf::insert error: {:?}", other),
                })?;
                let current_entries = leaf.num_entries();
                self.num_entries += current_entries - prev_entries;
                Ok(result)
            },
            None => {
                self.leaves.insert(leaf_index.position(), SmtLeaf::Single((key, value)));
                self.num_entries += 1;
                Ok(None)
            },
        }
    }

    /// Removes key-value pair at leaf index pointed to by `key` if it exists.
    fn perform_remove(&mut self, key: Word) -> Option<Word> {
        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        if let Some(leaf) = self.leaves.get_mut(&leaf_index.position()) {
            let prev_entries = leaf.num_entries();
            let (old_value, is_empty) = leaf.remove(key);
            let current_entries = leaf.num_entries();
            self.num_entries -= prev_entries - current_entries;
            if is_empty {
                self.leaves.remove(&leaf_index.position());
            }
            old_value
        } else {
            // there's nothing stored at the leaf; nothing to update
            None
        }
    }
}

impl SparseMerkleTree<SMT_DEPTH> for Smt {
    type Key = Word;
    type Value = Word;
    type Leaf = SmtLeaf;
    type Opening = SmtProof;

    const EMPTY_VALUE: Self::Value = EMPTY_WORD;
    const EMPTY_ROOT: Word = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    fn from_raw_parts(
        inner_nodes: InnerNodes,
        leaves: Leaves,
        root: Word,
    ) -> Result<Self, MerkleError> {
        if cfg!(debug_assertions) {
            let root_node_hash = inner_nodes
                .get(&NodeIndex::root())
                .map(InnerNode::hash)
                .unwrap_or(Self::EMPTY_ROOT);

            assert_eq!(root_node_hash, root);
        }
        let num_entries = leaves.values().map(|leaf| leaf.num_entries()).sum();
        Ok(Self { root, inner_nodes, leaves, num_entries })
    }

    fn root(&self) -> Word {
        self.root
    }

    fn set_root(&mut self, root: Word) {
        self.root = root;
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        self.inner_nodes
            .get(&index)
            .cloned()
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        if inner_node == EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()) {
            self.remove_inner_node(index)
        } else {
            self.inner_nodes.insert(index, inner_node)
        }
    }

    fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        self.inner_nodes.remove(&index)
    }

    fn insert_value(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Result<Option<Self::Value>, MerkleError> {
        // inserting an `EMPTY_VALUE` is equivalent to removing any value associated with `key`
        if value != Self::EMPTY_VALUE {
            self.perform_insert(key, value)
        } else {
            Ok(self.perform_remove(key))
        }
    }

    fn get_value(&self, key: &Self::Key) -> Self::Value {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).position();

        match self.leaves.get(&leaf_pos) {
            Some(leaf) => leaf.get_value(key).unwrap_or_default(),
            None => EMPTY_WORD,
        }
    }

    fn get_leaf(&self, key: &Word) -> Self::Leaf {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).position();

        match self.leaves.get(&leaf_pos) {
            Some(leaf) => leaf.clone(),
            None => SmtLeaf::new_empty((*key).into()),
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

    fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_canonical_u64())
    }

    fn path_and_leaf_to_opening(path: SparseMerklePath, leaf: SmtLeaf) -> SmtProof {
        SmtProof::new_unchecked(path, leaf)
    }
}

impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
}

// CONVERSIONS
// ================================================================================================

impl From<Word> for LeafIndex<SMT_DEPTH> {
    fn from(value: Word) -> Self {
        // We use the most significant `Felt` of a `Word` as the leaf index.
        Self::new_max_depth(value[3].as_canonical_u64())
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Smt {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write the number of filled leaves for this Smt
        target.write_usize(self.entries().count());

        // Write each (key, value) pair
        for (key, value) in self.entries() {
            target.write(key);
            target.write(value);
        }
    }

    fn get_size_hint(&self) -> usize {
        let entries_count = self.entries().count();

        // Each entry is the size of a digest plus a word.
        entries_count.get_size_hint()
            + entries_count * (Word::SERIALIZED_SIZE + EMPTY_WORD.get_size_hint())
    }
}

impl Deserializable for Smt {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Read the number of filled leaves for this Smt
        let num_filled_leaves = source.read_usize()?;

        // Use read_many_iter to avoid eager allocation and respect BudgetedReader limits
        let entries: Vec<(Word, Word)> =
            source.read_many_iter(num_filled_leaves)?.collect::<Result<_, _>>()?;

        Self::with_entries(entries)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }

    /// Minimum serialized size: vint64 length prefix (0 entries).
    fn min_serialized_size() -> usize {
        1
    }
}

// FUZZING
// ================================================================================================

#[cfg(any(fuzzing, feature = "fuzzing"))]
impl Smt {
    pub fn fuzz_with_entries_sequential(
        entries: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<Smt, MerkleError> {
        Self::with_entries_sequential(entries)
    }

    pub fn fuzz_compute_mutations_sequential(
        &self,
        kv_pairs: impl IntoIterator<Item = (Word, Word)>,
    ) -> MutationSet<SMT_DEPTH, Word, Word> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::compute_mutations(self, kv_pairs)
            .expect("Failed to compute mutations in fuzzing")
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
use crate::Felt;

#[test]
fn test_smt_serialization_deserialization() {
    // Smt for default types (empty map)
    let smt_default = Smt::default();
    let bytes = smt_default.to_bytes();
    assert_eq!(smt_default, Smt::read_from_bytes(&bytes).unwrap());
    assert_eq!(bytes.len(), smt_default.get_size_hint());

    // Smt with values
    let smt_leaves_2: [(Word, Word); 2] = [
        (
            Word::new([Felt::new(105), Felt::new(106), Felt::new(107), Felt::new(108)]),
            [Felt::new(5_u64), Felt::new(6_u64), Felt::new(7_u64), Felt::new(8_u64)].into(),
        ),
        (
            Word::new([Felt::new(101), Felt::new(102), Felt::new(103), Felt::new(104)]),
            [Felt::new(1_u64), Felt::new(2_u64), Felt::new(3_u64), Felt::new(4_u64)].into(),
        ),
    ];
    let smt = Smt::with_entries(smt_leaves_2).unwrap();

    let bytes = smt.to_bytes();
    assert_eq!(smt, Smt::read_from_bytes(&bytes).unwrap());
    assert_eq!(bytes.len(), smt.get_size_hint());
}

#[test]
fn smt_with_sorted_entries() {
    // Smt with sorted values
    let smt_leaves_2: [(Word, Word); 2] = [
        (
            Word::new([Felt::new(101), Felt::new(102), Felt::new(103), Felt::new(104)]),
            [Felt::new(1_u64), Felt::new(2_u64), Felt::new(3_u64), Felt::new(4_u64)].into(),
        ),
        (
            Word::new([Felt::new(105), Felt::new(106), Felt::new(107), Felt::new(108)]),
            [Felt::new(5_u64), Felt::new(6_u64), Felt::new(7_u64), Felt::new(8_u64)].into(),
        ),
    ];

    let smt = Smt::with_sorted_entries(smt_leaves_2).unwrap();
    let expected_smt = Smt::with_entries(smt_leaves_2).unwrap();

    assert_eq!(smt, expected_smt);
}
