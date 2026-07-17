//! This module contains the [`Subtree`] type that represents a complete 8-depth subtree
//! serialized into a single storage entry.
//!
//! The subtree uses a compact bitmask-based representation where the in-memory format matches
//! the serialized format, eliminating conversion overhead during serialization/deserialization.

use alloc::{collections::BTreeSet, vec::Vec};

use super::{EmptySubtreeRoots, InnerNode, InnerNodeInfo, NodeIndex, NodeMutation, SMT_DEPTH};
use crate::{Word, merkle::smt::full::concurrent::SUBTREE_DEPTH};

mod error;
pub use error::SubtreeError;

#[cfg(test)]
mod tests;

// TYPES
// ================================================================================================

/// A mutation converted to subtree-local coordinates.
struct LocalMutation {
    /// Local index within the subtree (0-254).
    local_index: u8,
    /// The kind of mutation to apply.
    kind: LocalMutationKind,
}

/// The kind of mutation to apply to a subtree node.
enum LocalMutationKind {
    /// Add or update a node with the given child hashes.
    Addition {
        /// The left child hash.
        left: Word,
        /// The right child hash.
        right: Word,
        /// Whether the left child is non-empty.
        has_left: bool,
        /// Whether the right child is non-empty.
        has_right: bool,
    },
    /// Remove the node at this position.
    Removal,
}

/// Iterator over non-empty nodes in a subtree.
///
/// Yields [`SubtreeNode`] for each node that has at least one non-empty child.
/// Tracks hash positions for use cases that need them (e.g., rebuild).
struct SubtreeNodeIter<'a> {
    subtree: &'a Subtree,
    /// Current word index in child_bits.
    word_idx: usize,
    /// Remaining bits in current word (nodes are cleared as visited).
    remaining: u64,
    /// Current position in the hashes vector.
    hash_idx: usize,
}

/// A non-empty node yielded by [`SubtreeNodeIter`].
struct SubtreeNode {
    /// Local index within the subtree (0-254).
    local_index: u8,
    /// Starting position in the hashes vector.
    hash_start: usize,
    /// Whether the left child is non-empty.
    has_left: bool,
    /// Whether the right child is non-empty.
    has_right: bool,
}

impl<'a> SubtreeNodeIter<'a> {
    fn new(subtree: &'a Subtree) -> Self {
        Self {
            subtree,
            word_idx: 0,
            remaining: subtree.child_bits[0],
            hash_idx: 0,
        }
    }
}

impl Iterator for SubtreeNodeIter<'_> {
    type Item = SubtreeNode;

    fn next(&mut self) -> Option<SubtreeNode> {
        const NODE_PAIR_MASK: u64 = 0b11;
        const NODES_PER_WORD: u8 = 32;

        // Skip empty words.
        while self.remaining == 0 && self.word_idx < 7 {
            self.word_idx += 1;
            self.remaining = self.subtree.child_bits[self.word_idx];
        }

        if self.remaining == 0 {
            return None;
        }

        // Find first set bit and its node index.
        let bit_pos = self.remaining.trailing_zeros() as u8;
        let node_in_word = bit_pos / Subtree::BITS_PER_NODE as u8;
        let local_index = (self.word_idx as u8) * NODES_PER_WORD + node_in_word;

        // Clear this node's bits so we don't visit it again.
        self.remaining &= !(NODE_PAIR_MASK << (node_in_word * Subtree::BITS_PER_NODE as u8));

        // Look up child presence.
        let bit_offset = (local_index as usize) * Subtree::BITS_PER_NODE;
        let has_left = self.subtree.get_bit(bit_offset);
        let has_right = self.subtree.get_bit(bit_offset + 1);

        let node = SubtreeNode {
            local_index,
            hash_start: self.hash_idx,
            has_left,
            has_right,
        };

        // Advance hash index for next iteration.
        self.hash_idx += has_left as usize + has_right as usize;

        Some(node)
    }
}

// SUBTREE
// ================================================================================================

/// Represents a complete 8-depth subtree that is serialized into a single RocksDB entry.
///
/// ### What is stored
/// - `nodes` tracks only **non-empty inner nodes** of this subtree (i.e., nodes for which at least
///   one child differs from the canonical empty hash). Each entry stores an `InnerNode` (hash
///   pair).
///
/// ### Local index layout (how indices are computed)
/// - Indices are **subtree-local** and follow binary-heap (level-order) layout: `root = 0`;
///   children of `i` are at `2i+1` and `2i+2`.
/// - Equivalently, given a `(depth, value)` from the parent tree, the local index is obtained by
///   taking the node’s depth **relative to the subtree root** and its left-to-right position within
///   that level (offset by the total number of nodes in all previous levels).
///
/// ### In-memory format
/// - `child_bits`: 8 little-endian u64s (64 bytes total).
/// - `hashes`: contiguous `Vec<Word>` of non-empty child hashes.
#[derive(Debug, Clone)]
pub struct Subtree {
    /// Index of this subtree's root in the parent SMT.
    root_index: NodeIndex,
    /// Bitmask indicating non-empty children.
    /// For local index i: bit 2*i = left child non-empty, bit 2*i+1 = right child non-empty.
    /// Stored as 8 little-endian u64s (512 bits total, 2 bits per node x 255 nodes + 2 unused).
    child_bits: [u64; 8],
    /// Non-empty child hashes in bit order.
    hashes: Vec<Word>,
}

impl Subtree {
    const FORMAT_MAGIC: [u8; 4] = *b"SMT1";
    const FORMAT_VERSION: u8 = 1;
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    const HASH_SIZE: usize = 32;
    const BITMASK_SIZE: usize = 64;
    const BITS_PER_NODE: usize = 2;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new empty subtree rooted at the given index.
    pub fn new(root_index: NodeIndex) -> Self {
        Self {
            root_index,
            child_bits: [0; 8],
            hashes: Vec::new(),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root index of this subtree in the parent SMT.
    pub fn root_index(&self) -> NodeIndex {
        self.root_index
    }

    /// Returns the number of non-empty inner nodes in this subtree.
    ///
    /// A node "exists" if at least one of its two child bits is set. Each node occupies a
    /// 2-bit pair `(left, right)` in `child_bits`, so we collapse each pair into one bit and
    /// count. For a word `w`:
    ///
    /// 1. `w | (w >> 1)` — propagates right-child bits into the even (left) position
    /// 2. `& 0x5555...`  — keeps only even positions (one bit per node)
    /// 3. `count_ones()` — counts occupied nodes
    ///
    /// Example with 4 nodes:
    ///   `w = 0b10_01_11_00`
    ///
    ///   Node 0 (bits 0-1): left=0, right=0 → empty
    ///   Node 1 (bits 2-3): left=1, right=1 → both children
    ///   Node 2 (bits 4-5): left=1, right=0 → left only
    ///   Node 3 (bits 6-7): left=0, right=1 → right only
    ///
    ///   - `w | (w >> 1)` = `0b11_01_11_10` (OR each pair into even positions)
    ///   - `& 0x55`       = `0b01_01_01_00` (mask to keep only even bits)
    ///   - popcount = 3 (nodes 1, 2, 3 exist; node 0 is empty)
    pub fn len(&self) -> usize {
        const EVEN_BIT_MASK: u64 = 0x5555_5555_5555_5555;

        self.child_bits
            .iter()
            .map(|&w| (((w | (w >> 1)) & EVEN_BIT_MASK).count_ones()) as usize)
            .sum()
    }

    /// Returns `true` if this subtree has no nodes.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Returns the inner node at the given global index, if it exists.
    pub fn get_inner_node(&self, index: NodeIndex) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        self.get_by_local_index(local_index)
    }

    /// Converts a global NodeIndex to a local subtree index.
    ///
    /// # Panics
    /// Panics if `global.depth() < base.depth()`.
    pub fn global_to_local(global: NodeIndex, base: NodeIndex) -> u8 {
        assert!(
            global.depth() >= base.depth(),
            "Global depth is less than base depth = {}, global depth = {}",
            base.depth(),
            global.depth()
        );

        let relative_depth = global.depth() - base.depth();
        let level_mask = (1u64 << relative_depth) - 1;
        let local_position = (global.position() & level_mask) as u8;
        level_mask as u8 + local_position
    }

    /// Creates the storage key for a subtree.
    pub fn subtree_key(root_index: NodeIndex) -> [u8; 9] {
        let mut key = [0u8; 9];
        key[0] = root_index.depth();
        key[1..].copy_from_slice(&root_index.position().to_be_bytes());
        key
    }

    /// Finds the subtree root for a given node index.
    pub fn find_subtree_root(node_index: NodeIndex) -> NodeIndex {
        let depth = node_index.depth();
        if depth < SUBTREE_DEPTH {
            NodeIndex::root()
        } else {
            let relative_depth = depth % SUBTREE_DEPTH;
            let subtree_root_depth = depth - relative_depth;
            let base_value = node_index.position() >> relative_depth;

            NodeIndex::new(subtree_root_depth, base_value).unwrap()
        }
    }

    /// Iterates over all inner nodes in this subtree, yielding their info.
    pub fn iter_inner_node_info(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.node_iter().filter_map(move |node| {
            self.get_by_local_index(node.local_index).map(|inner| InnerNodeInfo {
                value: inner.hash(),
                left: inner.left,
                right: inner.right,
            })
        })
    }

    // PUBLIC MUTATIONS
    // --------------------------------------------------------------------------------------------

    /// Applies a batch of mutations to this subtree.
    ///
    /// When mutations only update existing nodes (same structure, different hashes),
    /// hashes are patched in-place. Structural changes (additions or removals) trigger a rebuild.
    /// If multiple mutations target the same node index, the last mutation wins.
    ///
    /// - `NodeMutation::Addition(node)` inserts or updates a node
    /// - `NodeMutation::Removal` removes a node
    pub fn apply_mutations<'a>(
        &mut self,
        mutations: impl IntoIterator<Item = (&'a NodeIndex, &'a NodeMutation)>,
    ) {
        let Some((local_mutations, can_patch_in_place)) = self.collect_local_mutations(mutations)
        else {
            return;
        };

        if can_patch_in_place {
            self.patch_hashes_in_place(&local_mutations);
        } else {
            self.rebuild_from_mutations(local_mutations);
        }
    }

    /// Inserts or updates an inner node at the given global index.
    ///
    /// **Note**: For batch updates, prefer [`apply_mutations`](Self::apply_mutations) which is
    /// more efficient when applying multiple changes.
    ///
    /// Returns the previous node at this index, if any.
    pub fn insert_inner_node(
        &mut self,
        index: NodeIndex,
        inner_node: InnerNode,
    ) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        let previous = self.get_by_local_index(local_index);

        self.apply_mutations([(&index, &NodeMutation::Addition(inner_node))]);

        previous
    }

    /// Removes an inner node at the given global index.
    ///
    /// **Note**: For batch updates, prefer [`apply_mutations`](Self::apply_mutations) which is
    /// more efficient when applying multiple changes.
    ///
    /// Returns the removed node, if any.
    pub fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        let local_index = Self::global_to_local(index, self.root_index);
        let previous = self.get_by_local_index(local_index);

        if previous.is_some() {
            self.apply_mutations([(&index, &NodeMutation::Removal)]);
        }

        previous
    }

    // SERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this subtree into a compact byte representation.
    ///
    /// The format is trivial since in-memory layout matches serialization:
    /// - 4 bytes: format magic
    /// - 1 byte: format version
    /// - 64 bytes: `child_bits` as little-endian u64s
    /// - Variable: non-empty child hashes (32 bytes each)
    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(
            Self::FORMAT_MAGIC.len() + 1 + Self::BITMASK_SIZE + self.hashes.len() * Self::HASH_SIZE,
        );

        result.extend_from_slice(&Self::FORMAT_MAGIC);
        result.push(Self::FORMAT_VERSION);

        for word in &self.child_bits {
            result.extend_from_slice(&word.to_le_bytes());
        }

        for hash in &self.hashes {
            result.extend_from_slice(&hash.as_bytes());
        }

        result
    }

    /// Deserializes a subtree from its compact byte representation.
    ///
    /// The format is trivial since in-memory layout matches serialization:
    /// - 4 bytes: format magic
    /// - 1 byte: format version
    /// - 64 bytes: `child_bits` as little-endian u64s
    /// - Variable: non-empty child hashes (32 bytes each)
    pub fn from_vec(root_index: NodeIndex, data: &[u8]) -> Result<Self, SubtreeError> {
        let min_header = Self::FORMAT_MAGIC.len() + 1;
        if data.len() < min_header {
            return Err(SubtreeError::TooShort { found: data.len(), min: min_header });
        }
        if !data.starts_with(&Self::FORMAT_MAGIC) {
            return Err(SubtreeError::MissingFormatMagic);
        }

        let version = data[Self::FORMAT_MAGIC.len()];
        if version != Self::FORMAT_VERSION {
            return Err(SubtreeError::UnsupportedVersion { found: version });
        }

        let parse_payload = |payload: &[u8]| -> Result<Self, SubtreeError> {
            let min_len = Self::FORMAT_MAGIC.len() + 1 + Self::BITMASK_SIZE;
            if payload.len() < Self::BITMASK_SIZE {
                return Err(SubtreeError::TooShort {
                    found: payload.len() + min_header,
                    min: min_len,
                });
            }

            let (bits_data, hash_data) = payload.split_at(Self::BITMASK_SIZE);

            let mut child_bits = [0u64; 8];
            for (i, chunk) in bits_data.chunks_exact(8).enumerate() {
                child_bits[i] = u64::from_le_bytes(chunk.try_into().unwrap());
            }

            // Bits 510-511 are unused - reject corrupted data where these bits are set.
            const UNUSED_BITS_MASK: u64 = 0b11 << 62;
            if child_bits[7] & UNUSED_BITS_MASK != 0 {
                return Err(SubtreeError::InvalidBitmask);
            }

            let set_bits: usize = child_bits.iter().map(|w| w.count_ones() as usize).sum();
            if hash_data.len() != set_bits * Self::HASH_SIZE {
                return Err(SubtreeError::BadHashLen {
                    expected: set_bits * Self::HASH_SIZE,
                    found: hash_data.len(),
                });
            }

            let hashes: Vec<Word> = hash_data
                .chunks_exact(Self::HASH_SIZE)
                .map(|chunk| Word::try_from(chunk).map_err(|_| SubtreeError::InvalidHashData))
                .collect::<Result<_, _>>()?;

            Ok(Self { root_index, child_bits, hashes })
        };

        parse_payload(&data[min_header..])
    }

    // PRIVATE HELPERS
    // --------------------------------------------------------------------------------------------

    /// Gets an inner node by its local index within this subtree.
    fn get_by_local_index(&self, local_index: u8) -> Option<InnerNode> {
        let left_bit = (local_index as usize) * Self::BITS_PER_NODE;
        let right_bit = left_bit + 1;

        let has_left = self.get_bit(left_bit);
        let has_right = self.get_bit(right_bit);

        if !has_left && !has_right {
            return None;
        }

        let node_depth_in_subtree = Self::local_index_to_depth(local_index);
        let child_depth = self.root_index.depth() + node_depth_in_subtree + 1;
        let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth);

        let left_pos = self.count_bits_before(left_bit);
        let left = if has_left { self.hashes[left_pos] } else { empty_hash };

        let right_pos = if has_left { left_pos + 1 } else { left_pos };
        let right = if has_right { self.hashes[right_pos] } else { empty_hash };

        Some(InnerNode { left, right })
    }

    /// Collects subtree-local mutations and determines if the structure stays the same.
    ///
    /// Returns `None` if there are no mutations to apply.
    fn collect_local_mutations<'a>(
        &self,
        mutations: impl IntoIterator<Item = (&'a NodeIndex, &'a NodeMutation)>,
    ) -> Option<(Vec<LocalMutation>, bool)> {
        let mut local_mutations = Vec::new();

        for (index, mutation) in mutations {
            let local_index = Self::global_to_local(*index, self.root_index);
            let kind = match mutation {
                NodeMutation::Addition(node) => {
                    let node_depth_in_subtree = Self::local_index_to_depth(local_index);
                    let child_depth = self.root_index.depth() + node_depth_in_subtree + 1;
                    let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth);
                    let has_left = node.left != empty_hash;
                    let has_right = node.right != empty_hash;

                    LocalMutationKind::Addition {
                        left: node.left,
                        right: node.right,
                        has_left,
                        has_right,
                    }
                },
                NodeMutation::Removal => LocalMutationKind::Removal,
            };

            local_mutations.push(LocalMutation { local_index, kind });
        }

        if local_mutations.is_empty() {
            return None;
        }

        let mut seen = BTreeSet::new();
        let mut deduped = Vec::with_capacity(local_mutations.len());
        // Keep only the most recent mutation per local index: iterate in reverse to retain the
        // last mutation, then reverse again to restore the original execution order.
        for mutation in local_mutations.into_iter().rev() {
            if seen.insert(mutation.local_index) {
                deduped.push(mutation);
            }
        }
        deduped.reverse();

        let mut can_patch_in_place = true;
        for m in &deduped {
            let bit_offset = (m.local_index as usize) * Self::BITS_PER_NODE;
            let old_has_left = self.get_bit(bit_offset);
            let old_has_right = self.get_bit(bit_offset + 1);

            match m.kind {
                LocalMutationKind::Addition { has_left, has_right, .. } => {
                    if old_has_left != has_left || old_has_right != has_right {
                        can_patch_in_place = false;
                    }
                },
                LocalMutationKind::Removal => {
                    if old_has_left || old_has_right {
                        can_patch_in_place = false;
                    }
                },
            }
        }

        Some((deduped, can_patch_in_place))
    }

    /// Patches hashes in-place when the subtree structure is unchanged.
    ///
    /// Called when [`collect_local_mutations`](Self::collect_local_mutations) returns
    /// `can_patch_in_place = true`, meaning all mutations preserve the existing child bits.
    fn patch_hashes_in_place(&mut self, local_mutations: &[LocalMutation]) {
        for m in local_mutations {
            let LocalMutationKind::Addition { left, right, has_left, has_right } = m.kind else {
                continue;
            };
            let bit_offset = (m.local_index as usize) * Self::BITS_PER_NODE;
            let hash_pos = self.count_bits_before(bit_offset);
            if has_left {
                self.hashes[hash_pos] = left;
            }
            if has_right {
                self.hashes[hash_pos + has_left as usize] = right;
            }
        }
    }

    /// Rebuilds the subtree when mutations change the structure.
    ///
    /// Called when [`collect_local_mutations`](Self::collect_local_mutations) returns
    /// `can_patch_in_place = false`, meaning at least one mutation adds or removes child bits.
    /// Performs a merge of sorted existing nodes with sorted mutations.
    fn rebuild_from_mutations(&mut self, mut local_mutations: Vec<LocalMutation>) {
        local_mutations.sort_unstable_by_key(|m| m.local_index);

        let mut new_child_bits = [0u64; 8];
        let mut new_hashes = Vec::with_capacity(self.hashes.len() + local_mutations.len() * 2);

        let mut node_iter = SubtreeNodeIter::new(self);
        let mut current_node = node_iter.next();
        let mut mut_idx = 0;

        loop {
            let node_idx = current_node.as_ref().map(|n| n.local_index);
            let mutation_idx = local_mutations.get(mut_idx).map(|m| m.local_index);

            match (node_idx, mutation_idx) {
                (Some(n), Some(m)) if n < m => {
                    let node = current_node.take().unwrap();
                    self.copy_node(&node, &mut new_child_bits, &mut new_hashes);
                    current_node = node_iter.next();
                },
                (Some(n), Some(m)) if n > m => {
                    Self::write_mutation(
                        &local_mutations[mut_idx],
                        &mut new_child_bits,
                        &mut new_hashes,
                    );
                    mut_idx += 1;
                },
                (Some(_), Some(_)) => {
                    current_node = node_iter.next();
                    Self::write_mutation(
                        &local_mutations[mut_idx],
                        &mut new_child_bits,
                        &mut new_hashes,
                    );
                    mut_idx += 1;
                },
                (Some(_), None) => {
                    let node = current_node.take().unwrap();
                    self.copy_node(&node, &mut new_child_bits, &mut new_hashes);
                    current_node = node_iter.next();
                },
                (None, Some(_)) => {
                    Self::write_mutation(
                        &local_mutations[mut_idx],
                        &mut new_child_bits,
                        &mut new_hashes,
                    );
                    mut_idx += 1;
                },
                (None, None) => break,
            }
        }

        self.child_bits = new_child_bits;
        self.hashes = new_hashes;
    }

    /// Copies a node's hashes to the new subtree being built.
    fn copy_node(&self, node: &SubtreeNode, new_bits: &mut [u64; 8], new_hashes: &mut Vec<Word>) {
        let (word_idx, bit_idx) =
            Self::bit_position((node.local_index as usize) * Self::BITS_PER_NODE);
        if node.has_left {
            new_bits[word_idx] |= 1u64 << bit_idx;
            new_hashes.push(self.hashes[node.hash_start]);
        }
        if node.has_right {
            new_bits[word_idx] |= 1u64 << (bit_idx + 1);
            new_hashes.push(self.hashes[node.hash_start + node.has_left as usize]);
        }
    }

    /// Writes a mutation's data to the new subtree (if it's an addition).
    fn write_mutation(m: &LocalMutation, new_bits: &mut [u64; 8], new_hashes: &mut Vec<Word>) {
        let LocalMutationKind::Addition { left, right, has_left, has_right } = &m.kind else {
            return;
        };
        let (word_idx, bit_idx) =
            Self::bit_position((m.local_index as usize) * Self::BITS_PER_NODE);
        if *has_left {
            new_bits[word_idx] |= 1u64 << bit_idx;
            new_hashes.push(*left);
        }
        if *has_right {
            new_bits[word_idx] |= 1u64 << (bit_idx + 1);
            new_hashes.push(*right);
        }
    }

    /// Splits a bit offset into `(word_idx, bit_idx)` for indexing into `child_bits`.
    #[inline]
    const fn bit_position(bit_offset: usize) -> (usize, usize) {
        (bit_offset / 64, bit_offset & 0b_0011_1111)
    }

    /// Gets a bit from the child_bits array.
    #[inline]
    fn get_bit(&self, bit_offset: usize) -> bool {
        let (word_idx, bit_idx) = Self::bit_position(bit_offset);
        (self.child_bits[word_idx] >> bit_idx) & 1 != 0
    }

    /// Counts the number of set bits before the given bit offset.
    #[inline]
    fn count_bits_before(&self, bit_offset: usize) -> usize {
        let (word_idx, bit_idx) = Self::bit_position(bit_offset);
        let mut count = 0;

        for i in 0..word_idx {
            count += self.child_bits[i].count_ones() as usize;
        }

        if bit_idx > 0 {
            let mask = (1u64 << bit_idx) - 1;
            count += (self.child_bits[word_idx] & mask).count_ones() as usize;
        }

        count
    }

    /// Convert local index to depth within subtree.
    #[inline]
    const fn local_index_to_depth(local_index: u8) -> u8 {
        let n = local_index as u16 + 1;
        (u16::BITS as u8 - 1) - n.leading_zeros() as u8
    }

    /// Returns an iterator over all non-empty nodes in this subtree.
    fn node_iter(&self) -> SubtreeNodeIter<'_> {
        SubtreeNodeIter::new(self)
    }

    /// Returns whether the given mutations would take the patch-in-place path.
    ///
    /// `None` means no mutations to apply; `Some(true)` means patch-in-place;
    /// `Some(false)` means rebuild.
    #[cfg(test)]
    fn would_patch_in_place<'a>(
        &self,
        mutations: impl IntoIterator<Item = (&'a NodeIndex, &'a NodeMutation)>,
    ) -> Option<bool> {
        self.collect_local_mutations(mutations).map(|(_, can_patch)| can_patch)
    }
}
