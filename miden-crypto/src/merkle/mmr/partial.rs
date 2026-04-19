use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString,
    vec::Vec,
};

use super::{MmrDelta, MmrPath, MmrProof};
use crate::{
    Word,
    hash::poseidon2::Poseidon2,
    merkle::{
        InnerNodeInfo, MerklePath,
        mmr::{InOrderIndex, MmrError, MmrPeaks, forest::Forest},
    },
    utils::{ByteReader, ByteWriter, Deserializable, Serializable},
};

// TYPE ALIASES
// ================================================================================================

type NodeMap = BTreeMap<InOrderIndex, Word>;

// PARTIAL MERKLE MOUNTAIN RANGE
// ================================================================================================
/// Partially materialized Merkle Mountain Range (MMR), used to efficiently store and update the
/// authentication paths for a subset of the elements in a full MMR.
///
/// This structure stores both the authentication paths and the leaf values for tracked leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialMmr {
    /// The version of the MMR.
    ///
    /// This value serves the following purposes:
    ///
    /// - The forest is a counter for the total number of elements in the MMR.
    /// - Since the MMR is an append-only structure, every change to it causes a change to the
    ///   `forest`, so this value has a dual purpose as a version tag.
    /// - The bits in the forest also corresponds to the count and size of every perfect binary
    ///   tree that composes the MMR structure, which server to compute indexes and perform
    ///   validation.
    pub(crate) forest: Forest,

    /// The MMR peaks.
    ///
    /// The peaks are used for two reasons:
    ///
    /// 1. It authenticates the addition of an element to the [PartialMmr], ensuring only valid
    ///    elements are tracked.
    /// 2. During a MMR update peaks can be merged by hashing the left and right hand sides. The
    ///    peaks are used as the left hand.
    ///
    /// All the peaks of every tree in the MMR forest. The peaks are always ordered by number of
    /// leaves, starting from the peak with most children, to the one with least.
    pub(crate) peaks: Vec<Word>,

    /// Nodes used to construct merkle paths for a subset of the MMR's leaves.
    ///
    /// This includes both:
    /// - Tracked leaf values at their own in-order index
    /// - Authentication nodes needed for the merkle paths
    ///
    /// The elements in the MMR are referenced using a in-order tree index. This indexing scheme
    /// permits for easy computation of the relative nodes (left/right children, sibling, parent),
    /// which is useful for traversal. The indexing is also stable, meaning that merges to the
    /// trees in the MMR can be represented without rewrites of the indexes.
    pub(crate) nodes: NodeMap,

    /// Set of leaf positions that are being tracked.
    pub(crate) tracked_leaves: BTreeSet<usize>,
}

impl Default for PartialMmr {
    /// Creates a new [PartialMmr] with default values.
    fn default() -> Self {
        let forest = Forest::empty();
        let peaks = Vec::new();
        let nodes = BTreeMap::new();
        let tracked_leaves = BTreeSet::new();

        Self { forest, peaks, nodes, tracked_leaves }
    }
}

impl PartialMmr {
    /// Marker byte separating `nodes` from the tracked leaf vector. This makes format corruption
    /// detectable and prevents ambiguity between adjacent variable-length fields.
    const TRACKED_LEAVES_MARKER: u8 = 0xff;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [PartialMmr] instantiated from the specified peaks.
    pub fn from_peaks(peaks: MmrPeaks) -> Self {
        let forest = peaks.forest();
        let peaks = peaks.into();
        let nodes = BTreeMap::new();
        let tracked_leaves = BTreeSet::new();

        Self { forest, peaks, nodes, tracked_leaves }
    }

    /// Returns a new [PartialMmr] instantiated from the specified components.
    ///
    /// This constructor validates the consistency between peaks, nodes, and tracked_leaves:
    /// - All tracked leaf positions must be within forest bounds.
    /// - All tracked leaves must have their values in the nodes map.
    /// - All node indices must be valid leaf or internal node positions within the forest.
    ///
    /// Note: This performs structural validation only. It does not verify that authentication
    /// paths for tracked leaves are complete or that node values are cryptographically
    /// consistent with the peaks.
    ///
    /// # Errors
    /// Returns an error if the components are inconsistent.
    pub fn from_parts(
        peaks: MmrPeaks,
        nodes: NodeMap,
        tracked_leaves: BTreeSet<usize>,
    ) -> Result<Self, MmrError> {
        let forest = peaks.forest();
        let num_leaves = forest.num_leaves();

        // Validate that all tracked leaf positions are within forest bounds and have values
        for &pos in &tracked_leaves {
            if pos >= num_leaves {
                return Err(MmrError::InconsistentPartialMmr(format!(
                    "tracked leaf position {pos} is out of bounds (forest has {num_leaves} leaves)"
                )));
            }
            let leaf_idx = InOrderIndex::from_leaf_pos(pos);
            if !nodes.contains_key(&leaf_idx) {
                return Err(MmrError::InconsistentPartialMmr(format!(
                    "tracked leaf at position {pos} has no value in nodes"
                )));
            }
        }

        // Validate that all node indices correspond to actual nodes in the forest
        // This catches: empty forest with nodes, index 0, out of bounds, and separator indices
        for idx in nodes.keys() {
            if !forest.is_valid_in_order_index(idx) {
                return Err(MmrError::InconsistentPartialMmr(format!(
                    "node index {} is not a valid index in the forest",
                    idx.inner()
                )));
            }
        }

        let peaks = peaks.into();
        Ok(Self { forest, peaks, nodes, tracked_leaves })
    }

    /// Returns a new [PartialMmr] instantiated from the specified components without validation.
    ///
    /// # Preconditions
    /// This constructor does not check the consistency between peaks, nodes, and tracked_leaves.
    /// If the specified components are inconsistent, the returned partial MMR may exhibit
    /// undefined behavior.
    ///
    /// Use this method only when you are certain the components are valid, for example when
    /// constructing from trusted sources or for performance-critical code paths.
    pub fn from_parts_unchecked(
        peaks: MmrPeaks,
        nodes: NodeMap,
        tracked_leaves: BTreeSet<usize>,
    ) -> Self {
        let forest = peaks.forest();
        let peaks = peaks.into();

        Self { forest, peaks, nodes, tracked_leaves }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the current `forest` of this [PartialMmr].
    ///
    /// This value corresponds to the version of the [PartialMmr] and the number of leaves in the
    /// underlying MMR.
    pub fn forest(&self) -> Forest {
        self.forest
    }

    /// Returns the number of leaves in the underlying MMR for this [PartialMmr].
    pub fn num_leaves(&self) -> usize {
        self.forest.num_leaves()
    }

    /// Returns the peaks of the MMR for this [PartialMmr].
    pub fn peaks(&self) -> MmrPeaks {
        // expect() is OK here because the constructor ensures that MMR peaks can be constructed
        // correctly
        MmrPeaks::new(self.forest, self.peaks.clone()).expect("invalid MMR peaks")
    }

    /// Returns true if this partial MMR tracks an authentication path for the leaf at the
    /// specified position.
    pub fn is_tracked(&self, pos: usize) -> bool {
        self.tracked_leaves.contains(&pos)
    }

    /// Returns the leaf value at the specified position, or `None` if the leaf is not tracked.
    pub fn get(&self, pos: usize) -> Option<Word> {
        if !self.tracked_leaves.contains(&pos) {
            return None;
        }
        let leaf_idx = InOrderIndex::from_leaf_pos(pos);
        self.nodes.get(&leaf_idx).copied()
    }

    /// Returns an iterator over the tracked leaves as (position, value) pairs.
    pub fn leaves(&self) -> impl Iterator<Item = (usize, Word)> + '_ {
        self.tracked_leaves.iter().map(|&pos| {
            let leaf_idx = InOrderIndex::from_leaf_pos(pos);
            let leaf = *self.nodes.get(&leaf_idx).expect("tracked leaf must have value in nodes");
            (pos, leaf)
        })
    }

    /// Returns an [MmrProof] for the leaf at the specified position, or `None` if not tracked.
    ///
    /// Note: The leaf position is the 0-indexed number corresponding to the order the leaves were
    /// added, this corresponds to the MMR size _prior_ to adding the element. So the 1st element
    /// has position 0, the second position 1, and so on.
    ///
    /// # Errors
    /// Returns an error if the specified position is greater-or-equal than the number of leaves
    /// in the underlying MMR.
    pub fn open(&self, pos: usize) -> Result<Option<MmrProof>, MmrError> {
        let tree_bit = self
            .forest
            .leaf_to_corresponding_tree(pos)
            .ok_or(MmrError::PositionNotFound(pos))?;

        // Check if the leaf is tracked
        if !self.tracked_leaves.contains(&pos) {
            return Ok(None);
        }

        // Get the leaf value from nodes
        let leaf_idx = InOrderIndex::from_leaf_pos(pos);
        let leaf = *self.nodes.get(&leaf_idx).expect("tracked leaf must have value in nodes");

        // Collect authentication path nodes
        let depth = tree_bit as usize;
        let mut nodes = Vec::with_capacity(depth);
        let mut idx = leaf_idx;

        for _ in 0..depth {
            let Some(node) = self.nodes.get(&idx.sibling()) else {
                return Err(MmrError::InconsistentPartialMmr(format!(
                    "missing sibling for tracked leaf at position {pos}"
                )));
            };
            nodes.push(*node);
            idx = idx.parent();
        }

        let path = MmrPath::new(self.forest, pos, MerklePath::new(nodes));
        Ok(Some(MmrProof::new(path, leaf)))
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator nodes of all authentication paths of this [PartialMmr].
    pub fn nodes(&self) -> impl Iterator<Item = (&InOrderIndex, &Word)> {
        self.nodes.iter()
    }

    /// Returns an iterator over inner nodes of this [PartialMmr] for the specified leaves.
    ///
    /// The order of iteration is not defined. If a leaf is not presented in this partial MMR it
    /// is silently ignored.
    pub fn inner_nodes<'a, I: Iterator<Item = (usize, Word)> + 'a>(
        &'a self,
        mut leaves: I,
    ) -> impl Iterator<Item = InnerNodeInfo> + 'a {
        let stack = if let Some((pos, leaf)) = leaves.next() {
            let idx = InOrderIndex::from_leaf_pos(pos);
            vec![(idx, leaf)]
        } else {
            Vec::new()
        };

        InnerNodeIterator {
            nodes: &self.nodes,
            leaves,
            stack,
            seen_nodes: BTreeSet::new(),
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds a new peak and optionally track it. Returns a vector of the authentication nodes
    /// inserted into this [PartialMmr] as a result of this operation.
    ///
    /// When `track` is `true` the new leaf is tracked and its value is stored.
    ///
    /// # Errors
    /// Returns an error if the MMR exceeds the maximum supported forest size.
    pub fn add(&mut self, leaf: Word, track: bool) -> Result<Vec<(InOrderIndex, Word)>, MmrError> {
        // Fail early before mutating nodes.
        self.forest.append_leaf()?;
        // The smallest tree height equals the number of merges because adding a leaf is like
        // adding 1 in binary: each carry corresponds to a merge. For example, forest 3 (0b11)
        // + 1 = 4 (0b100) requires 2 carries/merges to form a tree of height 2.
        let num_merges = self.forest.smallest_tree_height_unchecked();
        let mut new_nodes = Vec::with_capacity(num_merges + 1);

        // Store the leaf value at its own index if tracking
        let leaf_pos = self.forest.num_leaves() - 1;
        let leaf_idx = InOrderIndex::from_leaf_pos(leaf_pos);
        if track {
            self.tracked_leaves.insert(leaf_pos);
            self.nodes.insert(leaf_idx, leaf);
            new_nodes.push((leaf_idx, leaf));
        }

        let peak = if num_merges == 0 {
            leaf
        } else {
            let mut track_right = track;
            // Check if the previous dangling leaf was tracked.
            // If num_merges > 0, there was a single-leaf tree that is now being merged.
            let prev_last_pos = self.forest.num_leaves() - 2;
            let mut track_left = self.tracked_leaves.contains(&prev_last_pos);

            let mut right = leaf;
            let mut right_idx = self.forest.rightmost_in_order_index();

            for _ in 0..num_merges {
                let left = self.peaks.pop().expect("Missing peak");
                let left_idx = right_idx.sibling();

                if track_right {
                    let old = self.nodes.insert(left_idx, left);
                    // It's valid to insert if: nothing was there, or same value was there
                    // (tracked leaf value can match auth node for its sibling)
                    debug_assert!(
                        old.is_none() || old == Some(left),
                        "Idx {left_idx:?} already contained a different element {old:?}",
                    );
                    if old.is_none() {
                        new_nodes.push((left_idx, left));
                    }
                };
                if track_left {
                    let old = self.nodes.insert(right_idx, right);
                    debug_assert!(
                        old.is_none() || old == Some(right),
                        "Idx {right_idx:?} already contained a different element {old:?}",
                    );
                    if old.is_none() {
                        new_nodes.push((right_idx, right));
                    }
                };

                // Update state for the next iteration.
                // --------------------------------------------------------------------------------

                // This layer is merged, go up one layer.
                right_idx = right_idx.parent();

                // Merge the current layer. The result is either the right element of the next
                // merge, or a new peak.
                right = Poseidon2::merge(&[left, right]);

                // This iteration merged the left and right nodes, the new value is always used as
                // the next iteration's right node. Therefore the tracking flags of this iteration
                // have to be merged into the right side only.
                track_right = track_right || track_left;

                // On the next iteration, a peak will be merged. If any of its children are tracked,
                // then we have to track the left side
                track_left = self.is_tracked_node(right_idx.sibling());
            }
            right
        };

        self.peaks.push(peak);

        Ok(new_nodes)
    }

    /// Adds the authentication path represented by [MerklePath] if it is valid.
    ///
    /// The `leaf_pos` refers to the global position of the leaf in the MMR, these are 0-indexed
    /// values assigned in a strictly monotonic fashion as elements are inserted into the MMR,
    /// this value corresponds to the values used in the MMR structure.
    ///
    /// The `leaf` corresponds to the value at `leaf_pos`, and `path` is the authentication path for
    /// that element up to its corresponding Mmr peak. Both the authentication path and the leaf
    /// value are stored.
    pub fn track(
        &mut self,
        leaf_pos: usize,
        leaf: Word,
        path: &MerklePath,
    ) -> Result<(), MmrError> {
        // Checks there is a tree with same depth as the authentication path, if not the path is
        // invalid.
        let path_depth = path.depth();
        let tree_leaves =
            1usize.checked_shl(path_depth as u32).ok_or(MmrError::UnknownPeak(path_depth))?;
        let tree = Forest::new(tree_leaves).map_err(|_| MmrError::UnknownPeak(path_depth))?;
        if (tree & self.forest).is_empty() {
            return Err(MmrError::UnknownPeak(path_depth));
        };

        // ignore the trees smaller than the target (these elements are position after the current
        // target and don't affect the target leaf_pos)
        let target_forest = self.forest ^ (self.forest & tree.all_smaller_trees_unchecked());
        let peak_pos = target_forest.num_trees() - 1;

        // translate from mmr leaf_pos to merkle path
        let path_idx = leaf_pos - (target_forest ^ tree).num_leaves();

        // Compute the root of the authentication path, and check it matches the current version of
        // the PartialMmr.
        let computed = path
            .compute_root(path_idx as u64, leaf)
            .map_err(MmrError::MerkleRootComputationFailed)?;
        if self.peaks[peak_pos] != computed {
            return Err(MmrError::PeakPathMismatch);
        }

        // Mark the leaf as tracked
        self.tracked_leaves.insert(leaf_pos);

        // Store the leaf value at its own index
        let leaf_idx = InOrderIndex::from_leaf_pos(leaf_pos);
        self.nodes.insert(leaf_idx, leaf);

        // Store the authentication path nodes
        let mut idx = leaf_idx;
        for node in path.nodes() {
            self.nodes.insert(idx.sibling(), *node);
            idx = idx.parent();
        }

        Ok(())
    }

    /// Removes a leaf of the [PartialMmr] and the unused nodes from the authentication path.
    ///
    /// Returns a vector of the authentication nodes removed from this [PartialMmr] as a result
    /// of this operation. This is useful for client-side pruning, where the caller needs to know
    /// which nodes can be deleted from storage.
    ///
    /// Note: `leaf_pos` corresponds to the position in the MMR and not on an individual tree.
    /// If `leaf_pos` is invalid for the current forest, this method returns an empty vector.
    pub fn untrack(&mut self, leaf_pos: usize) -> Vec<(InOrderIndex, Word)> {
        // Remove from tracked leaves set
        self.tracked_leaves.remove(&leaf_pos);

        let mut idx = InOrderIndex::from_leaf_pos(leaf_pos);
        let mut removed = Vec::new();

        // Check if the sibling leaf is still tracked. If so, we need to keep our leaf value
        // as an auth node for the sibling, and keep all auth nodes above.
        let sibling_idx = idx.sibling();
        let sibling_pos = sibling_idx.to_leaf_pos().expect("sibling of a leaf is always a leaf");
        if self.tracked_leaves.contains(&sibling_pos) {
            // Sibling is tracked, so don't remove anything - our leaf value and all auth
            // nodes above are still needed for the sibling's proof.
            return removed;
        }

        let Some(rel_pos) = self.forest.leaf_relative_position(leaf_pos) else {
            // Invalid MMR leaf position - treat as a no-op.
            return removed;
        };
        let tree_start = leaf_pos - rel_pos;

        // Remove the leaf value itself
        if let Some(word) = self.nodes.remove(&idx) {
            removed.push((idx, word));
        }

        // Remove authentication path nodes that are no longer needed.
        loop {
            // At each level, identify the subtree covered by `idx`. If any tracked leaf still
            // exists in this range, nodes above this point are still required.
            let level = idx.level() as usize;
            let subtree_size = 1usize << level;
            let subtree_start_rel = (rel_pos >> level) << level;
            let subtree_start = tree_start + subtree_start_rel;
            let subtree_end = subtree_start + subtree_size;
            if self.tracked_leaves.range(subtree_start..subtree_end).next().is_some() {
                break;
            }

            let sibling_idx = idx.sibling();

            // Try to remove the sibling auth node
            let Some(word) = self.nodes.remove(&sibling_idx) else {
                break;
            };
            removed.push((sibling_idx, word));

            // If `idx` is present, it was added for another element's authentication.
            if self.nodes.contains_key(&idx) {
                break;
            }
            idx = idx.parent();
        }

        removed
    }

    /// Applies updates to this [PartialMmr] and returns a vector of new authentication nodes
    /// inserted into the partial MMR.
    pub fn apply(&mut self, delta: MmrDelta) -> Result<Vec<(InOrderIndex, Word)>, MmrError> {
        if delta.forest < self.forest {
            return Err(MmrError::InvalidPeaks(format!(
                "forest of mmr delta {} is less than current forest {}",
                delta.forest, self.forest
            )));
        }

        let mut inserted_nodes = Vec::new();

        if delta.forest == self.forest {
            if !delta.data.is_empty() {
                return Err(MmrError::InvalidUpdate);
            }

            return Ok(inserted_nodes);
        }

        // find the trees to merge (bitmask of existing trees that will be combined)
        let changes = self.forest.num_leaves() ^ delta.forest.num_leaves();
        // `largest_tree_unchecked()` panics if `changes` is empty. `changes` cannot be empty
        // unless `self.forest == delta.forest`, which is guarded against above.
        let largest = super::forest::largest_tree_from_mask(changes);
        // The largest tree itself also cannot be an empty forest, so this cannot panic either.
        let trees_to_merge = self.forest & largest.all_smaller_trees_unchecked();

        // count the number elements needed to produce largest from the current state
        let (merge_count, new_peaks) = if !trees_to_merge.is_empty() {
            let depth = largest.smallest_tree_height_unchecked();
            // `trees_to_merge` also cannot be an empty forest, so this cannot panic either.
            let skipped = trees_to_merge.smallest_tree_height_unchecked();
            let computed = trees_to_merge.num_trees() - 1;
            let merge_count = depth - skipped - computed;

            let new_peaks = delta.forest & largest.all_smaller_trees_unchecked();

            (merge_count, new_peaks)
        } else {
            let new_peaks = Forest::new(changes)
                .expect("changes must be a valid forest under apply invariants");
            (0, new_peaks)
        };

        // verify the delta size
        if delta.data.len() != merge_count + new_peaks.num_trees() {
            return Err(MmrError::InvalidUpdate);
        }

        // keeps track of how many data elements from the update have been consumed
        let mut update_count = 0;

        if !trees_to_merge.is_empty() {
            // starts at the smallest peak and follows the merged peaks
            let mut peak_idx = self.forest.root_in_order_index();

            // match order of the update data while applying it
            self.peaks.reverse();

            let mut track = false;

            let mut peak_count = 0;
            let mut target = trees_to_merge.smallest_tree_unchecked();
            let mut new = delta.data[0];
            update_count += 1;

            while target < largest {
                // Check if either the left or right subtrees have nodes saved for authentication
                // paths. If so, turn tracking on to update those paths.
                if !track {
                    track = self.is_tracked_node(peak_idx);
                }

                // update data only contains the nodes from the right subtrees, left nodes are
                // either previously known peaks or computed values
                let (left, right) = if !(target & trees_to_merge).is_empty() {
                    let peak = self.peaks[peak_count];
                    let sibling_idx = peak_idx.sibling();

                    // if the sibling peak is tracked, add this peaks to the set of
                    // authentication nodes
                    if self.is_tracked_node(sibling_idx) {
                        self.nodes.insert(peak_idx, new);
                        inserted_nodes.push((peak_idx, new));
                    }
                    peak_count += 1;
                    (peak, new)
                } else {
                    let update = delta.data[update_count];
                    update_count += 1;
                    (new, update)
                };

                if track {
                    let sibling_idx = peak_idx.sibling();
                    if peak_idx.is_left_child() {
                        self.nodes.insert(sibling_idx, right);
                        inserted_nodes.push((sibling_idx, right));
                    } else {
                        self.nodes.insert(sibling_idx, left);
                        inserted_nodes.push((sibling_idx, left));
                    }
                }

                peak_idx = peak_idx.parent();
                new = Poseidon2::merge(&[left, right]);
                target = target.next_larger_tree()?;
            }

            debug_assert!(peak_count == trees_to_merge.num_trees());

            // restore the peaks order
            self.peaks.reverse();
            // remove the merged peaks
            self.peaks.truncate(self.peaks.len() - peak_count);
            // add the newly computed peak, the result of the tree merges
            self.peaks.push(new);
        }

        // The rest of the update data is composed of peaks. None of these elements can contain
        // tracked elements because the peaks were unknown, and it is not possible to add elements
        // for tacking without authenticating it to a peak.
        self.peaks.extend_from_slice(&delta.data[update_count..]);
        self.forest = delta.forest;

        debug_assert!(self.peaks.len() == self.forest.num_trees());

        Ok(inserted_nodes)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns true if this [PartialMmr] tracks authentication path for the node at the specified
    /// index.
    fn is_tracked_node(&self, node_index: InOrderIndex) -> bool {
        if let Some(leaf_pos) = node_index.to_leaf_pos() {
            // For leaf nodes, check if the leaf is in the tracked set.
            self.tracked_leaves.contains(&leaf_pos)
        } else {
            let left_child = node_index.left_child();
            let right_child = node_index.right_child();
            self.nodes.contains_key(&left_child) | self.nodes.contains_key(&right_child)
        }
    }
}

// CONVERSIONS
// ================================================================================================

impl From<MmrPeaks> for PartialMmr {
    fn from(peaks: MmrPeaks) -> Self {
        Self::from_peaks(peaks)
    }
}

impl From<PartialMmr> for MmrPeaks {
    fn from(partial_mmr: PartialMmr) -> Self {
        // Safety: the [PartialMmr] maintains the constraints the number of true bits in the forest
        // matches the number of peaks, as required by the [MmrPeaks]
        MmrPeaks::new(partial_mmr.forest, partial_mmr.peaks).unwrap()
    }
}

impl From<&MmrPeaks> for PartialMmr {
    fn from(peaks: &MmrPeaks) -> Self {
        Self::from_peaks(peaks.clone())
    }
}

impl From<&PartialMmr> for MmrPeaks {
    fn from(partial_mmr: &PartialMmr) -> Self {
        // Safety: the [PartialMmr] maintains the constraints the number of true bits in the forest
        // matches the number of peaks, as required by the [MmrPeaks]
        MmrPeaks::new(partial_mmr.forest, partial_mmr.peaks.clone()).unwrap()
    }
}

// ITERATORS
// ================================================================================================

/// An iterator over every inner node of the [PartialMmr].
pub struct InnerNodeIterator<'a, I: Iterator<Item = (usize, Word)>> {
    nodes: &'a NodeMap,
    leaves: I,
    stack: Vec<(InOrderIndex, Word)>,
    seen_nodes: BTreeSet<InOrderIndex>,
}

impl<I: Iterator<Item = (usize, Word)>> Iterator for InnerNodeIterator<'_, I> {
    type Item = InnerNodeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((idx, node)) = self.stack.pop() {
            let parent_idx = idx.parent();
            let new_node = self.seen_nodes.insert(parent_idx);

            // if we haven't seen this node's parent before, and the node has a sibling, return
            // the inner node defined by the parent of this node, and move up the branch
            if new_node && let Some(sibling) = self.nodes.get(&idx.sibling()) {
                let (left, right) = if parent_idx.left_child() == idx {
                    (node, *sibling)
                } else {
                    (*sibling, node)
                };
                let parent = Poseidon2::merge(&[left, right]);
                let inner_node = InnerNodeInfo { value: parent, left, right };

                self.stack.push((parent_idx, parent));
                return Some(inner_node);
            }

            // the previous leaf has been processed, try to process the next leaf
            if let Some((pos, leaf)) = self.leaves.next() {
                let idx = InOrderIndex::from_leaf_pos(pos);
                self.stack.push((idx, leaf));
            }
        }

        None
    }
}

impl Serializable for PartialMmr {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.forest.num_leaves().write_into(target);
        self.peaks.write_into(target);
        self.nodes.write_into(target);
        // Write a marker before tracked leaves to guard against malformed/truncated payloads.
        target.write_u8(Self::TRACKED_LEAVES_MARKER);
        let tracked: Vec<usize> = self.tracked_leaves.iter().copied().collect();
        tracked.write_into(target);
    }
}

impl Deserializable for PartialMmr {
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> Result<Self, crate::utils::DeserializationError> {
        use crate::utils::DeserializationError;

        let forest = Forest::new(usize::read_from(source)?)?;
        let peaks_vec = Vec::<Word>::read_from(source)?;
        let nodes = NodeMap::read_from(source)?;
        if !source.has_more_bytes() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        let marker = source.read_u8()?;
        if marker != Self::TRACKED_LEAVES_MARKER {
            return Err(DeserializationError::InvalidValue(
                "unknown partial mmr serialization format".to_string(),
            ));
        }
        let tracked: Vec<usize> = Vec::read_from(source)?;
        let tracked_leaves: BTreeSet<usize> = tracked.into_iter().collect();

        // Construct MmrPeaks to validate forest/peaks consistency
        let peaks = MmrPeaks::new(forest, peaks_vec).map_err(|e| {
            DeserializationError::InvalidValue(format!("invalid partial mmr peaks: {e}"))
        })?;

        // Use validating constructor
        Self::from_parts(peaks, nodes, tracked_leaves)
            .map_err(|e| DeserializationError::InvalidValue(format!("invalid partial mmr: {e}")))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{
        collections::{BTreeMap, BTreeSet},
        vec::Vec,
    };

    use super::{MmrPeaks, PartialMmr};
    use crate::{
        Word,
        merkle::{
            NodeIndex, int_to_node,
            mmr::{InOrderIndex, Mmr, forest::Forest},
            store::MerkleStore,
        },
        utils::{ByteWriter, Deserializable, DeserializationError, Serializable},
    };

    const LEAVES: [Word; 7] = [
        int_to_node(0),
        int_to_node(1),
        int_to_node(2),
        int_to_node(3),
        int_to_node(4),
        int_to_node(5),
        int_to_node(6),
    ];

    #[test]
    fn test_partial_mmr_apply_delta() {
        // build an MMR with 10 nodes (2 peaks) and a partial MMR based on it
        let mut mmr = Mmr::default();
        (0..10).for_each(|i| mmr.add(int_to_node(i)).unwrap());
        let mut partial_mmr: PartialMmr = mmr.peaks().into();

        // add authentication path for position 1 and 8
        {
            let node = mmr.get(1).unwrap();
            let proof = mmr.open(1).unwrap();
            partial_mmr.track(1, node, proof.path().merkle_path()).unwrap();
        }

        {
            let node = mmr.get(8).unwrap();
            let proof = mmr.open(8).unwrap();
            partial_mmr.track(8, node, proof.path().merkle_path()).unwrap();
        }

        // add 2 more nodes into the MMR and validate apply_delta()
        (10..12).for_each(|i| mmr.add(int_to_node(i)).unwrap());
        validate_apply_delta(&mmr, &mut partial_mmr);

        // add 1 more node to the MMR, validate apply_delta() and start tracking the node
        mmr.add(int_to_node(12)).unwrap();
        validate_apply_delta(&mmr, &mut partial_mmr);
        {
            let node = mmr.get(12).unwrap();
            let proof = mmr.open(12).unwrap();
            partial_mmr.track(12, node, proof.path().merkle_path()).unwrap();
            // Position 12 is the last leaf (dangling) and should now be tracked
            assert!(partial_mmr.is_tracked(12));
        }

        // by this point we are tracking authentication paths for positions: 1, 8, and 12

        // add 3 more nodes to the MMR (collapses to 1 peak) and validate apply_delta()
        (13..16).for_each(|i| mmr.add(int_to_node(i)).unwrap());
        validate_apply_delta(&mmr, &mut partial_mmr);
    }

    fn validate_apply_delta(mmr: &Mmr, partial: &mut PartialMmr) {
        // Get tracked leaf positions
        let tracked_positions: Vec<_> = partial.tracked_leaves.iter().copied().collect();
        let nodes_before = partial.nodes.clone();

        // compute and apply delta
        let delta = mmr.get_delta(partial.forest(), mmr.forest()).unwrap();
        let nodes_delta = partial.apply(delta).unwrap();

        // new peaks were computed correctly
        assert_eq!(mmr.peaks(), partial.peaks());

        let mut expected_nodes = nodes_before;
        for (key, value) in nodes_delta {
            // nodes should not be duplicated
            assert!(expected_nodes.insert(key, value).is_none());
        }

        // new nodes should be a combination of original nodes and delta
        assert_eq!(expected_nodes, partial.nodes);

        // make sure tracked leaves open to the same proofs as in the underlying MMR
        for pos in tracked_positions {
            let proof1 = partial.open(pos).unwrap().unwrap();
            let proof2 = mmr.open(pos).unwrap();
            assert_eq!(proof1, proof2);
        }
    }

    #[test]
    fn test_partial_mmr_inner_nodes_iterator() {
        // build the MMR
        let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();
        let first_peak = mmr.peaks().peaks()[0];

        // -- test single tree ----------------------------

        // get path and node for position 1
        let node1 = mmr.get(1).unwrap();
        let proof1 = mmr.open(1).unwrap();

        // create partial MMR and add authentication path to node at position 1
        let mut partial_mmr: PartialMmr = mmr.peaks().into();
        partial_mmr.track(1, node1, proof1.path().merkle_path()).unwrap();

        // empty iterator should have no nodes
        assert_eq!(partial_mmr.inner_nodes([].iter().cloned()).next(), None);

        // build Merkle store from authentication paths in partial MMR
        let mut store: MerkleStore = MerkleStore::new();
        store.extend(partial_mmr.inner_nodes([(1, node1)].iter().cloned()));

        let index1 = NodeIndex::new(2, 1).unwrap();
        let path1 = store.get_path(first_peak, index1).unwrap().path;

        assert_eq!(path1, *proof1.path().merkle_path());

        // -- test no duplicates --------------------------

        // build the partial MMR
        let mut partial_mmr: PartialMmr = mmr.peaks().into();

        let node0 = mmr.get(0).unwrap();
        let proof0 = mmr.open(0).unwrap();

        let node2 = mmr.get(2).unwrap();
        let proof2 = mmr.open(2).unwrap();

        partial_mmr.track(0, node0, proof0.path().merkle_path()).unwrap();
        partial_mmr.track(1, node1, proof1.path().merkle_path()).unwrap();
        partial_mmr.track(2, node2, proof2.path().merkle_path()).unwrap();

        // make sure there are no duplicates
        let leaves = [(0, node0), (1, node1), (2, node2)];
        let mut nodes = BTreeSet::new();
        for node in partial_mmr.inner_nodes(leaves.iter().cloned()) {
            assert!(nodes.insert(node.value));
        }

        // and also that the store is still be built correctly
        store.extend(partial_mmr.inner_nodes(leaves.iter().cloned()));

        let index0 = NodeIndex::new(2, 0).unwrap();
        let index1 = NodeIndex::new(2, 1).unwrap();
        let index2 = NodeIndex::new(2, 2).unwrap();

        let path0 = store.get_path(first_peak, index0).unwrap().path;
        let path1 = store.get_path(first_peak, index1).unwrap().path;
        let path2 = store.get_path(first_peak, index2).unwrap().path;

        assert_eq!(path0, *proof0.path().merkle_path());
        assert_eq!(path1, *proof1.path().merkle_path());
        assert_eq!(path2, *proof2.path().merkle_path());

        // -- test multiple trees -------------------------

        // build the partial MMR
        let mut partial_mmr: PartialMmr = mmr.peaks().into();

        let node5 = mmr.get(5).unwrap();
        let proof5 = mmr.open(5).unwrap();

        partial_mmr.track(1, node1, proof1.path().merkle_path()).unwrap();
        partial_mmr.track(5, node5, proof5.path().merkle_path()).unwrap();

        // build Merkle store from authentication paths in partial MMR
        let mut store: MerkleStore = MerkleStore::new();
        store.extend(partial_mmr.inner_nodes([(1, node1), (5, node5)].iter().cloned()));

        let index1 = NodeIndex::new(2, 1).unwrap();
        let index5 = NodeIndex::new(1, 1).unwrap();

        let second_peak = mmr.peaks().peaks()[1];

        let path1 = store.get_path(first_peak, index1).unwrap().path;
        let path5 = store.get_path(second_peak, index5).unwrap().path;

        assert_eq!(path1, *proof1.path().merkle_path());
        assert_eq!(path5, *proof5.path().merkle_path());
    }

    #[test]
    fn test_partial_mmr_add_without_track() {
        let mut mmr = Mmr::default();
        let empty_peaks = MmrPeaks::new(Forest::empty(), vec![]).unwrap();
        let mut partial_mmr = PartialMmr::from_peaks(empty_peaks);

        for el in (0..256).map(int_to_node) {
            mmr.add(el).unwrap();
            partial_mmr.add(el, false).unwrap();

            assert_eq!(mmr.peaks(), partial_mmr.peaks());
            assert_eq!(mmr.forest(), partial_mmr.forest());
        }
    }

    #[test]
    fn test_partial_mmr_add_with_track() {
        let mut mmr = Mmr::default();
        let empty_peaks = MmrPeaks::new(Forest::empty(), vec![]).unwrap();
        let mut partial_mmr = PartialMmr::from_peaks(empty_peaks);

        for i in 0..256 {
            let el = int_to_node(i as u64);
            mmr.add(el).unwrap();
            partial_mmr.add(el, true).unwrap();

            assert_eq!(mmr.peaks(), partial_mmr.peaks());
            assert_eq!(mmr.forest(), partial_mmr.forest());

            for pos in 0..i {
                let mmr_proof = mmr.open(pos).unwrap();
                let partialmmr_proof = partial_mmr.open(pos).unwrap().unwrap();
                assert_eq!(mmr_proof, partialmmr_proof);
            }
        }
    }

    #[test]
    fn test_partial_mmr_add_existing_track() {
        let mut mmr = Mmr::try_from_iter((0..7).map(int_to_node)).unwrap();

        // derive a partial Mmr from it which tracks authentication path to leaf 5
        let mut partial_mmr = PartialMmr::from_peaks(mmr.peaks());
        let path_to_5 = mmr.open(5).unwrap().path().merkle_path().clone();
        let leaf_at_5 = mmr.get(5).unwrap();
        partial_mmr.track(5, leaf_at_5, &path_to_5).unwrap();

        // add a new leaf to both Mmr and partial Mmr
        let leaf_at_7 = int_to_node(7);
        mmr.add(leaf_at_7).unwrap();
        partial_mmr.add(leaf_at_7, false).unwrap();

        // the openings should be the same
        assert_eq!(mmr.open(5).unwrap(), partial_mmr.open(5).unwrap().unwrap());
    }

    #[test]
    fn test_partial_mmr_add_updates_tracked_dangling_leaf() {
        // Track a dangling leaf, then add a new untracked leaf.
        // The previously dangling leaf's proof should still work.
        let mut mmr = Mmr::default();
        let mut partial_mmr = PartialMmr::default();

        // Add leaf 0 with tracking - it's a dangling leaf (forest=1)
        let leaf0 = int_to_node(0);
        mmr.add(leaf0).unwrap();
        partial_mmr.add(leaf0, true).unwrap();

        // Both should produce the same proof (empty path, leaf is a peak)
        assert_eq!(mmr.open(0).unwrap(), partial_mmr.open(0).unwrap().unwrap());

        // Add leaf 1 WITHOUT tracking - triggers merge, leaf 0 gets a sibling
        let leaf1 = int_to_node(1);
        mmr.add(leaf1).unwrap();
        partial_mmr.add(leaf1, false).unwrap();

        // Leaf 0 should still be tracked with correct proof after merge
        assert!(partial_mmr.is_tracked(0));
        assert!(!partial_mmr.is_tracked(1));
        assert_eq!(mmr.open(0).unwrap(), partial_mmr.open(0).unwrap().unwrap());
    }

    #[test]
    fn test_partial_mmr_serialization() {
        let mmr = Mmr::try_from_iter((0..7).map(int_to_node)).unwrap();
        let partial_mmr = PartialMmr::from_peaks(mmr.peaks());

        let bytes = partial_mmr.to_bytes();
        let decoded = PartialMmr::read_from_bytes(&bytes).unwrap();

        assert_eq!(partial_mmr, decoded);
    }

    #[test]
    fn test_partial_mmr_deserialization_rejects_large_forest() {
        let mut bytes = (Forest::MAX_LEAVES + 1).to_bytes();
        bytes.extend_from_slice(&0usize.to_bytes()); // empty peaks vec
        bytes.extend_from_slice(&0usize.to_bytes()); // empty nodes map
        bytes.extend_from_slice(&0usize.to_bytes()); // empty tracked vec

        let result = PartialMmr::read_from_bytes(&bytes);
        assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
    }

    #[test]
    fn test_partial_mmr_untrack() {
        // build the MMR
        let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();

        // get path and node for position 1
        let node1 = mmr.get(1).unwrap();
        let proof1 = mmr.open(1).unwrap();

        // get path and node for position 2
        let node2 = mmr.get(2).unwrap();
        let proof2 = mmr.open(2).unwrap();

        // create partial MMR and add authentication path to nodes at position 1 and 2
        let mut partial_mmr: PartialMmr = mmr.peaks().into();
        partial_mmr.track(1, node1, proof1.path().merkle_path()).unwrap();
        partial_mmr.track(2, node2, proof2.path().merkle_path()).unwrap();

        // untrack nodes at positions 1 and 2
        partial_mmr.untrack(1);
        partial_mmr.untrack(2);

        // nodes should not longer be tracked
        assert!(!partial_mmr.is_tracked(1));
        assert!(!partial_mmr.is_tracked(2));
        assert_eq!(partial_mmr.nodes().count(), 0);
    }

    #[test]
    fn test_partial_mmr_untrack_returns_removed_nodes() {
        // build the MMR
        let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();

        // get path and node for position 1
        let node1 = mmr.get(1).unwrap();
        let proof1 = mmr.open(1).unwrap();

        // create partial MMR
        let mut partial_mmr: PartialMmr = mmr.peaks().into();

        // add authentication path for position 1
        partial_mmr.track(1, node1, proof1.path().merkle_path()).unwrap();

        // collect nodes before untracking
        let nodes_before: BTreeSet<_> =
            partial_mmr.nodes().map(|(&idx, &word)| (idx, word)).collect();

        // untrack and capture removed nodes
        let removed: BTreeSet<_> = partial_mmr.untrack(1).into_iter().collect();

        // verify that all nodes that were in the partial MMR were returned
        assert_eq!(removed, nodes_before);

        // verify that partial MMR is now empty
        assert!(!partial_mmr.is_tracked(1));
        assert_eq!(partial_mmr.nodes().count(), 0);
    }

    #[test]
    fn test_partial_mmr_untrack_shared_nodes() {
        // build the MMR
        let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();

        // track two sibling leaves (positions 0 and 1)
        let node0 = mmr.get(0).unwrap();
        let proof0 = mmr.open(0).unwrap();

        let node1 = mmr.get(1).unwrap();
        let proof1 = mmr.open(1).unwrap();

        // create partial MMR
        let mut partial_mmr: PartialMmr = mmr.peaks().into();

        // add authentication paths for position 0 and 1
        partial_mmr.track(0, node0, proof0.path().merkle_path()).unwrap();
        partial_mmr.track(1, node1, proof1.path().merkle_path()).unwrap();

        // There are 3 unique nodes stored in `nodes`:
        // - nodes[idx0] = leaf0 (tracked leaf value, also serves as auth sibling for leaf1)
        // - nodes[idx1] = leaf1 (tracked leaf value, also serves as auth sibling for leaf0)
        // - nodes[parent_sibling] = shared higher-level auth node
        //
        // Note: Each tracked leaf's value is stored at its own InOrderIndex so that `open()`
        // can return an MmrProof containing the leaf value. These values also double as the
        // authentication siblings for their neighboring leaves.
        assert_eq!(partial_mmr.nodes().count(), 3);

        // untrack position 0:
        // Even though pos 0 is no longer tracked, we cannot remove any nodes because:
        // - leaf0's value (at idx0) is still needed as the auth sibling for leaf1's path
        // - leaf1's value (at idx1) is needed for open(1) to return MmrProof
        // - parent_sibling is still needed for leaf1's path
        let removed0 = partial_mmr.untrack(0);
        assert_eq!(removed0.len(), 0);
        assert_eq!(partial_mmr.nodes().count(), 3);
        assert!(partial_mmr.is_tracked(1));
        assert!(!partial_mmr.is_tracked(0));

        // untrack position 1:
        // Now sibling (pos 0) is NOT tracked, so all nodes can be removed:
        // - leaf1's value at idx1 (no longer needed for open())
        // - leaf0's value at idx0 (no longer needed as auth sibling)
        // - parent_sibling (no longer needed for any path)
        let removed1 = partial_mmr.untrack(1);
        assert_eq!(removed1.len(), 3);
        assert_eq!(partial_mmr.nodes().count(), 0);
        assert!(!partial_mmr.is_tracked(1));
    }

    #[test]
    fn test_partial_mmr_untrack_preserves_upper_siblings() {
        let mut mmr = Mmr::default();
        (0..8).for_each(|i| mmr.add(int_to_node(i)).unwrap());

        let mut partial_mmr: PartialMmr = mmr.peaks().into();
        for pos in [0, 2] {
            let node = mmr.get(pos).unwrap();
            let proof = mmr.open(pos).unwrap();
            partial_mmr.track(pos, node, proof.path().merkle_path()).unwrap();
        }

        partial_mmr.untrack(0);

        let proof_partial = partial_mmr.open(2).unwrap().unwrap();
        let proof_full = mmr.open(2).unwrap();
        assert_eq!(proof_partial, proof_full);
    }

    #[test]
    fn test_partial_mmr_deserialize_missing_marker_fails() {
        let mut mmr = Mmr::default();
        (0..3).for_each(|i| mmr.add(int_to_node(i)).unwrap());
        let peaks = mmr.peaks();

        let mut bytes = Vec::new();
        peaks.num_leaves().write_into(&mut bytes);
        peaks.peaks().to_vec().write_into(&mut bytes);
        BTreeMap::<InOrderIndex, Word>::new().write_into(&mut bytes);
        assert!(PartialMmr::read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_partial_mmr_deserialize_invalid_marker_fails() {
        let mut mmr = Mmr::default();
        (0..3).for_each(|i| mmr.add(int_to_node(i)).unwrap());
        let peaks = mmr.peaks();

        let mut bytes = Vec::new();
        peaks.num_leaves().write_into(&mut bytes);
        peaks.peaks().to_vec().write_into(&mut bytes);
        BTreeMap::<InOrderIndex, Word>::new().write_into(&mut bytes);
        bytes.write_u8(0x7f);
        Vec::<usize>::new().write_into(&mut bytes);

        assert!(PartialMmr::read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_partial_mmr_open_returns_proof_with_leaf() {
        // build the MMR
        let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();

        // get leaf and proof for position 1
        let leaf1 = mmr.get(1).unwrap();
        let mmr_proof = mmr.open(1).unwrap();

        // create partial MMR and track position 1
        let mut partial_mmr: PartialMmr = mmr.peaks().into();
        partial_mmr.track(1, leaf1, mmr_proof.path().merkle_path()).unwrap();

        // open should return MmrProof with the correct leaf value
        let partial_proof = partial_mmr.open(1).unwrap().unwrap();
        assert_eq!(partial_proof.leaf(), leaf1);
        assert_eq!(partial_proof, mmr_proof);

        // untrack and verify open returns None
        partial_mmr.untrack(1);
        assert!(partial_mmr.open(1).unwrap().is_none());
    }

    #[test]
    fn test_partial_mmr_add_tracks_leaf() {
        // create empty partial MMR
        let mut partial_mmr = PartialMmr::default();

        // add leaves, tracking some
        let leaf0 = int_to_node(0);
        let leaf1 = int_to_node(1);
        let leaf2 = int_to_node(2);

        partial_mmr.add(leaf0, true).unwrap(); // track
        partial_mmr.add(leaf1, false).unwrap(); // don't track
        partial_mmr.add(leaf2, true).unwrap(); // track

        // verify tracked leaves can be opened
        let proof0 = partial_mmr.open(0).unwrap();
        assert!(proof0.is_some());
        assert_eq!(proof0.unwrap().leaf(), leaf0);

        // verify untracked leaf returns None
        let proof1 = partial_mmr.open(1).unwrap();
        assert!(proof1.is_none());

        // verify tracked leaf can be opened
        let proof2 = partial_mmr.open(2).unwrap();
        assert!(proof2.is_some());
        assert_eq!(proof2.unwrap().leaf(), leaf2);

        // verify get() returns correct values
        assert_eq!(partial_mmr.get(0), Some(leaf0));
        assert_eq!(partial_mmr.get(1), None);
        assert_eq!(partial_mmr.get(2), Some(leaf2));

        // verify leaves() iterator returns only tracked leaves
        let tracked: Vec<_> = partial_mmr.leaves().collect();
        assert_eq!(tracked, vec![(0, leaf0), (2, leaf2)]);
    }

    #[test]
    fn test_partial_mmr_track_dangling_leaf() {
        // Single-leaf MMR: forest = 1, leaf 0 is a peak with an empty path.
        let mut mmr = Mmr::default();
        mmr.add(int_to_node(0)).unwrap();
        let mut partial_mmr: PartialMmr = mmr.peaks().into();

        let leaf0 = mmr.get(0).unwrap();
        // depth-0 MerklePath
        let proof0 = mmr.open(0).unwrap();

        // Track the dangling leaf via `track` using the empty path.
        partial_mmr.track(0, leaf0, proof0.path().merkle_path()).unwrap();

        // It should now be tracked and open to the same proof as the full MMR.
        assert!(partial_mmr.is_tracked(0));
        assert_eq!(partial_mmr.open(0).unwrap().unwrap(), proof0);
    }

    #[test]
    fn test_from_parts_validation() {
        use alloc::collections::BTreeMap;

        use super::InOrderIndex;

        // Build a valid MMR with 7 leaves
        let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();
        let peaks = mmr.peaks();

        // Valid case: empty nodes and empty tracked_leaves
        let result = PartialMmr::from_parts(peaks.clone(), BTreeMap::new(), BTreeSet::new());
        assert!(result.is_ok());

        // Invalid case: tracked leaf position out of bounds
        let mut out_of_bounds = BTreeSet::new();
        out_of_bounds.insert(100);
        let result = PartialMmr::from_parts(peaks.clone(), BTreeMap::new(), out_of_bounds);
        assert!(result.is_err());

        // Invalid case: tracked leaf has no value in nodes
        let mut tracked_no_value = BTreeSet::new();
        tracked_no_value.insert(0);
        let result = PartialMmr::from_parts(peaks.clone(), BTreeMap::new(), tracked_no_value);
        assert!(result.is_err());

        // Valid case: tracked leaf with its value in nodes
        let mut nodes_with_leaf = BTreeMap::new();
        let leaf_idx = InOrderIndex::from_leaf_pos(0);
        nodes_with_leaf.insert(leaf_idx, int_to_node(0));
        let mut tracked_valid = BTreeSet::new();
        tracked_valid.insert(0);
        let result = PartialMmr::from_parts(peaks.clone(), nodes_with_leaf, tracked_valid);
        assert!(result.is_ok());

        // Invalid case: node index out of bounds (leaf index)
        let mut invalid_nodes = BTreeMap::new();
        let invalid_idx = InOrderIndex::from_leaf_pos(100); // way out of bounds
        invalid_nodes.insert(invalid_idx, int_to_node(0));
        let result = PartialMmr::from_parts(peaks.clone(), invalid_nodes, BTreeSet::new());
        assert!(result.is_err());

        // Invalid case: index 0 (which is never valid for InOrderIndex)
        let mut nodes_with_zero = BTreeMap::new();
        // Create an InOrderIndex with value 0 via deserialization
        let zero_idx = InOrderIndex::read_from_bytes(&0usize.to_bytes()).unwrap();
        nodes_with_zero.insert(zero_idx, int_to_node(0));
        let result = PartialMmr::from_parts(peaks.clone(), nodes_with_zero, BTreeSet::new());
        assert!(result.is_err());

        // Invalid case: large even index (internal node) beyond forest bounds
        let mut nodes_with_large_even = BTreeMap::new();
        let large_even_idx = InOrderIndex::read_from_bytes(&1000usize.to_bytes()).unwrap();
        nodes_with_large_even.insert(large_even_idx, int_to_node(0));
        let result = PartialMmr::from_parts(peaks.clone(), nodes_with_large_even, BTreeSet::new());
        assert!(result.is_err());

        // Invalid case: separator index between trees
        // For 7 leaves (0b111 = 4+2+1), index 8 is a separator between the first tree (1-7)
        // and the second tree (9-11). Similarly, index 12 is a separator between the second
        // tree and the third tree (13).
        let mut nodes_with_separator = BTreeMap::new();
        let separator_idx = InOrderIndex::read_from_bytes(&8usize.to_bytes()).unwrap();
        nodes_with_separator.insert(separator_idx, int_to_node(0));
        let result = PartialMmr::from_parts(peaks.clone(), nodes_with_separator, BTreeSet::new());
        assert!(result.is_err(), "separator index 8 should be rejected");

        let mut nodes_with_separator_12 = BTreeMap::new();
        let separator_idx_12 = InOrderIndex::read_from_bytes(&12usize.to_bytes()).unwrap();
        nodes_with_separator_12.insert(separator_idx_12, int_to_node(0));
        let result = PartialMmr::from_parts(peaks, nodes_with_separator_12, BTreeSet::new());
        assert!(result.is_err(), "separator index 12 should be rejected");

        // Invalid case: nodes with empty forest
        let empty_peaks = MmrPeaks::new(Forest::empty(), vec![]).unwrap();
        let mut nodes_with_empty_forest = BTreeMap::new();
        nodes_with_empty_forest.insert(InOrderIndex::from_leaf_pos(0), int_to_node(0));
        let result = PartialMmr::from_parts(empty_peaks, nodes_with_empty_forest, BTreeSet::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_from_parts_validation_deserialization() {
        // Build an MMR with 7 leaves
        let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();
        let partial_mmr = PartialMmr::from_peaks(mmr.peaks());

        // Valid serialization/deserialization
        let bytes = partial_mmr.to_bytes();
        let decoded = PartialMmr::read_from_bytes(&bytes);
        assert!(decoded.is_ok());

        // Test that deserialization rejects bad data:
        // We'll construct invalid bytes that would create an invalid PartialMmr

        // Create a PartialMmr with a valid node, serialize it, then manually corrupt the node index
        let mut partial_with_node = PartialMmr::from_peaks(mmr.peaks());
        let node = mmr.get(1).unwrap();
        let proof = mmr.open(1).unwrap();
        partial_with_node.track(1, node, proof.path().merkle_path()).unwrap();

        // Serialize and verify it deserializes correctly first
        let valid_bytes = partial_with_node.to_bytes();
        let valid_decoded = PartialMmr::read_from_bytes(&valid_bytes);
        assert!(valid_decoded.is_ok());

        // Now create malformed data with index 0 via manual byte construction
        // This tests that deserialization properly validates inputs
        let mut bad_bytes = Vec::new();
        // forest (7 leaves)
        bad_bytes.extend_from_slice(&7usize.to_bytes());
        // peaks (3 peaks for forest 0b111)
        bad_bytes.extend_from_slice(&3usize.to_bytes()); // vec length
        for i in 0..3 {
            bad_bytes.extend_from_slice(&int_to_node(i as u64).to_bytes());
        }
        // nodes: 1 entry with index 0
        bad_bytes.extend_from_slice(&1usize.to_bytes()); // BTreeMap length
        bad_bytes.extend_from_slice(&0usize.to_bytes()); // invalid index 0
        bad_bytes.extend_from_slice(&int_to_node(0).to_bytes()); // value
        // tracked_leaves: empty vec
        bad_bytes.extend_from_slice(&0usize.to_bytes());

        let result = PartialMmr::read_from_bytes(&bad_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_parts_unchecked() {
        use alloc::collections::BTreeMap;

        // Build a valid MMR
        let mmr = Mmr::try_from_iter(LEAVES.iter().copied()).unwrap();
        let peaks = mmr.peaks();

        // from_parts_unchecked should not validate and always succeed
        let partial =
            PartialMmr::from_parts_unchecked(peaks.clone(), BTreeMap::new(), BTreeSet::new());
        assert_eq!(partial.forest(), peaks.forest());

        // Even invalid combinations should work (no validation)
        let mut invalid_tracked = BTreeSet::new();
        invalid_tracked.insert(999);
        let partial = PartialMmr::from_parts_unchecked(peaks, BTreeMap::new(), invalid_tracked);
        assert!(partial.tracked_leaves.contains(&999));
    }
}
