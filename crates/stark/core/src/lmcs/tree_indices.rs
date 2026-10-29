//! Validated Merkle tree indices and missing sibling iteration.
//!
//! [`TreeIndices`] bundles a sorted, deduplicated set of domain indices with
//! their source depth, enforcing the invariant that every index is in `0..2^depth`.
//!
//! [`MissingSiblingsIter`] walks the tree upward from a set of leaf positions
//! and yields the sibling nodes absent from the set — exactly the nodes whose
//! hashes must be provided to reconstruct the root.

use alloc::{collections::BTreeMap, vec::Vec};

use crate::lmcs::{LmcsError, node_id::NodeId};

/// A validated set of Merkle tree indices at a given source depth.
///
/// Invariants (enforced by [`new`](Self::new), [`fold_to_depth`](Self::fold_to_depth),
/// and [`shrink_depth`](Self::shrink_depth)):
/// - `indices` is sorted ascending with no duplicates.
/// - Every index satisfies `index < 2^depth`.
///
/// May be empty. Consumers that require non-empty input should check
/// [`is_empty`](Self::is_empty).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeIndices {
    indices: Vec<usize>,
    depth: u8,
}

impl TreeIndices {
    /// Create validated tree indices from an arbitrary iterator.
    ///
    /// Sorts, deduplicates, and validates that every index is in `0..2^depth`.
    /// Returns `LmcsError::InvalidProof` if any index is out of range.
    pub fn new(indices: impl IntoIterator<Item = usize>, depth: u8) -> Result<Self, LmcsError> {
        let mut indices: Vec<usize> = indices.into_iter().collect();
        indices.sort_unstable();
        indices.dedup();

        let max = 1usize << depth as usize;
        if indices.last().is_some_and(|&i| i >= max) {
            return Err(LmcsError::InvalidProof);
        }

        Ok(Self { indices, depth })
    }

    /// The tree depth (log₂ of the number of leaves).
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Number of unique indices.
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Whether the index set is empty.
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// Iterate over the indices in ascending order.
    pub fn iter(&self) -> core::slice::Iter<'_, usize> {
        self.indices.iter()
    }

    /// Iterator over sibling nodes absent from this leaf set, bottom-to-top.
    pub(super) fn missing_siblings(&self) -> MissingSiblingsIter {
        MissingSiblingsIter::new(&self.indices, self.depth)
    }

    /// Fold these source-domain indices onto a committed tree at `target_depth`.
    ///
    /// In natural (domain) order, a query index opens the leaf selected by its low
    /// `target_depth` bits: `query & ((1 << target_depth) - 1)`. Returns the
    /// deduplicated leaf indices, leaving `self` unchanged. Use
    /// [`expand_leaf_values`](Self::expand_leaf_values) to re-key leaf-keyed
    /// results back to the original query indices.
    ///
    /// Returns `InvalidProof` if `target_depth` is above the current source depth.
    pub fn fold_to_depth(&self, target_depth: u8) -> Result<TreeIndices, LmcsError> {
        let mut leaf_indices = self.clone();
        leaf_indices.fold_in_place(target_depth)?;
        Ok(leaf_indices)
    }

    /// Re-key leaf-keyed values back to the original query indices.
    ///
    /// Each query index maps to the leaf selected by its low `target_depth` bits;
    /// `target_depth` must match the depth passed to the [`fold_to_depth`](Self::fold_to_depth)
    /// that produced `leaf_values`. Returns `InvalidProof` if a required leaf is absent.
    pub fn expand_leaf_values<T: Clone>(
        &self,
        target_depth: u8,
        leaf_values: &BTreeMap<usize, T>,
    ) -> Result<BTreeMap<usize, T>, LmcsError> {
        let leaf_mask = (1usize << target_depth as usize) - 1;
        self.indices
            .iter()
            .map(|&query| {
                let value = leaf_values.get(&(query & leaf_mask)).ok_or(LmcsError::InvalidProof)?;
                Ok((query, value.clone()))
            })
            .collect()
    }

    /// Map domain indices to folded domain indices at `target_depth`, in place.
    ///
    /// In natural (domain) order, folding maps each index to its low `target_depth`
    /// bits: `index & ((1 << target_depth) - 1)`. The depth is reduced and duplicates
    /// from indices in the same coset are removed. Returns `InvalidProof` if
    /// `target_depth` is above the current source depth.
    fn fold_in_place(&mut self, target_depth: u8) -> Result<(), LmcsError> {
        if target_depth > self.depth {
            return Err(LmcsError::InvalidProof);
        }

        let mask = (1usize << target_depth as usize) - 1;
        for idx in &mut self.indices {
            *idx &= mask;
        }
        self.indices.sort_unstable();
        self.indices.dedup();
        self.depth = target_depth;
        Ok(())
    }

    /// Map domain indices to folded domain indices `shift` levels down, in place.
    ///
    /// Shifts at or beyond the current depth collapse every index to depth 0,
    /// where the tree has a single root/leaf at index 0 (for example, the
    /// commitment tree of a one-row matrix). Use
    /// [`fold_to_depth`](Self::fold_to_depth) when invalid target depths
    /// should be rejected instead of saturated.
    pub fn shrink_depth(&mut self, shift: u8) {
        let target_depth = self.depth.saturating_sub(shift);
        self.fold_in_place(target_depth)
            .expect("target depth is derived from current depth");
    }
}

// ============================================================================
// MissingSiblingsIter
// ============================================================================

/// Iterator over sibling nodes absent from a queried leaf set, bottom-to-top.
///
/// Given sorted, deduplicated leaf positions, walks the Merkle tree upward
/// and yields a [`NodeId`] for every sibling not in the set — exactly the
/// nodes whose hashes a verifier must receive to reconstruct the root.
///
/// # Algorithm
///
/// Each layer is scanned left-to-right. For every node, if its sibling is
/// the next entry it is "present" and both are consumed; otherwise the
/// sibling is "missing" and yielded. Either way, the node's parent is
/// promoted to the next layer (deduplicated, since sibling pairs share a
/// parent). When the current layer is exhausted, the accumulated parents
/// become the new current layer. Iteration ends when the parents reach
/// depth 0 (the root).
///
/// # Buffer layout
///
/// A single `Vec<NodeId>` holds both regions in non-overlapping slices:
///
/// ```text
/// [ next-layer parents | ... gap ... | current-layer unprocessed ]
///   0..next_len                        current.start..current.end
/// ```
///
/// The gap never closes because each pair of siblings produces at most one
/// parent, so `next_len` grows slower than `current.start` advances.
pub(super) struct MissingSiblingsIter {
    /// Shared buffer: `nodes[current]` are unprocessed nodes in the current
    /// layer; `nodes[..next_len]` accumulates their parents for the next layer.
    nodes: Vec<NodeId>,
    /// Slice of `nodes` still to process in this layer.
    current: core::ops::Range<usize>,
    /// Number of parent nodes written into `nodes[..next_len]`.
    /// Invariant: `next_len ≤ current.start` (regions never overlap).
    next_len: usize,
}

impl MissingSiblingsIter {
    /// Create a new iterator from sorted, deduplicated leaf positions.
    pub fn new(positions: &[usize], tree_depth: u8) -> Self {
        let tree_depth = tree_depth as usize;
        let len = if tree_depth > 0 { positions.len() } else { 0 };
        Self {
            nodes: positions.iter().map(|&p| NodeId::new(tree_depth, p)).collect(),
            current: 0..len,
            next_len: 0,
        }
    }
}

impl Iterator for MissingSiblingsIter {
    type Item = NodeId;

    fn next(&mut self) -> Option<NodeId> {
        loop {
            // The two buffer regions must never overlap.
            debug_assert!(self.next_len <= self.current.start);

            if let Some((node, rest)) = self.nodes[self.current.clone()].split_first() {
                let sibling = node.sibling();
                let sibling_present = rest.first() == Some(&sibling);

                // Promote parent to the next layer, deduplicating consecutive siblings.
                let parent = node.parent();
                if self.next_len == 0 || self.nodes[self.next_len - 1] != parent {
                    self.nodes[self.next_len] = parent;
                    self.next_len += 1;
                }

                // Consume one node (missing sibling) or two (sibling pair).
                self.current.start += if sibling_present { 2 } else { 1 };
                debug_assert!(self.next_len <= self.current.start);

                if !sibling_present {
                    return Some(sibling);
                }
            } else {
                // Current layer exhausted — promote to the parent layer.
                debug_assert!(self.current.is_empty());
                let next = self.nodes[..self.next_len].first()?;
                if next.depth() == 0 {
                    debug_assert_eq!(self.next_len, 1, "tree must converge to a single root");
                    return None; // Reached the root; no more siblings to yield.
                }
                self.current = 0..self.next_len;
                self.next_len = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn tree_indices_construction_and_validation() {
        // Sorts, deduplicates, and validates.
        let ti = TreeIndices::new([3, 1, 2, 1, 3], 3).unwrap();
        let vals: Vec<usize> = ti.iter().copied().collect();
        assert_eq!(vals, [1, 2, 3]);
        assert_eq!(ti.depth(), 3);

        // Empty is valid.
        assert!(TreeIndices::new([], 5).unwrap().is_empty());

        // depth=0 → single leaf, only index 0 is valid.
        assert!(TreeIndices::new([0], 0).is_ok());
        assert!(TreeIndices::new([1], 0).is_err());

        // Boundary: depth=2 → valid range 0..4.
        assert!(TreeIndices::new([3], 2).is_ok());
        assert!(TreeIndices::new([4], 2).is_err());
        assert!(TreeIndices::new([0, 4], 2).is_err());
    }

    #[test]
    fn fold_to_depth_then_expand_leaf_values() {
        // Query indices at depth 3 fold to their low 2 bits: 0,4→0; 5→1; 7→3.
        let ti = TreeIndices::new([0, 4, 5, 7], 3).unwrap();
        let leaves = ti.fold_to_depth(2).unwrap();
        assert_eq!(leaves.iter().copied().collect::<Vec<_>>(), [0, 1, 3]);
        assert_eq!(leaves.depth(), 2);

        // Folding leaves the source untouched and rejects a depth above it.
        assert_eq!(ti.iter().copied().collect::<Vec<_>>(), [0, 4, 5, 7]);
        assert_eq!(ti.depth(), 3);
        assert!(ti.fold_to_depth(4).is_err());

        // Each query index reads its low-2-bit leaf: 0,4→'a'; 5→'b'; 7→'c'.
        let leaf_values: BTreeMap<usize, char> =
            [(0, 'a'), (1, 'b'), (3, 'c')].into_iter().collect();
        let expanded = ti.expand_leaf_values(2, &leaf_values).unwrap();
        assert_eq!(
            expanded.into_iter().collect::<Vec<_>>(),
            vec![(0, 'a'), (4, 'a'), (5, 'b'), (7, 'c')]
        );
    }

    #[test]
    fn shrink_depth() {
        // Domain indices [4,5,6,7] at depth 3: low-bit mask with new_depth=1 → mask=1.
        // 4&1=0, 5&1=1, 6&1=0, 7&1=1 → sorted dedup → [0,1].
        let mut ti = TreeIndices::new([4, 5, 6, 7], 3).unwrap();
        ti.shrink_depth(2);
        assert_eq!(ti.iter().copied().collect::<Vec<_>>(), [0, 1]);
        assert_eq!(ti.depth(), 1);

        // Domain indices [0,3] at depth 2: low-bit mask with new_depth=1 → mask=1.
        // 0&1=0, 3&1=1 → [0,1].
        let mut ti = TreeIndices::new([0, 3], 2).unwrap();
        ti.shrink_depth(1);
        assert_eq!(ti.iter().copied().collect::<Vec<_>>(), [0, 1]);
        assert_eq!(ti.depth(), 1);

        // Shift by 0 is a no-op.
        let mut ti = TreeIndices::new([1, 3], 3).unwrap();
        ti.shrink_depth(0);
        assert_eq!(ti.iter().copied().collect::<Vec<_>>(), [1, 3]);
        assert_eq!(ti.depth(), 3);

        // Domain indices [0,2,4,6] at depth 3: low-bit mask with new_depth=2 → mask=3.
        // 0&3=0, 2&3=2, 4&3=0, 6&3=2 → sorted dedup → [0,2].
        let mut ti = TreeIndices::new([0, 2, 4, 6], 3).unwrap();
        ti.shrink_depth(1);
        assert_eq!(ti.iter().copied().collect::<Vec<_>>(), [0, 2]);
        assert_eq!(ti.depth(), 2);
    }

    fn missing_siblings(indices: impl IntoIterator<Item = usize>, depth: u8) -> Vec<NodeId> {
        TreeIndices::new(indices, depth).unwrap().missing_siblings().collect()
    }

    #[test]
    fn missing_siblings_edge_cases() {
        // Empty input → nothing to do.
        assert!(missing_siblings([], 3).is_empty());

        // depth=0 → root is the only leaf, no siblings exist.
        assert!(missing_siblings([0], 0).is_empty());

        // All leaves present → every sibling is in the set, nothing missing.
        assert!(missing_siblings([0, 1], 1).is_empty());
        assert!(missing_siblings([0, 1, 2, 3], 2).is_empty());
    }

    #[test]
    fn single_leaf_needs_one_sibling_per_level() {
        // A single leaf at depth d requires exactly d sibling hashes to reach the root,
        // one at each level from the leaf up to depth 1.
        for depth in 1u8..=5 {
            let sibs = missing_siblings([0], depth);
            assert_eq!(sibs.len(), depth as usize, "depth={depth}");
            for (i, sib) in sibs.iter().enumerate() {
                assert_eq!(sib.depth(), depth as usize - i, "depth={depth}, level={i}");
            }
        }
    }

    #[test]
    fn missing_siblings_various_patterns() {
        // Single leaf at depth 2: sibling + uncle.
        assert_eq!(missing_siblings([2], 2), vec![NodeId::new(2, 3), NodeId::new(1, 0)]);

        // Sibling pair: only the parent's sibling is missing.
        assert_eq!(missing_siblings([2, 3], 2), vec![NodeId::new(1, 0)]);

        // One pair + one lone leaf covering both subtrees → only the lone leaf's sibling.
        // Parents {0,1} form a complete pair, so nothing missing above.
        assert_eq!(missing_siblings([0, 2, 3], 2), vec![NodeId::new(2, 1)]);

        // Multi-level propagation at depth 3: positions [2,3,4].
        // Leaf level: (2,3) pair + lone 4 → missing sibling 5.
        // Parent level: parents {1,2} are not siblings → missing 0 and 3.
        // Grandparent level: {0,1} form a pair → converges to root.
        assert_eq!(
            missing_siblings([2, 3, 4], 3),
            vec![NodeId::new(3, 5), NodeId::new(2, 0), NodeId::new(2, 3)]
        );
    }
}
