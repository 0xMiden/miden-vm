use alloc::vec::Vec;
use core::mem;

use num::Integer;
use p3_maybe_rayon::prelude::*;

use super::{
    EmptySubtreeRoots, InnerNode, InnerNodes, Leaves, MerkleError, MutationSet, NodeIndex,
    SMT_DEPTH, Smt, SmtLeaf, SparseMerkleTreeReader, Word,
};
use crate::merkle::smt::{Map, NodeMutation, NodeMutations, SmtLeafError};

#[cfg(test)]
mod tests;

pub(in crate::merkle::smt) type MutatedSubtreeLeaves = Vec<Vec<SubtreeLeaf>>;

// CONCURRENT IMPLEMENTATIONS
// ================================================================================================

impl Smt {
    /// Parallel implementation of [`Smt::with_entries()`].
    ///
    /// This method constructs a new sparse Merkle tree concurrently by processing subtrees in
    /// parallel, working from the bottom up. The process works as follows:
    ///
    /// 1. First, the input key-value pairs are sorted and grouped into subtrees based on their leaf
    ///    indices. Each subtree covers a range of 256 (2^8) possible leaf positions.
    ///
    /// 2. The subtrees are then processed in parallel:
    ///    - For each subtree, compute the inner nodes from depth D down to depth D-8.
    ///    - Each subtree computation yields a new subtree root and its associated inner nodes.
    ///
    /// 3. These subtree roots are recursively merged to become the "leaves" for the next iteration,
    ///    which processes the next 8 levels up. This continues until the final root of the tree is
    ///    computed at depth 0.
    ///
    /// # Errors
    /// Returns an error if the provided entries contain multiple values for the same key.
    pub(crate) fn with_entries_concurrent(
        entries: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<Self, MerkleError> {
        let entries: Vec<(Word, Word)> = entries.into_iter().collect();

        if entries.is_empty() {
            return Ok(Self::default());
        }

        let (inner_nodes, leaves) = Self::build_subtrees(entries)?;

        // All the leaves are empty
        if inner_nodes.is_empty() {
            return Ok(Self::default());
        }

        let root = inner_nodes.get(&NodeIndex::root()).unwrap().hash();
        Ok(Self::from_raw_parts(inner_nodes, leaves, root))
    }

    /// Similar to `with_entries_concurrent` but used for pre-sorted entries to avoid overhead.
    pub(crate) fn with_sorted_entries_concurrent(
        entries: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<Self, MerkleError> {
        let entries: Vec<(Word, Word)> = entries.into_iter().collect();

        if entries.is_empty() {
            return Ok(Self::default());
        }

        let (inner_nodes, leaves) = build_subtrees_from_sorted_entries(entries)?;

        // All the leaves are empty
        if inner_nodes.is_empty() {
            return Ok(Self::default());
        }

        let root = inner_nodes.get(&NodeIndex::root()).unwrap().hash();
        Ok(Self::from_raw_parts(inner_nodes, leaves, root))
    }

    /// Parallel implementation of [`Smt::compute_mutations()`].
    ///
    /// This method computes mutations by recursively processing subtrees in parallel, working from
    /// the bottom up. The process works as follows:
    ///
    /// 1. First, the input key-value pairs are sorted and grouped into subtrees based on their leaf
    ///    indices. Each subtree covers a range of 256 (2^8) possible leaf positions.
    ///
    /// 2. The subtrees containing modifications are then processed in parallel:
    ///    - For each modified subtree, compute node mutations from depth D up to depth D-8
    ///    - Each subtree computation yields a new root at depth D-8 and its associated mutations
    ///
    /// 3. These subtree roots become the "leaves" for the next iteration, which processes the next
    ///    8 levels up. This continues until reaching the tree's root at depth 0.
    ///
    /// # Errors
    /// Returns an error if mutations would exceed [`crate::merkle::smt::MAX_LEAF_ENTRIES`]
    /// (1024 entries) in a leaf.
    pub(crate) fn compute_mutations_concurrent(
        &self,
        kv_pairs: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, MerkleError>
    where
        Self: Sized + Sync,
    {
        // Collect and sort key-value pairs by their corresponding leaf index and then their key
        // value.
        let mut sorted_kv_pairs: Vec<_> = kv_pairs.into_iter().collect();
        sorted_kv_pairs.par_sort_unstable_by_key(|(key, _)| *key);

        // After sorting, check for duplicate keys which are adjacent after the sort.
        Self::check_for_duplicate_keys(&sorted_kv_pairs)?;

        // Convert sorted pairs into mutated leaves and capture any new pairs
        let (mut subtree_leaves, new_pairs) =
            self.sorted_pairs_to_mutated_subtree_leaves(sorted_kv_pairs)?;

        // If no mutations, return an empty mutation set
        if subtree_leaves.is_empty() {
            return Ok(MutationSet {
                old_root: self.root(),
                new_root: self.root(),
                node_mutations: NodeMutations::default(),
                new_pairs,
            });
        }

        let mut node_mutations = NodeMutations::default();

        // Process each depth level in reverse, stepping by the subtree depth
        for depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
            // Parallel processing of each subtree to generate mutations and roots
            let (mutations_per_subtree, mut subtree_roots): (Vec<_>, Vec<_>) = subtree_leaves
                .into_par_iter()
                .map(|subtree| {
                    debug_assert!(subtree.is_sorted() && !subtree.is_empty());
                    self.build_subtree_mutations(subtree, SMT_DEPTH, depth)
                })
                .unzip();

            // Prepare leaves for the next depth level
            subtree_leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();

            // Aggregate all node mutations
            node_mutations.extend(mutations_per_subtree.into_iter().flatten());

            debug_assert!(!subtree_leaves.is_empty());
        }

        let new_root = subtree_leaves[0][0].hash;

        // Create mutation set
        let mutation_set = MutationSet {
            old_root: self.root(),
            new_root,
            node_mutations,
            new_pairs,
        };

        // There should be mutations and new pairs at this point
        debug_assert!(
            !mutation_set.node_mutations().is_empty() && !mutation_set.new_pairs().is_empty()
        );

        Ok(mutation_set)
    }

    // SUBTREE MUTATION
    // --------------------------------------------------------------------------------------------

    /// Computes the node mutations and the root of a subtree
    fn build_subtree_mutations(
        &self,
        mut leaves: Vec<SubtreeLeaf>,
        tree_depth: u8,
        bottom_depth: u8,
    ) -> (NodeMutations, SubtreeLeaf)
    where
        Self: Sized,
    {
        debug_assert!(bottom_depth <= tree_depth);
        debug_assert!(Integer::is_multiple_of(&bottom_depth, &SUBTREE_DEPTH));
        debug_assert!(leaves.len() <= usize::pow(2, SUBTREE_DEPTH as u32));

        let subtree_root_depth = bottom_depth - SUBTREE_DEPTH;
        let mut node_mutations: NodeMutations = Default::default();
        let mut next_leaves: Vec<SubtreeLeaf> = Vec::with_capacity(leaves.len() / 2);

        for current_depth in (subtree_root_depth..bottom_depth).rev() {
            debug_assert!(current_depth <= bottom_depth);

            let next_depth = current_depth + 1;
            let mut iter = leaves.drain(..).peekable();

            while let Some(first_leaf) = iter.next() {
                // This constructs a valid index because next_depth will never exceed the depth of
                // the tree.
                let parent_index = NodeIndex::new_unchecked(next_depth, first_leaf.col).parent();
                let parent_node = self.get_inner_node(parent_index);
                let combined_node = fetch_sibling_pair(&mut iter, first_leaf, parent_node);
                let combined_hash = combined_node.hash();

                let &empty_hash = EmptySubtreeRoots::entry(tree_depth, current_depth);

                // Add the parent node even if it is empty for proper upward updates
                next_leaves.push(SubtreeLeaf {
                    col: parent_index.position(),
                    hash: combined_hash,
                });

                node_mutations.insert(
                    parent_index,
                    if combined_hash != empty_hash {
                        NodeMutation::Addition(combined_node)
                    } else {
                        NodeMutation::Removal
                    },
                );
            }
            drop(iter);
            leaves = mem::take(&mut next_leaves);
        }

        debug_assert_eq!(leaves.len(), 1);
        let root_leaf = leaves.pop().unwrap();
        (node_mutations, root_leaf)
    }

    // SUBTREE CONSTRUCTION
    // --------------------------------------------------------------------------------------------

    /// Computes the raw parts for a new sparse Merkle tree from a set of key-value pairs.
    ///
    /// `entries` need not be sorted. This function will sort them using parallel sorting.
    ///
    /// # Errors
    /// Returns an error if the provided entries contain multiple values for the same key.
    fn build_subtrees(mut entries: Vec<(Word, Word)>) -> Result<(InnerNodes, Leaves), MerkleError> {
        entries.par_sort_unstable_by_key(|item| {
            let index = Self::key_to_leaf_index(&item.0);
            index.position()
        });
        build_subtrees_from_sorted_entries(entries)
    }

    // LEAF NODE CONSTRUCTION
    // --------------------------------------------------------------------------------------------

    /// Performs the initial transforms for constructing a [`SparseMerkleTree`] by composing
    /// subtrees. In other words, this function takes the key-value inputs to the tree, and produces
    /// the inputs to feed into [`build_subtree()`].
    ///
    /// `pairs` *must* already be sorted **by leaf index column**, not simply sorted by key. If
    /// `pairs` is not correctly sorted, the returned computations will be incorrect.
    ///
    /// # Errors
    /// Returns an error if the provided pairs contain multiple values for the same key.
    ///
    /// # Panics
    /// With debug assertions on, this function panics if it detects that `pairs` is not correctly
    /// sorted. Without debug assertions, the returned computations will be incorrect.
    pub(in crate::merkle::smt) fn sorted_pairs_to_leaves(
        pairs: Vec<(Word, Word)>,
    ) -> Result<PairComputations<u64, SmtLeaf>, MerkleError> {
        process_sorted_pairs_to_leaves(pairs, Self::pairs_to_leaf)
    }

    /// Constructs a single leaf from an arbitrary amount of key-value pairs.
    /// Those pairs must all have the same leaf index.
    ///
    /// # Errors
    /// Returns a `MerkleError::DuplicateValuesForIndex` if the provided pairs contain multiple
    /// values for the same key.
    ///
    /// # Returns
    /// - `Ok(Some(SmtLeaf))` if a valid leaf is constructed.
    /// - `Ok(None)` if the only provided value is `Self::EMPTY_VALUE`.
    fn pairs_to_leaf(mut pairs: Vec<(Word, Word)>) -> Result<Option<SmtLeaf>, MerkleError> {
        assert!(!pairs.is_empty());

        if pairs.len() > 1 {
            pairs.sort_by(|(key_1, _), (key_2, _)| key_1.cmp(key_2));
            // Check for duplicates in a sorted list by comparing adjacent pairs
            Self::check_for_duplicate_keys(&pairs)?;
            Ok(Some(SmtLeaf::new_multiple(pairs).unwrap()))
        } else {
            let (key, value) = pairs.pop().unwrap();
            if value == Self::EMPTY_VALUE {
                Ok(None)
            } else {
                Ok(Some(SmtLeaf::new_single(key, value)))
            }
        }
    }

    /// Computes leaves from a set of key-value pairs and current leaf values.
    /// Derived from `sorted_pairs_to_leaves`
    fn sorted_pairs_to_mutated_subtree_leaves(
        &self,
        pairs: Vec<(Word, Word)>,
    ) -> Result<(MutatedSubtreeLeaves, Map<Word, Word>), MerkleError> {
        // Map to track new key-value pairs for mutated leaves
        let mut new_pairs = Map::new();

        let accumulator = process_sorted_pairs_to_leaves(pairs, |leaf_pairs| {
            let mut leaf = self.get_leaf(&leaf_pairs[0].0);

            let mut leaf_changed = false;
            for (key, value) in leaf_pairs {
                // Check if the value has changed
                let old_value = new_pairs.get(&key).cloned().unwrap_or_else(|| {
                    // Safe to unwrap: `leaf_pairs` contains keys all belonging to this leaf.
                    // `SmtLeaf::get_value()` only returns `None` if the key does not belong to the
                    // leaf, which cannot happen due to the sorting/grouping
                    // logic in `process_sorted_pairs_to_leaves()`.
                    leaf.get_value(&key).unwrap()
                });

                if value != old_value {
                    // Update the leaf and track the new key-value pair
                    leaf = self.construct_prospective_leaf(leaf, &key, &value).map_err(
                        |e| match e {
                            SmtLeafError::TooManyLeafEntries { actual } => {
                                MerkleError::TooManyLeafEntries { actual }
                            },
                            other => panic!("unexpected SmtLeaf::insert error: {:?}", other),
                        },
                    )?;
                    new_pairs.insert(key, value);
                    leaf_changed = true;
                }
            }

            if leaf_changed {
                // Only return the leaf if it actually changed
                Ok(Some(leaf))
            } else {
                // Return None if leaf hasn't changed
                Ok(None)
            }
        });
        // The closure is the only possible source of errors.
        // Since it never returns an error - only `Ok(Some(_))` or `Ok(None)` - we can safely assume
        // `accumulator` is always `Ok(_)`.
        Ok((accumulator?.leaves, new_pairs))
    }
}

// SUBTREES
// ================================================================================================

/// A subtree is of depth 8.
pub(in crate::merkle::smt) const SUBTREE_DEPTH: u8 = 8;

/// A depth-8 subtree contains 256 "columns" that can possibly be occupied.
pub(in crate::merkle::smt) const COLS_PER_SUBTREE: u64 = u64::pow(2, SUBTREE_DEPTH as u32);

/// Helper struct for organizing the data we care about when computing Merkle subtrees.
///
/// Note that these represent "conceptual" leaves of some subtree, not necessarily
/// the leaf type for the sparse Merkle tree.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct SubtreeLeaf {
    /// The 'value' field of [`NodeIndex`]. When computing a subtree, the depth is already known.
    pub col: u64,
    /// The hash of the node this `SubtreeLeaf` represents.
    pub hash: Word,
}

/// Helper struct to organize the return value of [`Smt::sorted_pairs_to_leaves()`].
#[derive(Debug, Clone)]
pub(in crate::merkle::smt) struct PairComputations<K, L> {
    /// Literal leaves to be added to the sparse Merkle tree's internal mapping.
    pub nodes: Map<K, L>,
    /// "Conceptual" leaves that will be used for computations.
    pub leaves: Vec<Vec<SubtreeLeaf>>,
}

// Derive requires `L` to impl Default, even though we don't actually need that.
impl<K, L> Default for PairComputations<K, L> {
    fn default() -> Self {
        Self {
            nodes: Default::default(),
            leaves: Default::default(),
        }
    }
}

#[derive(Debug)]
pub(in crate::merkle::smt) struct SubtreeLeavesIter<'s> {
    leaves: core::iter::Peekable<alloc::vec::Drain<'s, SubtreeLeaf>>,
}

impl<'s> SubtreeLeavesIter<'s> {
    pub(crate) fn from_leaves(leaves: &'s mut Vec<SubtreeLeaf>) -> Self {
        // TODO: determine if there is any notable performance difference between taking a Vec,
        // which many need flattening first, vs storing a `Box<dyn Iterator<Item = SubtreeLeaf>>`.
        // The latter may have self-referential properties that are impossible to express in purely
        // safe Rust Rust.
        Self { leaves: leaves.drain(..).peekable() }
    }
}

impl Iterator for SubtreeLeavesIter<'_> {
    type Item = Vec<SubtreeLeaf>;

    /// Each `next()` collects an entire subtree.
    fn next(&mut self) -> Option<Vec<SubtreeLeaf>> {
        let mut subtree: Vec<SubtreeLeaf> = Default::default();

        let mut last_subtree_col = 0;

        while let Some(leaf) = self.leaves.peek() {
            last_subtree_col = u64::max(1, last_subtree_col);
            let is_exact_multiple = Integer::is_multiple_of(&last_subtree_col, &COLS_PER_SUBTREE);
            let next_subtree_col = if is_exact_multiple {
                u64::next_multiple_of(last_subtree_col + 1, COLS_PER_SUBTREE)
            } else {
                last_subtree_col.next_multiple_of(COLS_PER_SUBTREE)
            };

            last_subtree_col = leaf.col;
            if leaf.col < next_subtree_col {
                subtree.push(self.leaves.next().unwrap());
            } else if subtree.is_empty() {
                continue;
            } else {
                break;
            }
        }

        if subtree.is_empty() {
            debug_assert!(self.leaves.peek().is_none());
            return None;
        }

        Some(subtree)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Processes sorted key-value pairs to compute leaves for a subtree.
///
/// This function groups key-value pairs by their corresponding column index and processes each
/// group to construct leaves. The actual construction of the leaf is delegated to the
/// `process_leaf` callback, allowing flexibility for different use cases (e.g., creating
/// new leaves or mutating existing ones).
///
/// # Parameters
/// - `pairs`: A vector of sorted key-value pairs. The pairs *must* be sorted by leaf index column
///   (not simply by key). If the input is not sorted correctly, the function will produce incorrect
///   results and may panic in debug mode.
/// - `process_leaf`: A callback function used to process each group of key-value pairs
///   corresponding to the same column index. The callback takes a vector of key-value pairs for a
///   single column and returns the constructed leaf for that column.
///
/// # Returns
/// A `PairComputations<u64, Self::Leaf>` containing:
/// - `nodes`: A mapping of column indices to the constructed leaves.
/// - `leaves`: A collection of `SubtreeLeaf` structures representing the processed leaves. Each
///   `SubtreeLeaf` includes the column index and the hash of the corresponding leaf.
///
/// # Errors
/// Returns an error if the `process_leaf` callback fails.
///
/// # Panics
/// This function will panic in debug mode if the input `pairs` are not sorted by column index.
pub(crate) fn process_sorted_pairs_to_leaves<F>(
    pairs: Vec<(Word, Word)>,
    mut process_leaf: F,
) -> Result<PairComputations<u64, SmtLeaf>, MerkleError>
where
    F: FnMut(Vec<(Word, Word)>) -> Result<Option<SmtLeaf>, MerkleError>,
{
    debug_assert!(pairs.is_sorted_by_key(|(key, _)| Smt::key_to_leaf_index(key).position()));
    let mut accumulator: PairComputations<u64, SmtLeaf> = Default::default();
    // As we iterate, we'll keep track of the kv-pairs we've seen so far that correspond to a
    // single leaf. When we see a pair that's in a different leaf, we'll swap these pairs
    // out and store them in our accumulated leaves.
    let mut current_leaf_buffer: Vec<(Word, Word)> = Default::default();
    let mut iter = pairs.into_iter().peekable();
    while let Some((key, value)) = iter.next() {
        let col = Smt::key_to_leaf_index(&key).index.position();
        let peeked_col = iter.peek().map(|(key, _v)| {
            let index = Smt::key_to_leaf_index(key);
            let next_col = index.index.position();
            // We panic if `pairs` is not sorted by column.
            debug_assert!(next_col >= col);
            next_col
        });
        current_leaf_buffer.push((key, value));
        // If the next pair is the same column as this one, then we're done after adding this
        // pair to the buffer.
        if peeked_col == Some(col) {
            continue;
        }
        // Otherwise, the next pair is a different column, or there is no next pair. Either way
        // it's time to swap out our buffer.
        let leaf_pairs = mem::take(&mut current_leaf_buffer);
        // Process leaf and propagate any errors
        match process_leaf(leaf_pairs) {
            Ok(Some(leaf)) => {
                accumulator.nodes.insert(col, leaf);
            },
            Ok(None) => {
                // No leaf was constructed for this column. The column will be skipped.
            },
            Err(e) => return Err(e),
        }
        debug_assert!(current_leaf_buffer.is_empty());
    }
    // Compute the leaves from the nodes concurrently
    let mut accumulated_leaves: Vec<SubtreeLeaf> = accumulator
        .nodes
        .clone()
        .into_par_iter()
        .map(|(col, leaf)| SubtreeLeaf { col, hash: Smt::hash_leaf(&leaf) })
        .collect();
    // Sort the leaves by column
    accumulated_leaves.par_sort_by_key(|leaf| leaf.col);
    // TODO: determine is there is any notable performance difference between computing
    // subtree boundaries after the fact as an iterator adapter (like this), versus computing
    // subtree boundaries as we go. Either way this function is only used at the beginning of a
    // parallel construction, so it should not be a critical path.
    accumulator.leaves = SubtreeLeavesIter::from_leaves(&mut accumulated_leaves).collect();
    Ok(accumulator)
}

/// Computes the raw parts for a new sparse Merkle tree from a set of key-value pairs.
///
/// This function is mostly an implementation detail of
/// [`Smt::with_entries_concurrent()`].
///
/// # Errors
/// Returns an error if the provided entries contain multiple values for the same key.
fn build_subtrees_from_sorted_entries(
    entries: Vec<(Word, Word)>,
) -> Result<(InnerNodes, Leaves), MerkleError> {
    let mut accumulated_nodes: InnerNodes = Default::default();
    let PairComputations {
        leaves: mut leaf_subtrees,
        nodes: initial_leaves,
    } = Smt::sorted_pairs_to_leaves(entries)?;
    // If there are no leaves, we can return early
    if initial_leaves.is_empty() {
        return Ok((accumulated_nodes, initial_leaves));
    }
    for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
        let (nodes, mut subtree_roots): (Vec<Map<_, _>>, Vec<SubtreeLeaf>) = leaf_subtrees
            .into_par_iter()
            .map(|subtree| {
                debug_assert!(subtree.is_sorted());
                debug_assert!(!subtree.is_empty());
                let (nodes, subtree_root) = build_subtree(subtree, SMT_DEPTH, current_depth);
                (nodes, subtree_root)
            })
            .unzip();
        leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
        accumulated_nodes.extend(nodes.into_iter().flatten());
        debug_assert!(!leaf_subtrees.is_empty());
    }
    Ok((accumulated_nodes, initial_leaves))
}

/// Builds Merkle nodes from a bottom layer of "leaves" -- represented by a horizontal index and
/// the hash of the leaf at that index. `leaves` *must* be sorted by horizontal index, and
/// `leaves` must not contain more than one depth-8 subtree's worth of leaves.
///
/// This function will then calculate the inner nodes above each leaf for 8 layers, as well as
/// the "leaves" for the next 8-deep subtree, so this function can effectively be chained into
/// itself.
///
/// # Panics
/// With debug assertions on, this function panics under invalid inputs: if `leaves` contains
/// more entries than can fit in a depth-8 subtree, if `leaves` contains leaves belonging to
/// different depth-8 subtrees, if `bottom_depth` is lower in the tree than the specified
/// maximum depth (`DEPTH`), or if `leaves` is not sorted.
pub(crate) fn build_subtree(
    mut leaves: Vec<SubtreeLeaf>,
    tree_depth: u8,
    bottom_depth: u8,
) -> (Map<NodeIndex, InnerNode>, SubtreeLeaf) {
    #[cfg(debug_assertions)]
    {
        // Ensure that all leaves have unique column indices within this subtree.
        // In normal usage via public APIs, this should never happen because leaf
        // construction enforces uniqueness. However, when testing or benchmarking
        // `build_subtree()` in isolation, duplicate columns can appear if input
        // constraints are not enforced.
        use alloc::collections::BTreeSet;
        let mut seen_cols = BTreeSet::new();
        for leaf in &leaves {
            assert!(seen_cols.insert(leaf.col), "Duplicate column found in subtree: {}", leaf.col);
        }
    }
    debug_assert!(bottom_depth <= tree_depth);
    debug_assert!(Integer::is_multiple_of(&bottom_depth, &SUBTREE_DEPTH));
    debug_assert!(leaves.len() <= usize::pow(2, SUBTREE_DEPTH as u32));
    let subtree_root = bottom_depth - SUBTREE_DEPTH;
    let mut inner_nodes: Map<NodeIndex, InnerNode> = Default::default();
    let mut next_leaves: Vec<SubtreeLeaf> = Vec::with_capacity(leaves.len() / 2);
    for next_depth in (subtree_root..bottom_depth).rev() {
        debug_assert!(next_depth <= bottom_depth);
        // `next_depth` is the stuff we're making.
        // `current_depth` is the stuff we have.
        let current_depth = next_depth + 1;
        let mut iter = leaves.drain(..).peekable();
        while let Some(first) = iter.next() {
            // On non-continuous iterations, including the first iteration, `first_column` may
            // be a left or right node. On subsequent continuous iterations, we will always call
            // `iter.next()` twice.
            // On non-continuous iterations (including the very first iteration), this column
            // could be either on the left or the right. If the next iteration is not
            // discontinuous with our right node, then the next iteration's
            let is_right = first.col.is_odd();
            let (left, right) = if is_right {
                // Discontinuous iteration: we have no left node, so it must be empty.
                let left = SubtreeLeaf {
                    col: first.col - 1,
                    hash: *EmptySubtreeRoots::entry(tree_depth, current_depth),
                };
                let right = first;
                (left, right)
            } else {
                let left = first;
                let right_col = first.col + 1;
                let right = match iter.peek().copied() {
                    Some(SubtreeLeaf { col, .. }) if col == right_col => {
                        // Our inputs must be sorted.
                        debug_assert!(left.col <= col);
                        // The next leaf in the iterator is our sibling. Use it and consume it!
                        iter.next().unwrap()
                    },
                    // Otherwise, the leaves don't contain our sibling, so our sibling must be
                    // empty.
                    _ => SubtreeLeaf {
                        col: right_col,
                        hash: *EmptySubtreeRoots::entry(tree_depth, current_depth),
                    },
                };
                (left, right)
            };
            let index = NodeIndex::new_unchecked(current_depth, left.col).parent();
            let node = InnerNode { left: left.hash, right: right.hash };
            let hash = node.hash();
            let &equivalent_empty_hash = EmptySubtreeRoots::entry(tree_depth, next_depth);
            // If this hash is empty, then it doesn't become a new inner node, nor does it count
            // as a leaf for the next depth.
            if hash != equivalent_empty_hash {
                inner_nodes.insert(index, node);
                next_leaves.push(SubtreeLeaf { col: index.position(), hash });
            }
        }
        // Stop borrowing `leaves`, so we can swap it.
        // The iterator is empty at this point anyway.
        drop(iter);
        // After each depth, consider the stuff we just made the new "leaves", and empty the
        // other collection.
        mem::swap(&mut leaves, &mut next_leaves);
    }
    debug_assert_eq!(leaves.len(), 1);
    let root = leaves.pop().unwrap();
    (inner_nodes, root)
}

/// Constructs an `InnerNode` representing the sibling pair of which `first_leaf` is a part:
/// - If `first_leaf` is a right child, the left child is copied from the `parent_node`.
/// - If `first_leaf` is a left child, the right child is taken from `iter` if it was also mutated
///   or copied from the `parent_node`.
///
/// Returns the `InnerNode` containing the hashes of the sibling pair.
pub(crate) fn fetch_sibling_pair(
    iter: &mut core::iter::Peekable<alloc::vec::Drain<SubtreeLeaf>>,
    first_leaf: SubtreeLeaf,
    parent_node: InnerNode,
) -> InnerNode {
    let is_right_node = first_leaf.col.is_odd();

    if is_right_node {
        let left_leaf = SubtreeLeaf {
            col: first_leaf.col - 1,
            hash: parent_node.left,
        };
        InnerNode {
            left: left_leaf.hash,
            right: first_leaf.hash,
        }
    } else {
        let right_col = first_leaf.col + 1;
        let right_leaf = match iter.peek().copied() {
            Some(SubtreeLeaf { col, .. }) if col == right_col => iter.next().unwrap(),
            _ => SubtreeLeaf { col: right_col, hash: parent_node.right },
        };
        InnerNode {
            left: first_leaf.hash,
            right: right_leaf.hash,
        }
    }
}

#[cfg(feature = "internal")]
pub fn build_subtree_for_bench(
    leaves: Vec<SubtreeLeaf>,
    tree_depth: u8,
    bottom_depth: u8,
) -> (Map<NodeIndex, InnerNode>, SubtreeLeaf) {
    build_subtree(leaves, tree_depth, bottom_depth)
}
