//! This module contains the definition of [`History`], a simple container for some number of
//! historical versions of a given merkle tree.
//!
//! This history consists of a series of _deltas_ from the current state of the tree, moving
//! backward in history away from that current state. These deltas are then used to form an overlay
//! that represents the changes to be made on top of the current tree to put it _back_ in that
//! historical state.
//!
//! It provides functionality for adding new states to the history, as well as for querying the
//! history at a given point in time.
//!
//! # Complexity
//!
//! Versions in this structure are _complete_. This means that the data stored for any given
//! historical version is sufficient to apply atop the current tree to return it to the state
//! corresponding to that historical version.
//!
//! # Performance
//!
//! This structure operates entirely in memory, and is hence reasonably quick to query. As of the
//! current time, no detailed benchmarking has taken place for the history.

pub mod error;

mod tests;

use alloc::collections::VecDeque;
use core::fmt::Debug;

use error::{HistoryError, Result};

use crate::{
    Map, Word,
    merkle::{
        EmptySubtreeRoots, NodeIndex,
        smt::{
            NodeMutation, SMT_DEPTH,
            large_forest::{
                root::{RootValue, VersionId},
                utils::MutationSet,
            },
        },
    },
};

// UTILITY TYPE ALIASES
// ================================================================================================

/// A collection of changes to arbitrary non-leaf nodes in a merkle tree.
///
/// All changes to nodes between versions `v` and `v + 1` must be explicitly "undone" in the
/// `NodeChanges` representing version `v`. This includes nodes that were defaulted in version `v`
/// that were given an explicit value in version `v + 1`, where the `NodeChanges` must explicitly
/// set those nodes back to the default.
///
/// Failure to do so will result in incorrect values when those nodes are queried at a point in the
/// history corresponding to version `v`.
pub type NodeChanges = Map<NodeIndex, Word>;

/// The type of the keys that need to be changed by the delta to return the target tree to the state
/// represented by the delta.
pub type ChangedKeys = Map<Word, Word>;

// HISTORY
// ================================================================================================

/// A History contains a sequence of versions atop a given tree.
///
/// The versions are _cumulative_, meaning that querying the history must account for changes from
/// the current tree that take place in versions that are not the queried version or the current
/// tree.
#[derive(Clone, Debug)]
pub struct History {
    /// The maximum number of historical versions to be stored.
    max_count: usize,

    /// The deltas that make up the history for this tree.
    ///
    /// It will never contain more than `max_count` deltas, and is ordered with the oldest data at
    /// the lowest index.
    ///
    /// # Implementation Note
    ///
    /// We use a [`VecDeque`] instead of a [`Vec`] so that we can both have efficient access to any
    /// delta, while also making removals from the end efficient. As [`Self::truncate`] only ever
    /// removes some oldest `n` entries, this is the exact behavior we want.
    deltas: VecDeque<Delta>,
}

impl History {
    /// Constructs a new history container, containing at most `max_count` historical versions for
    /// a tree.
    #[must_use]
    pub fn empty(max_count: usize) -> Self {
        let deltas = VecDeque::new();
        Self { max_count, deltas }
    }

    /// Gets the maximum number of versions that this history can store.
    #[must_use]
    pub fn max_versions(&self) -> usize {
        self.max_count
    }

    /// Gets the current number of versions in the history.
    #[must_use]
    pub fn num_versions(&self) -> usize {
        self.deltas.len()
    }

    /// Returns all the roots that the history knows about.
    ///
    /// The iteration order of the roots is guaranteed to move backward in time, with earlier items
    /// being roots from versions closer to the present.
    ///
    /// # Complexity
    ///
    /// Calling this method provides an iterator whose consumption requires a traversal of all the
    /// versions. The method's complexity is thus `O(n)` in the number of versions.
    pub fn roots(&self) -> impl Iterator<Item = RootValue> {
        self.deltas.iter().rev().map(|d| d.root)
    }

    /// Returns the root value that corresponds to the provided `version`.
    pub fn root_for_version(&self, version: VersionId) -> Result<RootValue> {
        let ix = self.find_latest_corresponding_version(version)?;

        // The direct index is safe here because `find_latest_...` will have returned an error if
        // there is no such version, and is hence guaranteed to have returned a valid index.
        Ok(self.deltas[ix].root)
    }

    /// Adds a version to the history with the provided `root` and represented by the changes from
    /// the current tree given in `nodes` and `changed_keys`, with `entry_count` as the total
    /// number of entries for the tree that corresponds to this version.
    ///
    /// If adding this version would result in exceeding `self.max_count` historical versions, then
    /// the oldest of the versions is automatically removed.
    ///
    /// # Gotchas
    ///
    /// When constructing the `nodes` and `leaves`, keep in mind that those collections must contain
    /// entries for the **default value of a node or leaf** at any position where the tree was
    /// sparse in the state represented by `root`. If this is not done, incorrect values may be
    /// returned.
    ///
    /// This is necessary because the changes are the _reverse_ from what one might expect. Namely,
    /// the changes in a given version `v` must "_revert_" the changes made in the transition from
    /// version `v` to version `v + 1`.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NonMonotonicVersions`] if the provided version is not greater than the
    ///   previously added version.
    pub fn add_version(
        &mut self,
        root: RootValue,
        version_id: VersionId,
        nodes: NodeChanges,
        changed_keys: ChangedKeys,
        entry_count: usize,
    ) -> Result<()> {
        // We need to fail early if the provided new version is not monotonic with respect to the
        // latest version in the history.
        if let Some(v) = self.deltas.back()
            && v.version_id >= version_id
        {
            return Err(HistoryError::NonMonotonicVersions(version_id, v.version_id));
        }

        // We then check if we would exceed our version count limit, and remove the oldest if so.
        if self.num_versions() >= self.max_versions() {
            self.deltas.pop_front();
        }

        // We then need to update all the older deltas with the necessary additional changes
        // represented in this newly-added version.
        for delta in &mut self.deltas {
            // The root and the version remain the same, but we may need to change the nodes and
            // keys.
            for (ix, value) in &nodes {
                delta.nodes.entry(*ix).or_insert(*value);
            }
            for (key, value) in &changed_keys {
                // If the delta has removed something, we never want to re-add it over the top.
                delta.changed_keys.entry(*key).or_insert(*value);
            }
        }

        self.deltas
            .push_back(Delta::new(root, version_id, nodes, changed_keys, entry_count));

        Ok(())
    }

    /// Adds a version to the history, represented by the changes from the current tree given
    /// `mutations`, with `entry_count` corresponding to the number of entries in the full tree
    /// corresponding to this version.
    ///
    /// If adding this version would result in exceeding `self.max_count` historical versions, then
    /// the oldest of the versions is automatically removed.
    ///
    /// # Gotchas
    ///
    /// When constructing the `mutations`, keep in mind that the set must contain entries for the
    /// **default value of a node or leaf** at any position where the tree was sparse in the state
    /// represented by `root`. If this is not done, incorrect values may be returned.
    ///
    /// This is necessary because the changes are the _reverse_ from what one might expect. Namely,
    /// the changes in a given version `v` must "_revert_" the changes made in the transition from
    /// version `v` to version `v + 1`.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::NonMonotonicVersions`] if the provided version is not greater than the
    ///   previously added version.
    pub fn add_version_from_mutation_set(
        &mut self,
        version_id: VersionId,
        mutations: MutationSet,
        entry_count: usize,
    ) -> Result<()> {
        let mut changed_keys = ChangedKeys::default();
        mutations.new_pairs.into_iter().for_each(|(k, v)| {
            changed_keys.insert(k, v);
        });

        // The node changes are more complex, as we have to explicitly handle reversions to empty
        // specially.
        let node_changes: NodeChanges = mutations
            .node_mutations
            .into_iter()
            .map(|(ix, m)| match m {
                NodeMutation::Removal => (ix, *EmptySubtreeRoots::entry(SMT_DEPTH, ix.depth())),
                NodeMutation::Addition(n) => (ix, n.hash()),
            })
            .collect();

        // Now we can simply delegate to the standard function.
        self.add_version(mutations.new_root, version_id, node_changes, changed_keys, entry_count)
    }

    /// Returns the index in the sequence of deltas of the version that corresponds to the provided
    /// `version_id`.
    ///
    /// To "correspond" means that it either has the provided `version_id`, or is the newest version
    /// with a `version_id` less than the provided id. In either case, it is the correct version to
    /// be used to query the tree state in the provided `version_id`.
    ///
    /// # Complexity
    ///
    /// Finding the latest corresponding version in the history requires a linear traversal of the
    /// history entries, and hence has complexity `O(n)` in the number of versions.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::HistoryEmpty`] if the history is empty and hence there is no version to
    ///   find.
    /// - [`HistoryError::VersionTooOld`] if the history does not contain the data to provide a
    ///   coherent overlay for the provided `version_id` due to `version_id` being older than the
    ///   oldest version stored.
    fn find_latest_corresponding_version(&self, version_id: VersionId) -> Result<usize> {
        // If the version is older than the oldest, we error.
        if let Some(oldest_version) = self.deltas.front() {
            if oldest_version.version_id > version_id {
                return Err(HistoryError::VersionTooOld);
            }
        } else {
            return Err(HistoryError::HistoryEmpty);
        }

        // As we want the NEWEST delta that satisfies the version, we look for the position at which
        // the delta cannot be used and move back by one.
        let ix = self
            .deltas
            .iter()
            .position(|d| d.version_id > version_id)
            .unwrap_or_else(|| self.num_versions())
            .checked_sub(1)
            .expect(
                "Subtraction should not overflow as we have ruled out the no-version \
                case, and in the other cases the left operand will be >= 1",
            );

        Ok(ix)
    }

    /// Returns a view of the history that allows querying as a single unified overlay on the
    /// current state of the merkle tree as if the overlay was reverting the tree to the state
    /// corresponding to the specified `version_id`.
    ///
    /// Note that the history may not contain a version that directly corresponds to `version_id`.
    /// In such a case, the view will instead use the newest version coherent with the provided
    /// `version_id`, as this is the correct version for the provided id. Note that this will be
    /// incorrect if the versions stored in the history do not represent contiguous changes from the
    /// current tree.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::VersionTooOld`] if the history does not contain the data to provide a
    ///   coherent overlay for the provided `version_id` due to `version_id` being older than the
    ///   oldest version stored.
    pub fn get_view_at(&self, version_id: VersionId) -> Result<HistoryView<'_>> {
        HistoryView::new_of(version_id, self)
    }

    /// Removes all versions in the history that are older than the version denoted by the provided
    /// `version_id`.
    ///
    /// If `version_id` is not a version known by the history, it will keep the newest version that
    /// is capable of serving as that version in queries.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history prior to any removals.
    pub fn truncate(&mut self, version_id: VersionId) -> usize {
        // We start by getting the index to truncate to, though it is not an error to remove
        // something too old.
        let truncate_ix = self.find_latest_corresponding_version(version_id).unwrap_or(0);

        for _ in 0..truncate_ix {
            self.deltas.pop_front();
        }

        truncate_ix
    }

    /// Removes all versions from the history.
    pub fn clear(&mut self) {
        self.deltas.clear();
    }
}

/// The functions in this impl block are specifically used for testing and are not available for
/// general API usage.
#[cfg(test)]
impl History {
    /// Returns `true` if `root` is in the history and `false` otherwise.
    #[must_use]
    pub fn is_known_root(&self, root: RootValue) -> bool {
        self.deltas.iter().any(|r| r.root == root)
    }
}

// HISTORY VIEW
// ================================================================================================

/// A read-only view of the history overlay on the tree at a specified place in the history.
#[derive(Copy, Clone, Debug)]
pub struct HistoryView<'history> {
    /// The delta corresponding to this overlay.
    delta: &'history Delta,
}

impl<'history> HistoryView<'history> {
    /// Constructs a new history view that acts as a single overlay of the state represented by the
    /// history at the provided `version`.
    ///
    /// # Complexity
    ///
    /// The computational complexity of this method is linear in the number of versions stored in
    /// the history.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::VersionTooOld`] if the history does not contain the data to provide a
    ///   coherent overlay for the provided `version`.
    fn new_of(version: VersionId, history: &'history History) -> Result<Self> {
        let version_ix = history.find_latest_corresponding_version(version)?;
        let delta = &history.deltas[version_ix];
        Ok(Self { delta })
    }

    /// Gets the value of the node in the history at the provided `index`, or returns `None` if the
    /// version does not overlay the current tree at that node.
    #[must_use]
    pub fn node_value(&self, index: &NodeIndex) -> Option<&Word> {
        self.delta.nodes.get(index)
    }

    /// Queries the value of a specific `key` in a leaf in the overlay, returning the value for that
    /// `key` if it has been changed, and [`None`] otherwise.
    #[must_use]
    pub fn value(&self, key: &Word) -> Option<Word> {
        self.delta.changed_keys.get(key).cloned()
    }

    /// Returns `true` if the key is removed by this delta, and `false` otherwise.
    #[must_use]
    pub fn is_key_removed(&self, key: &Word) -> bool {
        self.delta.changed_keys.get(key).map(Word::is_empty).unwrap_or(false)
    }

    /// Returns an iterator which yields the entries that are added by this view.
    pub fn changed_keys(&self) -> impl Iterator<Item = (Word, Word)> + 'history {
        self.delta.changed_keys.iter().map(|(k, v)| (*k, *v))
    }

    /// Returns the total number of entries in the tree at this historical version.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.delta.entry_count
    }
}

// DELTA
// ================================================================================================

/// A delta for a state `n` represents the changes (to both nodes and leaves) that need to be
/// applied on top of the state `n + 1` to yield the correct tree for state `n`.
///
/// # Cumulative Deltas and Temporal Ordering
///
/// In order to best represent the history of a merkle tree, these deltas are constructed to take
/// advantage of two main properties:
///
/// - They are _cumulative_, which reduces their practical memory usage. This does, however, mean
///   that querying the state of older blocks is more expensive than querying newer ones.
/// - Deltas are applied in **temporally reversed order** from what one might expect. Most
///   conventional applications of deltas bring something from the past into the future through
///   application. In our case, the application of one or more deltas moves the tree into a **past
///   state**.
///
/// # Construction
///
/// While the [`Delta`] type is visible in the interface of the history, it is only intended to be
/// constructed by the history. Users should not be allowed to construct it directly.
#[derive(Clone, Debug, PartialEq)]
struct Delta {
    /// The root of the tree in the `version` corresponding to the application of the reversions in
    /// this delta to the previous tree state.
    root: RootValue,

    /// The version of the tree represented by the delta.
    version_id: VersionId,

    /// Any changes to the non-leaf nodes in the tree for this delta.
    nodes: NodeChanges,

    /// The keys that need to be changed by the delta to return the target tree to the state
    /// represented by the delta. This includes pairs that either add or mutate a value under a
    /// key, and pairs where the value is the `EMPTY_WORD` and hence represent removals.
    changed_keys: ChangedKeys,

    /// The total number of entries that existed in the tree at the version represented by this
    /// delta, stored eagerly to avoid recomputation.
    entry_count: usize,
}

impl Delta {
    /// Creates a new delta with the provided `root`, representing the provided changes to the
    /// `nodes` in the merkle tree, using `changed_keys` to represent the changes to entries in
    /// the tree, and storing `entry_count` as the total number of entries at this version.
    #[must_use]
    fn new(
        root: RootValue,
        version_id: VersionId,
        nodes: NodeChanges,
        changed_keys: ChangedKeys,
        entry_count: usize,
    ) -> Self {
        Self {
            root,
            version_id,
            nodes,
            changed_keys,
            entry_count,
        }
    }
}
