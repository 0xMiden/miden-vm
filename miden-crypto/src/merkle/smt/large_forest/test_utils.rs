#![cfg(test)]
//! This module contains utility functions for testing the large forest.

/// Placeholder entry count for tests that do not exercise or assert entry count behavior.
pub const UNUSED_ENTRY_COUNT: usize = 0;

use alloc::{string::ToString, vec::Vec};
use core::error::Error;

use itertools::Itertools;
use miden_field::{Felt, Word};
use proptest::prelude::*;

use crate::{
    EMPTY_WORD, Map, ONE, ZERO,
    merkle::smt::{
        Backend, ForestInMemoryBackend, ForestOperation, LargeSmtForest, LeafIndex, LineageId,
        MAX_LEAF_ENTRIES, RootInfo, SMT_DEPTH, Smt, SmtForestUpdateBatch, SmtProof, SmtUpdateBatch,
        TreeId, VersionId,
        large_forest::{
            backend::{BackendError, Result as BackendResult},
            root::{TreeEntry, TreeWithRoot},
            utils::MutationSet,
        },
    },
};

// CONSTANTS
// ================================================================================================

/// The minimum number of entries that can be included in a batch.
const MIN_BATCH_ENTRIES: usize = 0;

/// The maximum number of entries that can be included in a batch.
const MAX_BATCH_ENTRIES: usize = 300;

/// The message used by [`FallibleEntriesBackend`] to simulate an iteration failure.
pub const FALLIBLE_READ_FAILURE_MESSAGE: &str = "simulated read failure";

// UTILS
// ================================================================================================

/// Converts the provided `error` into a test case failure.
///
/// This is necessary because the `From<impl Error>` implementation is only available in builds with
/// `std` enabled, and we want error forwarding to not suck.
pub fn to_fail(error: impl Error) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

// PROPERTY TEST GENERATORS
// ================================================================================================

/// Generates an arbitrary lineage id.
pub fn arbitrary_lineage() -> impl Strategy<Value = LineageId> {
    prop::array::uniform32(any::<u8>()).prop_map(LineageId::new)
}

/// Generates two distinct lineage identifiers.
pub fn arbitrary_distinct_lineages() -> impl Strategy<Value = (LineageId, LineageId)> {
    (arbitrary_lineage(), arbitrary_lineage())
        .prop_filter("lineages must be distinct", |(a, b)| a != b)
}

/// Generates an arbitrary version identifier.
pub fn arbitrary_version() -> impl Strategy<Value = VersionId> {
    // As the proptests occasionally increment the version they are given, we exclude u64::MAX just
    // in case. The probability is vanishingly unlikely though.
    0..u64::MAX
}

/// Generates an arbitrary valid felt value.
pub fn arbitrary_felt() -> impl Strategy<Value = Felt> {
    prop_oneof![any::<u64>().prop_map(Felt::new), Just(ZERO), Just(ONE)]
}

/// Generates an arbitrary valid word value.
pub fn arbitrary_word() -> impl Strategy<Value = Word> {
    prop_oneof![prop::array::uniform4(arbitrary_felt()).prop_map(Word::new), Just(Word::empty()),]
}

/// Generates a non-empty word value.
pub fn arbitrary_non_empty_word() -> impl Strategy<Value = Word> {
    arbitrary_word().prop_filter("word must be non-empty", |word| *word != EMPTY_WORD)
}

/// Generates a random number of unique (non-overlapping) key-value pairs.
///
/// Note that the generated pairs may well have the same leaf index.
pub fn arbitrary_entries() -> impl Strategy<Value = Vec<(Word, Word)>> {
    prop::collection::vec(
        (arbitrary_word(), arbitrary_word()),
        MIN_BATCH_ENTRIES..=MAX_BATCH_ENTRIES,
    )
    .prop_map(move |entries| {
        // We want to avoid duplicate entries. It is well-defined, but it helps with test simplicity
        // to avoid it here.
        let mut keys_in_leaf: Map<LeafIndex<SMT_DEPTH>, usize> = Map::default();

        entries
            .into_iter()
            .flat_map(|(k, v)| {
                let leaf_index = LeafIndex::from(k);
                let count = keys_in_leaf.entry(leaf_index).or_default();

                // We don't want to overfill a leaf.
                if *count >= MAX_LEAF_ENTRIES {
                    return None;
                } else {
                    *count += 1;
                }

                Some((k, v))
            })
            .collect()
    })
}

/// Generates an arbitrary batch of updates to be performed on an arbitrary tree.
pub fn arbitrary_batch() -> impl Strategy<Value = SmtUpdateBatch> {
    arbitrary_entries().prop_map(|e| {
        SmtUpdateBatch::new(e.into_iter().map(|(k, v)| {
            if v == EMPTY_WORD {
                ForestOperation::remove(k)
            } else {
                ForestOperation::insert(k, v)
            }
        }))
    })
}

/// Builds a reference [`Smt`] by applying `initial` to an empty tree.
pub fn build_tree(initial: SmtUpdateBatch) -> core::result::Result<Smt, TestCaseError> {
    let mut tree = Smt::new();
    apply_batch(&mut tree, initial)?;
    Ok(tree)
}

/// Applies a batch to the provided reference [`Smt`].
pub fn apply_batch(
    tree: &mut Smt,
    batch: SmtUpdateBatch,
) -> core::result::Result<(), TestCaseError> {
    let mutations = tree
        .compute_mutations(batch.consume().into_iter().map(Into::<(Word, Word)>::into))
        .map_err(to_fail)?;
    tree.apply_mutations(mutations).map_err(to_fail)
}

/// Collects the keys affected by a batch using the batch's canonicalized ordering and deduping.
pub fn batch_keys(batch: &SmtUpdateBatch) -> Vec<Word> {
    batch.clone().consume().into_iter().map(|operation| operation.key()).collect()
}

/// Sorts tree entries explicitly by `(key, value)` so tests compare sets without constraining
/// backend iteration order.
pub fn sorted_tree_entries(tree: &Smt) -> Vec<TreeEntry> {
    let mut entries = tree
        .entries()
        .map(|(key, value)| TreeEntry { key: *key, value: *value })
        .collect_vec();
    entries.sort_by_key(|entry| (entry.key, entry.value));
    entries
}

/// Sorts forest entries explicitly by `(key, value)` so tests compare observable contents rather
/// than relying on unspecified iterator ordering.
pub fn sorted_forest_entries<B: Backend>(
    forest: &LargeSmtForest<B>,
    tree: TreeId,
) -> core::result::Result<Vec<TreeEntry>, TestCaseError> {
    let mut entries = forest
        .entries(tree)
        .map_err(to_fail)?
        .collect::<crate::merkle::smt::large_forest::Result<Vec<_>>>()
        .map_err(to_fail)?;
    entries.sort_by_key(|entry| (entry.key, entry.value));
    Ok(entries)
}

fn word_to_option(value: Word) -> Option<Word> {
    if value == EMPTY_WORD { None } else { Some(value) }
}

/// Asserts that the forest and reference tree agree on entries, counts, key lookups, and openings.
pub fn assert_tree_queries_match<B: Backend>(
    forest: &LargeSmtForest<B>,
    tree_id: TreeId,
    reference: &Smt,
    sample_keys: &[Word],
    assert_openings: bool,
) -> core::result::Result<(), TestCaseError> {
    let forest_entries = sorted_forest_entries(forest, tree_id)?;
    let reference_entries = sorted_tree_entries(reference);
    let reference_entry_count = reference_entries.len();
    prop_assert_eq!(forest_entries, reference_entries);
    prop_assert_eq!(forest.entry_count(tree_id).map_err(to_fail)?, reference_entry_count);

    for key in sample_keys {
        prop_assert_eq!(
            forest.get(tree_id, *key).map_err(to_fail)?,
            word_to_option(reference.get_value(key))
        );
        if assert_openings {
            prop_assert_eq!(forest.open(tree_id, *key).map_err(to_fail)?, reference.open(key));
        }
    }

    Ok(())
}

/// Asserts that the forest metadata for `lineage` matches the provided sequence of versions.
pub fn assert_lineage_metadata<B: Backend>(
    forest: &LargeSmtForest<B>,
    lineage: LineageId,
    versions: &[(VersionId, Word)],
) -> core::result::Result<(), TestCaseError> {
    let (latest_version, latest_root) =
        versions.last().copied().expect("lineage must be non-empty");

    prop_assert_eq!(forest.latest_version(lineage), Some(latest_version));
    prop_assert_eq!(forest.latest_root(lineage), Some(latest_root));
    prop_assert_eq!(
        forest.lineage_roots(lineage).expect("lineage must be present").collect_vec(),
        versions.iter().rev().map(|(_, root)| *root).collect_vec()
    );

    for (idx, (version, root)) in versions.iter().enumerate() {
        let tree = TreeId::new(lineage, *version);
        let expected = if idx + 1 == versions.len() {
            RootInfo::LatestVersion(*root)
        } else {
            RootInfo::HistoricalVersion(*root)
        };
        prop_assert_eq!(forest.root_info(tree), expected);
    }

    Ok(())
}

// FALLIBLE ENTRIES BACKEND
// ================================================================================================

/// A wrapper around [`ForestInMemoryBackend`] that injects an error on the 3rd item yielded by
/// the `entries` iterator, to exercise the error-propagation path.
#[derive(Debug)]
pub struct FallibleEntriesBackend {
    inner: ForestInMemoryBackend,
}

impl FallibleEntriesBackend {
    /// Constructs a new `FallibleEntriesBackend` wrapping a fresh [`ForestInMemoryBackend`].
    pub fn new() -> Self {
        Self { inner: ForestInMemoryBackend::new() }
    }
}

/// An iterator that yields the first 2 items from the inner iterator as `Ok(...)`, then yields
/// a single `Err(BackendError::Unspecified(...))`, then yields `None` forever.
pub struct FallibleIter<I> {
    inner: I,
    count: usize,
}

impl<I: Iterator<Item = BackendResult<TreeEntry>>> Iterator for FallibleIter<I> {
    type Item = BackendResult<TreeEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count >= 3 {
            return None;
        }
        self.count += 1;
        if self.count <= 2 {
            self.inner.next()
        } else {
            Some(Err(BackendError::Unspecified(FALLIBLE_READ_FAILURE_MESSAGE.into())))
        }
    }
}

impl Backend for FallibleEntriesBackend {
    fn open(&self, lineage: LineageId, key: Word) -> BackendResult<SmtProof> {
        self.inner.open(lineage, key)
    }

    fn get_leaf(
        &self,
        lineage: LineageId,
        leaf_index: LeafIndex<SMT_DEPTH>,
    ) -> BackendResult<crate::merkle::smt::SmtLeaf> {
        self.inner.get_leaf(lineage, leaf_index)
    }

    fn get(&self, lineage: LineageId, key: Word) -> BackendResult<Option<Word>> {
        self.inner.get(lineage, key)
    }

    fn version(&self, lineage: LineageId) -> BackendResult<VersionId> {
        self.inner.version(lineage)
    }

    fn lineages(&self) -> BackendResult<impl Iterator<Item = LineageId>> {
        self.inner.lineages()
    }

    fn trees(&self) -> BackendResult<impl Iterator<Item = TreeWithRoot>> {
        self.inner.trees()
    }

    fn entry_count(&self, lineage: LineageId) -> BackendResult<usize> {
        self.inner.entry_count(lineage)
    }

    fn entries(
        &self,
        lineage: LineageId,
    ) -> BackendResult<impl Iterator<Item = BackendResult<TreeEntry>>> {
        let inner_iter = self.inner.entries(lineage)?;
        Ok(FallibleIter { inner: inner_iter, count: 0 })
    }

    fn add_lineage(
        &mut self,
        lineage: LineageId,
        version: VersionId,
        updates: SmtUpdateBatch,
    ) -> BackendResult<TreeWithRoot> {
        self.inner.add_lineage(lineage, version, updates)
    }

    fn update_tree(
        &mut self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> BackendResult<MutationSet> {
        self.inner.update_tree(lineage, new_version, updates)
    }

    fn add_lineages(
        &mut self,
        version: VersionId,
        lineages: SmtForestUpdateBatch,
    ) -> BackendResult<Vec<(LineageId, TreeWithRoot)>> {
        self.inner.add_lineages(version, lineages)
    }

    fn update_forest(
        &mut self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> BackendResult<Vec<(LineageId, MutationSet)>> {
        self.inner.update_forest(new_version, updates)
    }
}
