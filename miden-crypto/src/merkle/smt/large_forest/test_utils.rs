#![cfg(test)]
//! This module contains utility functions for testing the large forest.

use alloc::{string::ToString, vec::Vec};
use core::error::Error;

use miden_field::{Felt, Word};
use proptest::prelude::*;

use crate::{
    EMPTY_WORD, Map, ONE, ZERO,
    merkle::smt::{
        Backend, ForestInMemoryBackend, ForestOperation, LeafIndex, LineageId, MAX_LEAF_ENTRIES,
        SMT_DEPTH, SmtForestUpdateBatch, SmtProof, SmtUpdateBatch, VersionId,
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
            Some(Err(BackendError::Unspecified("simulated read failure".into())))
        }
    }
}

impl Backend for FallibleEntriesBackend {
    fn open(&self, lineage: LineageId, key: Word) -> BackendResult<SmtProof> {
        self.inner.open(lineage, key)
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
