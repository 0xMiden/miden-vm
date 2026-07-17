//! This module contains a non-persistent, in-memory [`Backend`] for the SMT forest. It is
//! non-parallel and is not intended to be such, allowing its use on effectively any platform where
//! this library can be built.

mod property_tests;
mod tests;

use alloc::vec::Vec;

#[cfg(test)]
use crate::merkle::smt::large_forest::operation::SmtUpdateBatch;
use crate::{
    EMPTY_WORD, Map, Word,
    merkle::{
        MerkleError,
        smt::{
            LeafIndex, SMT_DEPTH, Smt, SmtLeaf, SmtProof, VersionId,
            large_forest::{
                Backend, BackendReader,
                backend::{BackendError, Result},
                operation::SmtForestUpdateBatch,
                root::{LineageId, TreeEntry, TreeWithRoot},
                utils::{
                    AppliedLineageMutation, LineageMutation, LineageMutationKind, MutationSet,
                },
            },
        },
    },
};

// IN-MEMORY BACKEND SNAPSHOT
// ================================================================================================

/// A read-only, point-in-time snapshot of an [`InMemoryBackend`].
///
/// This type intentionally implements only [`BackendReader`], not [`Backend`]. It is returned by
/// [`InMemoryBackend::reader`] to hand out a detached copy of the backend state without exposing
/// any mutation capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryBackendSnapshot(InMemoryBackend);

impl BackendReader for InMemoryBackendSnapshot {
    fn open(&self, lineage: LineageId, key: Word) -> Result<SmtProof> {
        self.0.open(lineage, key)
    }

    fn get_leaf(&self, lineage: LineageId, leaf_index: LeafIndex<SMT_DEPTH>) -> Result<SmtLeaf> {
        self.0.get_leaf(lineage, leaf_index)
    }

    fn get(&self, lineage: LineageId, key: Word) -> Result<Option<Word>> {
        self.0.get(lineage, key)
    }

    fn version(&self, lineage: LineageId) -> Result<VersionId> {
        self.0.version(lineage)
    }

    fn lineages(&self) -> Result<impl Iterator<Item = LineageId>> {
        self.0.lineages()
    }

    fn trees(&self) -> Result<impl Iterator<Item = TreeWithRoot>> {
        self.0.trees()
    }

    fn entry_count(&self, lineage: LineageId) -> Result<usize> {
        self.0.entry_count(lineage)
    }

    fn entries(&self, lineage: LineageId) -> Result<impl Iterator<Item = Result<TreeEntry>>> {
        self.0.entries(lineage)
    }
}

// IN-MEMORY BACKEND
// ================================================================================================

/// The in-memory backend itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryBackend {
    /// The storage for the full trees that are stored in this backend, always guaranteed to be the
    /// latest tree in the lineage.
    trees: Map<LineageId, TreeData>,
}

/// Prepared mutations for [`InMemoryBackend`].
///
/// This is the in-memory backend's concrete [`Backend::PreparedMutations`] type. It stores the
/// forward SMT mutation sets that were computed during the first phase of a forest update. Applying
/// it mutates the in-memory trees directly without recomputing the update batches.
///
/// The fields are private because callers should treat prepared mutation data as opaque and pass it
/// back through
/// [`LargeSmtForest::apply_mutations`](crate::merkle::smt::LargeSmtForest::apply_mutations).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryPreparedMutations {
    entries: Vec<InMemoryPreparedLineageMutation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InMemoryPreparedLineageMutation {
    lineage: LineageId,
    old_version: Option<VersionId>,
    version: VersionId,
    forward: MutationSet,
    kind: LineageMutationKind,
}

impl InMemoryBackend {
    /// Constructs a new instance of the in-memory backend.
    pub fn new() -> Self {
        let trees = Map::default();
        Self { trees }
    }

    /// Converts this backend into a read-only snapshot.
    pub fn into_snapshot(self) -> InMemoryBackendSnapshot {
        InMemoryBackendSnapshot(self)
    }

    fn mutation_from_tree(
        lineage: LineageId,
        old_version: Option<VersionId>,
        new_version: VersionId,
        kind: LineageMutationKind,
        forward: MutationSet,
    ) -> (LineageMutation, InMemoryPreparedLineageMutation) {
        let old_root = forward.old_root();
        let new_root = forward.root();

        let mutation =
            LineageMutation::new(lineage, old_version, new_version, old_root, new_root, kind);
        let prepared = InMemoryPreparedLineageMutation {
            lineage,
            old_version,
            version: new_version,
            forward,
            kind,
        };

        (mutation, prepared)
    }
}

// BACKEND READER TRAIT
// ================================================================================================

impl BackendReader for InMemoryBackend {
    /// Returns an opening for the specified `key` in the SMT with the specified `lineage`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is one not known by this
    ///   backend.
    fn open(&self, lineage: LineageId, key: Word) -> Result<SmtProof> {
        let tree = self.trees.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(tree.tree.open(&key))
    }

    /// Returns the leaf stored at `leaf_index` in the SMT with the specified `lineage`.
    ///
    /// If no leaf is explicitly stored at the given index, an empty leaf for that index is
    /// returned.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is one not known by this
    ///   backend.
    fn get_leaf(&self, lineage: LineageId, leaf_index: LeafIndex<SMT_DEPTH>) -> Result<SmtLeaf> {
        let tree = self.trees.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(tree
            .tree
            .get_leaf_by_index(leaf_index)
            .unwrap_or_else(|| SmtLeaf::new_empty(leaf_index)))
    }

    /// Returns the value associated with the provided `key` in the SMT with the specified
    /// `lineage`, or [`None`] if no such value exists.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is one not known by this
    ///   backend.
    fn get(&self, lineage: LineageId, key: Word) -> Result<Option<Word>> {
        let tree = self.trees.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        let value = tree.tree.get_value(&key);
        let value = if value == EMPTY_WORD { None } else { Some(value) };

        Ok(value)
    }

    /// Returns the version of the tree with the specified `lineage`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] If the provided `lineage` is one not known by this
    ///   backend.
    fn version(&self, lineage: LineageId) -> Result<VersionId> {
        let tree = self.trees.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(tree.version)
    }

    /// Returns an iterator over all the lineages that the backend knows about.
    fn lineages(&self) -> Result<impl Iterator<Item = LineageId>> {
        Ok(self.trees.keys().cloned())
    }

    /// Returns an iterator over all the trees that the backend knows about.
    ///
    /// The iteration order is unspecified.
    fn trees(&self) -> Result<impl Iterator<Item = TreeWithRoot>> {
        Ok(self.trees.iter().map(|(l, t)| TreeWithRoot::new(*l, t.version, t.tree.root())))
    }

    /// Returns the total number of (key-value) entries in the specified `tree`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is one not known by this
    ///   backend.
    fn entry_count(&self, lineage: LineageId) -> Result<usize> {
        let tree = self.trees.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(tree.tree.num_entries())
    }

    /// Returns an iterator that yields the populated (key-value) entries for the specified
    /// `lineage`.
    ///
    /// It yields entries in an arbitrary order, and never yields entries where the value is the
    /// empty word.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is one not known by this
    ///   backend.
    fn entries(&self, lineage: LineageId) -> Result<impl Iterator<Item = Result<TreeEntry>>> {
        let tree = self.trees.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(tree.tree.entries().map(|(k, v)| Ok(TreeEntry { key: *k, value: *v })))
    }
}

// BACKEND TRAIT
// ================================================================================================

impl Backend for InMemoryBackend {
    type Reader = InMemoryBackendSnapshot;
    type PreparedMutations = InMemoryPreparedMutations;

    fn reader(&self) -> Result<Self::Reader> {
        Ok(self.clone().into_snapshot())
    }

    /// Computes the mutations required to apply the provided `updates` on the forest.
    fn compute_mutations(
        &self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> Result<(Vec<LineageMutation>, Self::PreparedMutations)> {
        let updates = updates.into_iter().collect::<Vec<_>>();
        let mut mutations = Vec::with_capacity(updates.len());
        let mut prepared = Vec::with_capacity(updates.len());
        for (lineage, ops) in updates {
            let (old_version, kind, forward) = if let Some(tree_data) = self.trees.get(&lineage) {
                (
                    Some(tree_data.version),
                    LineageMutationKind::UpdateTree,
                    tree_data.tree.compute_mutations(ops.into_iter().map(Into::into))?,
                )
            } else {
                (
                    None,
                    LineageMutationKind::AddLineage,
                    Smt::new().compute_mutations(ops.into_iter().map(Into::into))?,
                )
            };
            let (mutation, prepared_entry) =
                Self::mutation_from_tree(lineage, old_version, new_version, kind, forward);
            mutations.push(mutation);
            prepared.push(prepared_entry);
        }

        Ok((mutations, InMemoryPreparedMutations { entries: prepared }))
    }

    /// Apply a mutation set to the entire forest, returning the mutation sets that would reverse
    /// the changes to each lineage in the forest.
    ///
    /// - [`BackendError::Merkle`] if an error occurs with the merkle tree semantics.
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is not known by this backend.
    fn apply_mutations(
        &mut self,
        mutations: Self::PreparedMutations,
    ) -> Result<Vec<AppliedLineageMutation>> {
        // We start by checking that all lineages referred to in the `mutations` are valid,
        // failing early with an error if need be.
        for mutation in &mutations.entries {
            match mutation.kind {
                LineageMutationKind::AddLineage => {
                    if self.trees.contains_key(&mutation.lineage) {
                        return Err(BackendError::DuplicateLineage(mutation.lineage));
                    }
                },
                LineageMutationKind::UpdateTree => {
                    let tree_data = self
                        .trees
                        .get(&mutation.lineage)
                        .ok_or(BackendError::UnknownLineage(mutation.lineage))?;

                    if Some(tree_data.version) != mutation.old_version {
                        return Err(BackendError::BadVersion {
                            provided: mutation.old_version.unwrap_or_default(),
                            latest: tree_data.version,
                        });
                    }

                    let old_root = mutation.forward.old_root();
                    let latest_root = tree_data.tree.root();
                    if latest_root != old_root {
                        return Err(MerkleError::ConflictingRoots {
                            expected_root: old_root,
                            actual_root: latest_root,
                        }
                        .into());
                    }
                },
            }
        }

        let mut applied = Vec::with_capacity(mutations.entries.len());

        // Apply mutations to each lineage.
        for mutation in mutations.entries {
            let old_root = mutation.forward.old_root();
            let new_root = mutation.forward.root();
            match mutation.kind {
                LineageMutationKind::AddLineage => {
                    let mut tree = Smt::new();
                    let reverse = MutationSet::default();

                    if !mutation.forward.is_empty() {
                        tree.apply_mutations(mutation.forward)
                            .map_err(BackendError::internal_from)?;
                    }

                    applied.push(AppliedLineageMutation::new(
                        mutation.lineage,
                        mutation.old_version,
                        mutation.version,
                        old_root,
                        new_root,
                        0,
                        reverse,
                        mutation.kind,
                    ));
                    self.trees
                        .insert(mutation.lineage, TreeData { version: mutation.version, tree });
                },
                LineageMutationKind::UpdateTree => {
                    let tree_data = self
                        .trees
                        .get_mut(&mutation.lineage)
                        .ok_or(BackendError::UnknownLineage(mutation.lineage))?;
                    let old_entry_count = tree_data.tree.num_entries();

                    let reverse = if mutation.forward.is_empty() {
                        mutation.forward
                    } else {
                        let reverse = tree_data
                            .tree
                            .apply_mutations_with_reversion(mutation.forward)
                            .map_err(BackendError::internal_from)?;
                        tree_data.version = mutation.version;
                        reverse
                    };

                    applied.push(AppliedLineageMutation::new(
                        mutation.lineage,
                        mutation.old_version,
                        mutation.version,
                        old_root,
                        new_root,
                        old_entry_count,
                        reverse,
                        mutation.kind,
                    ));
                },
            }
        }

        Ok(applied)
    }
}

// These are the implementations of helper methods used by the backend tests.
#[cfg(test)]
impl InMemoryBackend {
    /// Adds the provided `lineage` to the forest.
    ///
    /// # Errors
    ///
    /// - [`BackendError::DuplicateLineage`] if the provided `lineage` is the same as an
    ///   already-known lineage. No data is changed in this case.
    /// - [`BackendError::Merkle`] if the provided `updates` cannot be applied to the empty tree.
    pub(crate) fn add_lineage(
        &mut self,
        lineage: LineageId,
        version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<TreeWithRoot> {
        if self.trees.contains_key(&lineage) {
            return Err(BackendError::DuplicateLineage(lineage));
        }

        let mut batch = SmtForestUpdateBatch::empty();
        batch.operations(lineage).add_operations(updates.into_iter());
        let (_mutations, persistent_mutations) = self.compute_mutations(version, batch)?;

        let mut applied_mutations = self.apply_mutations(persistent_mutations)?;
        let applied_mutation = applied_mutations
            .pop()
            .expect("should have applied exactly one lineage mutation");

        // Finally we just return the necessary metadata.
        Ok(TreeWithRoot::new(lineage, version, applied_mutation.new_root()))
    }

    /// Performs the provided `updates` on the tree with the specified `lineage`, returning the
    /// mutation set that will revert the changes made to the tree.
    ///
    /// At most one new root is added to the backend for the entire batch.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Merkle`] if the application of `updates` to the tree fails for any reason.
    /// - [`BackendError::UnknownLineage`] If the provided `lineage` is one not known by this
    ///   backend.
    pub(crate) fn update_tree(
        &mut self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<MutationSet> {
        if !self.trees.contains_key(&lineage) {
            return Err(BackendError::UnknownLineage(lineage));
        }

        let mut batch = SmtForestUpdateBatch::empty();
        batch.operations(lineage).add_operations(updates.into_iter());
        let (_mutations, persistent_mutations) = self.compute_mutations(new_version, batch)?;

        let mut applied_mutations = self.apply_mutations(persistent_mutations)?;
        let applied_mutation = applied_mutations
            .pop()
            .expect("should have applied exactly one lineage mutation");

        // We then just return the reversion set for the operations in question.
        Ok(applied_mutation.into_reverse())
    }

    /// Adds multiple new `lineages` to the tree, creating an empty tree for each and applying the
    /// provided modifications to it, with the result being given the specified `version`.
    ///
    /// If the provide batch of modifications is empty for any given lineage, then the **empty tree
    /// will be added** as the first version in that lineage.
    ///
    /// # Errors
    ///
    /// - [`BackendError::DuplicateLineage`] if any provided lineage conflicts with an already-known
    ///   lineage. No data is changed in this case.
    /// - [`BackendError::Merkle`] if any of the provided updates cannot be applied on top of the
    ///   empty tree.
    pub(crate) fn add_lineages(
        &mut self,
        version: VersionId,
        lineages: SmtForestUpdateBatch,
    ) -> Result<Vec<(LineageId, TreeWithRoot)>> {
        for lineage in lineages.lineages() {
            if self.trees.contains_key(lineage) {
                return Err(BackendError::DuplicateLineage(*lineage));
            }
        }

        let (_mutations, persistent_mutations) = self.compute_mutations(version, lineages)?;

        let applied_mutations = self.apply_mutations(persistent_mutations)?;

        // Build the return value from the applied mutations.
        let results = applied_mutations
            .into_iter()
            .map(|applied_mutation| (applied_mutation.lineage(), applied_mutation.result()))
            .collect();

        Ok(results)
    }

    /// Performs the provided `updates` on the entire forest, returning the mutation sets that would
    /// reverse the changes to each tree in the forest.
    ///
    /// The order of application of these mutations is unspecified.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Merkle`] if any set of operations on any lineage in the batch fail for any
    ///   reason.
    /// - [`BackendError::UnknownLineage`] if any lineage in the `updates` is not known by the
    ///   backend.
    ///
    /// # Panics
    ///
    /// - If a tree that has been checked to be present is not present upon later access.
    pub(crate) fn update_forest(
        &mut self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> Result<Vec<(LineageId, MutationSet)>> {
        for lineage in updates.lineages() {
            if !self.trees.contains_key(lineage) {
                return Err(BackendError::UnknownLineage(*lineage));
            }
        }

        let (_mutations, persistent_mutations) = self.compute_mutations(new_version, updates)?;

        let applied_mutations = self.apply_mutations(persistent_mutations)?;

        // Build the return value from the applied mutations.
        let reversion_sets = applied_mutations
            .into_iter()
            .map(|applied_mutation| (applied_mutation.lineage(), applied_mutation.into_reverse()))
            .collect();

        Ok(reversion_sets)
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

// TREE DATA
// ================================================================================================

/// A container for the data associated with the latest tree in a given lineage within the backend.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeData {
    version: VersionId,
    tree: Smt,
}
