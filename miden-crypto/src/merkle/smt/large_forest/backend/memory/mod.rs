//! This module contains a non-persistent, in-memory [`Backend`] for the SMT forest. It is
//! non-parallel and is not intended to be such, allowing its use on effectively any platform where
//! this library can be built.

mod property_tests;
mod tests;

use alloc::vec::Vec;

use crate::{
    EMPTY_WORD, Map, Word,
    merkle::smt::{
        Smt, SmtProof, VersionId,
        large_forest::{
            Backend,
            backend::{BackendError, MutationSet, Result},
            operation::{SmtForestUpdateBatch, SmtUpdateBatch},
            root::{LineageId, TreeEntry, TreeWithRoot},
        },
    },
};

// IN-MEMORY BACKEND
// ================================================================================================

/// The in-memory backend itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryBackend {
    /// The storage for the full trees that are stored in this backend, always guaranteed to be the
    /// latest tree in the lineage.
    trees: Map<LineageId, TreeData>,
}

impl InMemoryBackend {
    /// Constructs a new instance of the in-memory backend.
    pub fn new() -> Self {
        let trees = Map::default();
        Self { trees }
    }
}

// BACKEND TRAIT
// ================================================================================================

impl Backend for InMemoryBackend {
    /// Returns an opening for the specified `key` in the SMT with the specified `lineage`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] If the provided `lineage` is one not known by this
    ///   backend.
    fn open(&self, lineage: LineageId, key: Word) -> Result<SmtProof> {
        let tree = self.trees.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(tree.tree.open(&key))
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

    /// Adds the provided `lineage` to the forest.
    ///
    /// # Errors
    ///
    /// - [`BackendError::DuplicateLineage`] if the provided `lineage` is the same as an
    ///   already-known lineage. No data is changed in this case.
    /// - [`BackendError::Merkle`] if the provided `updates` cannot be applied to the empty tree.
    fn add_lineage(
        &mut self,
        lineage: LineageId,
        version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<TreeWithRoot> {
        // Returning this in the case of a duplicate lineage is required by the method contract on
        // the `Backend` trait.
        if self.trees.contains_key(&lineage) {
            return Err(BackendError::DuplicateLineage(lineage));
        }

        let mut tree = Smt::new();

        // A failure to compute mutations is a failure derived from user input, so we forward it as
        // appropriate.
        let mutations = tree.compute_mutations(updates.into_iter().map(|o| o.into()))?;

        // If computation of the mutations has succeeded but the application fails, then this should
        // be reported as an internal error, not a merkle error, to allow the caller to decide what
        // to do.
        tree.apply_mutations(mutations).map_err(BackendError::internal_from)?;

        // The following has had its preconditions checked, so we can change the state without
        // worrying about consistency.
        let tree_data = TreeData { version, tree };
        let root = tree_data.tree.root();
        self.trees.insert(lineage, tree_data);
        Ok(TreeWithRoot::new(lineage, version, root))
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
    fn update_tree(
        &mut self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<MutationSet> {
        // The method contract requires raising this error in the case that `lineage` is unknown to
        // the backend.
        let tree_data =
            self.trees.get_mut(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        let tree = &mut tree_data.tree;

        // We compute the mutations as a precondition check, which will leave the underlying tree in
        // the same state if anything errors. Any error this yields is considered to be derived from
        // user-input and hence is forwarded as-is.
        let mutations = tree.compute_mutations(updates.into_iter().map(|o| o.into()))?;

        // The invariants on this method given by the `Backend` trait states that no new allocations
        // should be performed if the updates do not change the tree. As a result, we can
        // short-circuit even trying.
        if mutations.is_empty() {
            // As the reverse of an empty mutations is also empty mutations, we can just return
            // that.
            return Ok(mutations);
        }

        // Any failure to apply the mutations here is considered an internal error, so we transform
        // it as such.
        let reversion_set = tree
            .apply_mutations_with_reversion(mutations)
            .map_err(BackendError::internal_from)?;

        // With preconditions checked, we can actually perform our modifications as it should yield
        // a consistent state.
        tree_data.version = new_version;

        Ok(reversion_set)
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
    fn update_forest(
        &mut self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> Result<Vec<(LineageId, MutationSet)>> {
        // We start by checking that all lineages referred to in the batch of `updates` are valid,
        // failing early with an error if need be.
        let updates = updates
            .into_iter()
            .map(|(lineage, ops)| {
                if !self.trees.contains_key(&lineage) {
                    return Err(BackendError::UnknownLineage(lineage));
                }

                Ok((lineage, ops))
            })
            .collect::<Result<Vec<_>>>()?;

        // Next, we compute all the relevant mutations to each tree, also failing with an error
        // where relevant.
        let mutations = updates
            .into_iter()
            .map(|(lineage, ops)| {
                let tree = self.trees.get(&lineage).expect("Tree known to be present was not");
                let mutations = tree.tree.compute_mutations(ops.into_iter().map(|o| o.into()))?;
                Ok((lineage, mutations))
            })
            .collect::<Result<Vec<_>>>()?;

        // With the preconditions checked, we can unconditionally perform the changes on all trees.
        let reversion_sets = mutations
            .into_iter()
            .map(|(lineage, mutations)| {
                if mutations.is_empty() {
                    // The inverse of empty mutations is empty mutations.
                    Ok((lineage, mutations))
                } else {
                    let tree =
                        self.trees.get_mut(&lineage).expect("Tree known to be present was not");
                    let reversion = tree
                        .tree
                        .apply_mutations_with_reversion(mutations)
                        .map_err(BackendError::internal_from)?;
                    tree.version = new_version;
                    Ok((lineage, reversion))
                }
            })
            .collect::<Result<Vec<_>>>()?;

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
