//! Contains utility types, aliases, and functions for use as part of the SMT forest.

use alloc::vec::Vec;

use crate::{
    Word,
    merkle::smt::{
        full::SMT_DEPTH,
        large_forest::{
            backend::Backend,
            root::{LineageId, TreeWithRoot, VersionId},
        },
    },
};

// TYPE ALIASES
// ================================================================================================

/// The mutation set used by the forest backends to provide reverse mutations that describe the
/// changes necessary to revert the tree to its previous state.
pub type MutationSet = crate::merkle::smt::MutationSet<SMT_DEPTH, Word, Word>;

// FOREST MUTATIONS
// ================================================================================================

/// A prospective set of mutations to a forest.
///
/// This is the forest-level analogue of [`crate::merkle::smt::MutationSet`]. It represents changes
/// that have already been computed but have not yet been committed to the underlying backend or to
/// the forest's lineage metadata.
///
/// A mutation set has two parts:
///
/// - inspectable [`LineageMutation`] entries, which expose the affected lineages, requested
///   versions, old roots, and proposed new roots; and
/// - backend-specific prepared data, which is intentionally opaque and is consumed by
///   [`crate::merkle::smt::LargeSmtForest::apply_mutations`].
///
/// The type is parameterized by the backend because different backend implementations may prepare
/// different internal data. For example, an in-memory backend can keep regular SMT mutation sets,
/// while a persistent backend can keep storage-level updates that avoid recomputing the tree walk
/// during application.
///
/// Values of this type are only valid for the forest state against which they were computed.
/// Applying them after the target lineage has changed will fail during forest-level validation.
pub struct SmtForestMutationSet<B: Backend> {
    entries: Vec<LineageMutation>,
    prepared: B::PreparedMutations,
}

impl<B: Backend> SmtForestMutationSet<B> {
    /// Constructs a forest mutation set from inspectable lineage entries and backend-prepared data.
    ///
    /// This constructor is crate-private because only forest/backend code can maintain the
    /// invariant that the public lineage metadata and opaque prepared data describe the same set of
    /// changes.
    pub(crate) fn new(entries: Vec<LineageMutation>, prepared: B::PreparedMutations) -> Self {
        Self { entries, prepared }
    }

    /// Returns the lineage-level mutations in this set.
    ///
    /// Callers can use this to inspect the old and new roots for each affected lineage before
    /// committing the mutation set. The returned entries are read-only; the opaque backend portion
    /// of the mutation set remains unavailable so that callers cannot accidentally break the link
    /// between the visible metadata and the prepared backend data.
    pub fn lineage_mutations(&self) -> &[LineageMutation] {
        &self.entries
    }

    /// Returns the roots that would be observed after successfully applying this mutation set.
    ///
    /// This is a convenience view over [`Self::lineage_mutations`]. For update mutations that do
    /// not change the underlying tree, the returned [`TreeWithRoot`] uses the existing latest
    /// version rather than the requested new version, matching the behavior of
    /// [`crate::merkle::smt::LargeSmtForest::update_tree`] and
    /// [`crate::merkle::smt::LargeSmtForest::update_forest`].
    pub fn roots(&self) -> impl Iterator<Item = TreeWithRoot> + '_ {
        self.entries.iter().map(LineageMutation::result)
    }

    /// Consumes this value into its inspectable entries and backend-prepared mutation data.
    ///
    /// This is crate-private for the same reason as [`Self::new`]: only the forest can safely
    /// coordinate applying the backend data and then updating lineage metadata/history from the
    /// inspectable entries.
    pub(crate) fn into_parts(self) -> (Vec<LineageMutation>, B::PreparedMutations) {
        (self.entries, self.prepared)
    }
}

/// A prospective mutation to one lineage in a forest.
///
/// This type records only inspectable metadata that callers need before committing a mutation set:
/// affected lineage, version transition, root transition, and mutation kind. Backend-specific
/// mutation data, including forward and reverse SMT mutation sets, stays in opaque backend
/// prepared data until [`crate::merkle::smt::LargeSmtForest::apply_mutations`] commits it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageMutation {
    lineage: LineageId,
    old_version: Option<VersionId>,
    new_version: VersionId,
    old_root: Word,
    new_root: Word,
    kind: LineageMutationKind,
}

impl LineageMutation {
    /// Constructs a lineage mutation.
    ///
    /// This constructor is crate-private because callers must not be able to fabricate mutation
    /// metadata that is inconsistent with the backend-prepared data in an [`SmtForestMutationSet`].
    pub(crate) fn new(
        lineage: LineageId,
        old_version: Option<VersionId>,
        new_version: VersionId,
        old_root: Word,
        new_root: Word,
        kind: LineageMutationKind,
    ) -> Self {
        Self {
            lineage,
            old_version,
            new_version,
            old_root,
            new_root,
            kind,
        }
    }

    /// Returns the affected lineage.
    pub fn lineage(&self) -> LineageId {
        self.lineage
    }

    /// Returns the previous version for update mutations, or `None` for new lineages.
    ///
    /// This value is used by [`crate::merkle::smt::LargeSmtForest::apply_mutations`] to reject
    /// stale mutation sets. For updates, it must still match the latest version in the forest when
    /// the mutation set is applied.
    pub fn old_version(&self) -> Option<VersionId> {
        self.old_version
    }

    /// Returns the requested new version.
    ///
    /// For an update that does not change the tree, this version is the version requested by the
    /// compute call, but the lineage will not advance when the mutation set is applied.
    pub fn new_version(&self) -> VersionId {
        self.new_version
    }

    /// Returns the root before this mutation.
    ///
    /// For updates, this must match the current latest root when the mutation set is applied. For a
    /// new lineage, this is the empty SMT root from which the initial tree is computed.
    pub fn old_root(&self) -> Word {
        self.old_root
    }

    /// Returns the root after this mutation.
    ///
    /// This is the root commitment that callers usually inspect before deciding whether to commit a
    /// computed mutation set.
    pub fn new_root(&self) -> Word {
        self.new_root
    }

    /// Returns the mutation kind.
    pub fn kind(&self) -> LineageMutationKind {
        self.kind
    }

    /// Returns the root information this mutation would produce if applied.
    ///
    /// For no-op update mutations, this returns the old version and old root, since applying such a
    /// mutation does not allocate a new tree version. For new-lineage mutations and non-empty
    /// update mutations, this returns the requested new version and computed new root.
    pub fn result(&self) -> TreeWithRoot {
        let version =
            if self.kind == LineageMutationKind::UpdateTree && self.old_root == self.new_root {
                self.old_version.expect("update tree mutations always have an old version")
            } else {
                self.new_version
            };
        TreeWithRoot::new(self.lineage, version, self.new_root)
    }
}

/// Data returned by a backend after applying prepared mutations.
///
/// The forest uses this data to update lineage metadata and historical views after the backend has
/// committed its latest-tree state. Unlike [`LineageMutation`], this type includes the reverse SMT
/// mutation set and old entry count because those are only needed after a successful apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedLineageMutation {
    lineage: LineageId,
    old_version: Option<VersionId>,
    new_version: VersionId,
    old_root: Word,
    new_root: Word,
    old_entry_count: usize,
    reverse: MutationSet,
    kind: LineageMutationKind,
}

impl AppliedLineageMutation {
    /// Constructs an applied lineage mutation.
    ///
    /// This constructor is crate-private because backend implementations must keep the returned
    /// history payload consistent with the prepared mutation data they just applied.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        lineage: LineageId,
        old_version: Option<VersionId>,
        new_version: VersionId,
        old_root: Word,
        new_root: Word,
        old_entry_count: usize,
        reverse: MutationSet,
        kind: LineageMutationKind,
    ) -> Self {
        Self {
            lineage,
            old_version,
            new_version,
            old_root,
            new_root,
            old_entry_count,
            reverse,
            kind,
        }
    }

    /// Returns the affected lineage.
    pub fn lineage(&self) -> LineageId {
        self.lineage
    }

    /// Returns the previous version for update mutations, or `None` for new lineages.
    pub fn old_version(&self) -> Option<VersionId> {
        self.old_version
    }

    /// Returns the requested new version.
    pub fn new_version(&self) -> VersionId {
        self.new_version
    }

    /// Returns the root before this mutation.
    pub fn old_root(&self) -> Word {
        self.old_root
    }

    /// Returns the root after this mutation.
    pub fn new_root(&self) -> Word {
        self.new_root
    }

    /// Returns the entry count before this mutation.
    pub fn old_entry_count(&self) -> usize {
        self.old_entry_count
    }

    /// Returns the reverse mutation set for this lineage.
    pub fn reverse(&self) -> &MutationSet {
        &self.reverse
    }

    /// Consumes this mutation and returns the reverse mutation set.
    pub(crate) fn into_reverse(self) -> MutationSet {
        self.reverse
    }

    /// Returns the mutation kind.
    pub fn kind(&self) -> LineageMutationKind {
        self.kind
    }

    /// Returns the root information produced by this applied mutation.
    ///
    /// For no-op update mutations, this returns the old version, since applying such a
    /// mutation does not allocate a new tree version. For new-lineage mutations and non-empty
    /// update mutations, this returns the requested new version and computed new root.
    pub fn result(&self) -> TreeWithRoot {
        let version =
            if self.kind == LineageMutationKind::UpdateTree && self.old_root == self.new_root {
                self.old_version.expect("update tree mutations always have an old version")
            } else {
                self.new_version
            };
        TreeWithRoot::new(self.lineage, version, self.new_root)
    }
}

/// The operation represented by a lineage mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineageMutationKind {
    /// A new lineage is being added.
    AddLineage,
    /// An existing lineage is being updated.
    UpdateTree,
}
