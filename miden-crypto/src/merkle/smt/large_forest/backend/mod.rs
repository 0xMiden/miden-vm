//! This file contains the [`Backend`] trait for the SMT forest implementation and the supporting
//! types it needs.

pub mod memory;
#[cfg(feature = "persistent-forest")]
pub mod persistent;

use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt::Debug;

use thiserror::Error;

use crate::{
    Word,
    merkle::{
        MerkleError,
        smt::{
            LeafIndex, SMT_DEPTH, SmtLeaf, SmtProof,
            large_forest::{
                operation::{SmtForestUpdateBatch, SmtUpdateBatch},
                root::{LineageId, TreeEntry, TreeWithRoot, VersionId},
                utils::MutationSet,
            },
        },
    },
};

// BACKEND
// ================================================================================================

/// The backing storage for the SMT forest, providing the necessary high-level methods for
/// performing operations on the full trees that make up the forest, while allowing the forest
/// itself to be storage agnostic.
///
/// # Backend Data Storage
///
/// Having a generic [`Backend`] provides no guarantees to the user about how it stores data and
/// what patterns are used for data access under the hood. It is, however, guaranteed to store
/// _only_ the data necessary to describe the latest state of each tree in the forest.
///
/// # Error Handling
///
/// We separate errors in backend implementations into two semantic categories:
///
/// 1. **User-Derived Errors:** These are errors that arise downstream of data provided by the user.
///    These errors must be signaled by returning an [`Err`] variant with an appropriate error.
/// 2. **Internal Errors:** These are errors that are not derived from data provided by the user.
///    Signaling such an error is up to the implementation, but can be done through both panicking
///    and returning the [`BackendError::Internal`] variant as appropriate. These **may leave the
///    backend in an inconsistent state** as they are designed to effect program termination or
///    perform it directly.
///
/// The only reason that [`BackendError::Internal`] exists is to allow certain failures to result in
/// termination at the level of the _forest_ instead of the _backend_ as this can sometimes lead to
/// cleaner logic. If this is not appropriate, a panic is a better option.
///
/// # Expected Behavior
///
/// Certain methods on this trait (e.g. [`Backend::update_tree`]) provide behaviors expected for
/// that method. These combine with the following trait-level behavior requirements to become part
/// of the contract of the method, but a portion that cannot be encoded in the type system. Any
/// failure to conform to these expected behaviors is **considered a bug in the implementation** of
/// the backend, and must be rectified.
///
/// The following behavior is expected of all methods in implementations of this trait:
///
/// - For any failure derived from user input (see _User-Derived Errors_ above), the data and the
///   backend must be **left in a consistent state** when the error is returned to the caller.
/// - Failures derived from user input (see _User-Derived Errors_ above) must be signaled to the
///   caller by returning a variant of [`BackendError`] that is **not [`BackendError::Internal`]**.
///   Methods may place additional constraints on which errors are used to signal certain failures.
///   Such failures should not lead to data corruption of any persistent data.
pub trait Backend
where
    Self: Debug,
{
    // QUERIES
    // ============================================================================================

    /// Returns an opening for the specified `key` in the SMT with the specified `lineage`.
    ///
    /// It is the responsibility of the forest to ensure lineage existence before querying the
    /// backend. The backend must return an error if the lineage does not exist.
    fn open(&self, lineage: LineageId, key: Word) -> Result<SmtProof>;

    /// Returns the leaf stored at the provided `leaf_index` in the SMT with the specified
    /// `lineage`. If no leaf is explicitly stored at the given index, the backend must return
    /// an empty leaf for that index.
    ///
    /// It is the responsibility of the forest to ensure lineage existence before querying the
    /// backend. The backend must return an error if the lineage does not exist.
    fn get_leaf(&self, lineage: LineageId, leaf_index: LeafIndex<SMT_DEPTH>) -> Result<SmtLeaf>;

    /// Returns the value associated with the provided `key` in the SMT with the specified
    /// `lineage`, or [`None`] if no such value exists.
    ///
    /// It is the responsibility of the forest to ensure lineage existence before querying the
    /// backend. The backend must return an error if the lineage does not exist.
    fn get(&self, lineage: LineageId, key: Word) -> Result<Option<Word>>;

    /// Returns the version of the tree with the specified `lineage`.
    ///
    /// It is the responsibility of the forest to ensure lineage existence before querying the
    /// backend. The backend must return an error if the lineage does not exist.
    fn version(&self, lineage: LineageId) -> Result<VersionId>;

    /// Returns an iterator over all the lineages that the backend knows about.
    ///
    /// The iteration order is unspecified.
    fn lineages(&self) -> Result<impl Iterator<Item = LineageId>>;

    /// Returns an iterator over all the trees (and their corresponding roots) that the backend
    /// knows about.
    ///
    /// The iteration order is unspecified.
    fn trees(&self) -> Result<impl Iterator<Item = TreeWithRoot>>;

    /// Returns the total number of (key-value) entries in the specified `lineage`.
    ///
    /// It is the responsibility of the forest to ensure lineage existence before querying the
    /// backend. The backend must return an error if the lineage does not exist.
    ///
    /// # Expected Behavior
    ///
    /// Implementations must guarantee the following behavior in addition to the global invariants:
    ///
    /// - This method must be **cheap** to call, not requiring network or disk I/O to service the
    ///   result. This usually implies in-memory caching of the data.
    /// - This method must not return errors other than if the lineage does not exist.
    fn entry_count(&self, lineage: LineageId) -> Result<usize>;

    /// Returns an iterator that yields the populated (key-value) entries for the specified
    /// `lineage`.
    ///
    /// It is the responsibility of the forest to ensure lineage existence before querying the
    /// backend. The backend must return an error if the lineage does not exist.
    ///
    /// The iterator may yield entries in any arbitrary order, but must not yield entries for which
    /// the value is the empty word.
    ///
    /// # Expected Behavior
    ///
    /// Implementations must guarantee the following behavior in addition to the global invariants:
    ///
    /// - If any kind of error occurs during iteration that should be signaled to the user, the
    ///   iterator must return `Some(Err(...))`. The caller should stop iteration after receiving an
    ///   error as the iterator state is no longer valid.
    /// - `None` will be returned upon successful completion, or at any time after an error has been
    ///   returned.
    fn entries(&self, lineage: LineageId) -> Result<impl Iterator<Item = Result<TreeEntry>>>;

    // SINGLE-TREE MODIFIERS
    // ============================================================================================

    /// Adds a new `lineage` to the forest with the provided `version` and sets the associated SMT
    /// to have the value created by applying `updates` to the empty tree, returning the new root of
    /// that tree.
    ///
    /// # Expected Behavior
    ///
    /// Implementations must guarantee the following behavior in addition to the global invariants:
    ///
    /// - If the provided `lineage` conflicts with an already-existing lineage in the backend, it
    ///   must return [`BackendError::DuplicateLineage`].
    fn add_lineage(
        &mut self,
        lineage: LineageId,
        version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<TreeWithRoot>;

    /// Performs the provided `updates` on the tree with the specified `lineage`, returning the
    /// mutation set that will revert the changes made to the tree.
    ///
    /// # Expected Behavior
    ///
    /// Implementations must guarantee the following behavior in addition to the global invariants:
    ///
    /// - At most one new root must be added to the forest for the entire batch.
    /// - If applying the provided `updates` results in no changes to the tree, no new tree must be
    ///   allocated.
    fn update_tree(
        &mut self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<MutationSet>;

    // MULTI-TREE MODIFIERS
    // ============================================================================================

    /// Adds multiple new `lineages` to the backend with the provided `version` and sets the
    /// associated SMTs to have the value created by applying the provided updates to the empty
    /// tree, returning the new root of that tree.
    ///
    /// # Expected Behavior
    ///
    /// Implementations must guarantee the following behavior in addition to the global invariants:
    ///
    /// - If any provided lineage conflicts with an already-existing lineage in the backend, it must
    ///   return [`BackendError::DuplicateLineage`].
    fn add_lineages(
        &mut self,
        version: VersionId,
        lineages: SmtForestUpdateBatch,
    ) -> Result<Vec<(LineageId, TreeWithRoot)>>;

    /// Performs the provided `updates` on the forest, setting all new tree states to have the
    /// provided `new_version` and returning a vector of the mutation sets that reverse the changes
    /// to each changed tree.
    ///
    /// # Expected Behavior
    ///
    /// Implementations must guarantee the following behavior in addition to the global invariants:
    ///
    /// - At most one new root must be added to the forest for each target root in the provided
    ///   `updates`.
    /// - If applying the provided `updates` results in no changes to a given lineage of trees in
    ///   the forest, then no new tree must be allocated in that lineage.
    fn update_forest(
        &mut self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> Result<Vec<(LineageId, MutationSet)>>;
}

// BACKEND ERROR
// ================================================================================================

/// The error type for use within Backends.
#[derive(Debug, Error)]
pub enum BackendError {
    /// Raised when corrupted data is encountered in the backend.
    ///
    /// It exists as a separate error variant to allow the forest itself to handle it better if
    /// possible, but should be considered a fatal error.
    #[error("Backend data corruption encountered: {0}")]
    CorruptedData(String),

    /// Raised when there is a conflict between an existing lineage ID and one already in the
    /// forest.
    #[error("Duplicate lineage ID {0} provided")]
    DuplicateLineage(LineageId),

    /// Raised for arbitrary errors that are not derived from user-input. These should be considered
    /// fatal by callers, but exist to forward the termination decision up to an appropriate level.
    #[error(transparent)]
    Internal(Box<dyn core::error::Error + Sync + Send>),

    /// Raised when there is an error with the merkle tree semantics within the backend.
    #[error(transparent)]
    Merkle(#[from] MerkleError),

    /// Raised for arbitrary other errors within the backend that are derived from user-input and
    /// hence non-fatal.
    #[error(transparent)]
    Other(Box<dyn core::error::Error + Sync + Send>),

    /// Raised when the backend is queried for a lineage it doesn't know about.
    #[error("Lineage {0} is not known by the backend")]
    UnknownLineage(LineageId),

    /// Raised for other errors in the backend that are user-specified.
    #[error("Unspecified error: {0}")]
    Unspecified(String),
}

impl BackendError {
    /// Constructs an internal error variant from the provided concrete error `e`.
    fn internal_from<E: core::error::Error + Sync + Send + 'static>(e: E) -> Self {
        Self::Internal(Box::new(e))
    }

    /// Constructs an internal error variant from the provided `message`.
    #[cfg(feature = "persistent-forest")]
    fn internal_from_message(message: impl Into<String>) -> Self {
        Self::internal_from(Self::Unspecified(message.into()))
    }
}

/// The result type for use with backends.
pub type Result<T> = core::result::Result<T, BackendError>;
