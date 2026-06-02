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
                operation::SmtForestUpdateBatch,
                root::{LineageId, TreeEntry, TreeWithRoot, VersionId},
                utils::{AppliedLineageMutation, LineageMutation},
            },
        },
    },
};

// BACKEND READER
// ================================================================================================

/// The read-only interface for the SMT forest storage backend.
///
/// This trait provides the query operations necessary to read the full trees that make up the
/// forest. It is a supertrait of [`Backend`], which extends it with write operations.
///
/// # Backend Data Storage
///
/// Having a generic [`BackendReader`] provides no guarantees to the user about how it stores data
/// and what patterns are used for data access under the hood. It is, however, guaranteed to store
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
/// The following behavior is expected of all methods in implementations of this trait:
///
/// - For any failure derived from user input (see _User-Derived Errors_ above), the data and the
///   backend must be **left in a consistent state** when the error is returned to the caller.
/// - Failures derived from user input (see _User-Derived Errors_ above) must be signaled to the
///   caller by returning a variant of [`BackendError`] that is **not [`BackendError::Internal`]**.
///   Methods may place additional constraints on which errors are used to signal certain failures.
///   Such failures should not lead to data corruption of any persistent data.
pub trait BackendReader
where
    Self: Debug,
{
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
}

// BACKEND
// ================================================================================================

/// The full read-write interface for the SMT forest storage backend.
///
/// This trait extends [`BackendReader`] with mutation operations, allowing the forest to add new
/// lineages and update existing ones.
///
/// # Implementation Contract
///
/// Method-level doc comments describe invariants that cannot be encoded in the type system.
/// Implementations are responsible for upholding them.
pub trait Backend: BackendReader {
    /// The read-only view type returned by [`Self::reader`].
    ///
    /// The returned type implements [`BackendReader`] but not [`Backend`], providing a read-only
    /// guarantee. Implementations may return either a point-in-time snapshot or a live view, but
    /// the view must always reflect a consistent committed state (not partial writes). Holding the
    /// reader must not block writes in any way.
    type Reader: BackendReader;

    /// Backend-specific data prepared during mutation computation and consumed during application.
    ///
    /// This type is intentionally opaque to forest users. Implementations should store enough
    /// information here to apply the already-computed mutations without repeating the expensive
    /// tree update computation.
    ///
    /// The prepared value must represent only prospective changes. Computing it must not change
    /// the backend's committed state. It may contain ordinary SMT mutation sets, storage-level
    /// updates, serialized values, or any other implementation-specific data needed to apply the
    /// mutation efficiently later.
    type PreparedMutations;

    /// Returns a read-only view of this backend that observes its current state.
    fn reader(&self) -> Result<Self::Reader>;

    // TWO-PHASE MODIFIERS
    // ============================================================================================

    /// Computes the backend data required to mutate lineages, without applying it.
    ///
    /// # Expected Behavior
    ///
    /// Implementations must guarantee the following behavior in addition to the global invariants:
    ///
    /// - The backend's committed state must not change.
    /// - Each unknown lineage in `updates` is treated as an addition from the empty tree.
    /// - Each known lineage in `updates` is treated as an update to its latest tree.
    /// - Each lineage in `updates` must produce at most one [`LineageMutation`].
    /// - No-op lineage updates must not allocate new backend tree versions when applied.
    /// - The prepared mutations must be applicable atomically by [`Self::apply_mutations`] where
    ///   the backend supports atomic writes.
    fn compute_mutations(
        &self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> Result<(Vec<LineageMutation>, Self::PreparedMutations)>;

    /// Applies previously-computed backend mutations.
    ///
    /// This method consumes the opaque prepared data returned by one of the backend compute
    /// methods. It commits the backend's latest-tree state and returns the applied lineage data
    /// needed by [`crate::merkle::smt::LargeSmtForest`] to update forest-level lineage metadata and
    /// history.
    ///
    /// # Expected Behavior
    ///
    /// Implementations must guarantee the following behavior in addition to the global invariants:
    ///
    /// - The prepared mutation data must still be applicable to the current backend state before
    ///   any mutation is written. For updates, the current version and root must match the
    ///   version/root captured during the compute phase. For additions, the lineage must still be
    ///   absent.
    /// - User-derived errors must leave the backend in a consistent committed state.
    /// - If the prepared data contains multiple lineage updates, they should be committed
    ///   atomically when the backend's storage engine supports atomic batched writes.
    /// - The method must not recompute Merkle mutations from the original user updates; that work
    ///   belongs to the compute methods.
    /// - On success, the returned [`AppliedLineageMutation`] values must correspond to the applied
    ///   prepared mutations in the same lineage set, including reverse mutations and old entry
    ///   counts for update history.
    fn apply_mutations(
        &mut self,
        mutations: Self::PreparedMutations,
    ) -> Result<Vec<AppliedLineageMutation>>;
}

// BACKEND ERROR
// ================================================================================================

/// The error type for use within Backends.
#[derive(Debug, Error)]
pub enum BackendError {
    /// Raised when an update was prepared against a version that is no longer current.
    #[error("Version {provided} is not current backend version {latest}")]
    BadVersion { provided: VersionId, latest: VersionId },

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
