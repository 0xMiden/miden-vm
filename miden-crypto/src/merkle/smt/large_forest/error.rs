//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

use alloc::{boxed::Box, string::String};

use thiserror::Error;

use crate::merkle::{
    MerkleError,
    smt::{
        SmtLeafError, SmtProofError, TreeId, VersionId,
        large_forest::{backend::BackendError, history::error::HistoryError, root::LineageId},
    },
};

// LARGE SMT FOREST ERROR
// ================================================================================================

/// The type of errors returned by operations on the large SMT forest.
#[derive(Debug, Error)]
pub enum LargeSmtForestError {
    /// Raised when the provided version for any update is older than the latest-known version for
    /// the lineage being updated.
    #[error("Version {provided} is not newer than latest-known {latest}")]
    BadVersion { provided: VersionId, latest: VersionId },

    /// Raised when there is a conflict between an existing lineage ID and one already in the
    /// forest.
    #[error("Duplicate lineage ID {0} provided")]
    DuplicateLineage(LineageId),

    /// Raised for arbitrary errors that are not derived from user-input. These **must be considered
    /// fatal by the caller**, but exist to provide the caller with control over process termination
    /// (e.g. for improved diagnostics or error reporting) wherever possible.
    #[error(transparent)]
    Fatal(Box<dyn core::error::Error + Sync + Send>),

    /// Errors in the history subsystem of the forest.
    #[error(transparent)]
    History(#[from] HistoryError),

    /// Errors with the merkle tree operations of the forest.
    #[error(transparent)]
    Merkle(#[from] MerkleError),

    /// Errors in working with leaves in the merkle trees.
    #[error(transparent)]
    SmtLeaf(#[from] SmtLeafError),

    /// Errors in the construction and manipulation of SMT proofs.
    #[error(transparent)]
    SmtProof(#[from] SmtProofError),

    /// Raised when an operation specifies a lineage that is not known.
    #[error("The lineage {0:?} is not in the forest")]
    UnknownLineage(LineageId),

    /// Raised when an operation specifies a tree that is not known.
    #[error("The tree {0} is not in the forest")]
    UnknownTree(TreeId),

    /// Raised when an operation requests a version that is not known.
    #[error("The version {0} is not known by the forest")]
    UnknownVersion(VersionId),

    /// Raised for arbitrary other errors.
    #[error(transparent)]
    Other(#[from] Box<dyn core::error::Error + Sync + Send>),

    /// An unspecified, non-fatal error.
    #[error("Unspecified error: {0}")]
    Unspecified(String),
}

impl LargeSmtForestError {
    /// Constructs a fatal error variant from the provided concrete error `e`.
    pub fn fatal_from<E: core::error::Error + Sync + Send + 'static>(e: E) -> Self {
        Self::Fatal(Box::new(e))
    }
}

/// We want to forward backend errors specifically when we can, so we manually implement the
/// conversion.
impl From<BackendError> for LargeSmtForestError {
    fn from(value: BackendError) -> Self {
        match value {
            BackendError::CorruptedData(_) => LargeSmtForestError::fatal_from(value),
            BackendError::DuplicateLineage(l) => LargeSmtForestError::DuplicateLineage(l),
            BackendError::Internal(e) => LargeSmtForestError::Fatal(e),
            BackendError::Merkle(e) => LargeSmtForestError::from(e),
            BackendError::Other(e) => LargeSmtForestError::from(e),
            BackendError::UnknownLineage(t) => LargeSmtForestError::UnknownLineage(t),
            BackendError::Unspecified(msg) => LargeSmtForestError::Unspecified(msg),
        }
    }
}

/// The result type for use within the large SMT forest portion of the library.
pub type Result<T> = core::result::Result<T, LargeSmtForestError>;
