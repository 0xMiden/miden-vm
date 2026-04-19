//! The error type and utility types for working with errors from the SMT history construct.
use thiserror::Error;

use crate::merkle::smt::large_forest::history::VersionId;

/// The type of errors returned by the history container.
#[derive(Debug, Error, PartialEq)]
pub enum HistoryError {
    /// Raised when a query expects the history to contain at least one entry, but it is empty.
    #[error("The history was empty")]
    HistoryEmpty,

    /// Raised when a version is added to the history and is not newer than the previous.
    #[error("Version {0} is not monotonic with respect to {1}")]
    NonMonotonicVersions(VersionId, VersionId),

    /// Raised when no version exists in the history for an arbitrary query.
    #[error("The specified version is too old to be served by the history")]
    VersionTooOld,
}

/// The result type for use within the history container.
pub type Result<T> = core::result::Result<T, HistoryError>;
