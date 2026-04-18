use alloc::{boxed::Box, string::String};

/// Errors returned by any `SmtStorage` implementation.
///
/// Categories:
/// - Backend errors (DB/I/O)
/// - Decode/length mismatches with expected/actual parameters
/// - Unsupported operations
/// - Higher-level value and subtree decode failures
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Backend I/O or database error (e.g., RocksDB).
    #[error("backend error: {0}")]
    Backend(#[from] Box<dyn core::error::Error + Send + Sync + 'static>),
    /// Key bytes had the wrong length (e.g., leaf index key, subtree root key).
    #[error("invalid key length: expected {expected} bytes, found {found}")]
    BadKeyLen { expected: usize, found: usize },
    /// Subtree key bytes had the wrong length (e.g., subtree root key).
    #[error(
        "invalid subtree key length at depth {depth}: expected {expected} bytes, found {found}"
    )]
    BadSubtreeKeyLen { depth: u8, expected: usize, found: usize },
    /// Value/metadata bytes had the wrong length (e.g., leaf/entry counts).
    #[error("invalid value length for {what}: expected {expected} bytes, found {found}")]
    BadValueLen {
        what: &'static str,
        expected: usize,
        found: usize,
    },
    /// Leaf-level error (e.g., too many entries).
    #[error("leaf operation failed")]
    Leaf(#[from] crate::merkle::smt::SmtLeafError),
    /// Failed to (de)serialize a stored subtree blob.
    #[error("failed to decode subtree")]
    Subtree(#[from] crate::merkle::smt::SubtreeError),
    /// The requested operation is not supported by this backend.
    #[error("operation not supported: {0}")]
    Unsupported(String),
    /// Higher-level type (e.g., `Word`) failed to decode from bytes.
    #[error("failed to decode value bytes")]
    Value(#[from] crate::utils::DeserializationError),
}
