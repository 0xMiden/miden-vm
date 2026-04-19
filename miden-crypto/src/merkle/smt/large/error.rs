use thiserror::Error;

use super::{MerkleError, StorageError};
use crate::Word;

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during LargeSmt operations.
#[derive(Debug, Error)]
pub enum LargeSmtError {
    /// A Merkle tree operation failed.
    #[error("merkle operation failed")]
    Merkle(#[from] MerkleError),

    /// A storage operation failed.
    #[error("storage operation failed")]
    Storage(#[from] StorageError),

    /// The reconstructed root does not match the expected root.
    #[error("root mismatch: expected {expected:?}, got {actual:?}")]
    RootMismatch {
        /// The expected root hash.
        expected: Word,
        /// The actual reconstructed root hash.
        actual: Word,
    },

    /// Storage already contains data when trying to create a new tree.
    ///
    /// Use [`super::LargeSmt::load_with_root()`] or [`super::LargeSmt::load()`] to load
    /// existing storage.
    #[error("storage is not empty")]
    StorageNotEmpty,
}

#[cfg(test)]
// Compile-time assertion that LargeSmtError implements the required traits
const _: fn() = || {
    fn assert_impl<T: std::error::Error + Send + Sync + 'static>() {}
    assert_impl::<LargeSmtError>();
    assert_impl::<MerkleError>();
    assert_impl::<StorageError>();
};
