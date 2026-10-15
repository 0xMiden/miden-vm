//! Cryptographic hash functions used by the Miden protocol.

use crate::Felt;

/// Generic digest types for binary hash functions.
pub(crate) mod digest;

/// Blake3 hash function.
pub mod blake;

/// Eidos hash function.
pub mod eidos;

/// Keccak hash function.
pub mod keccak;

/// SHA-2 hash functions (SHA-256 and SHA-512).
pub mod sha2;

// TRAITS
// ================================================================================================

/// Extension trait for hashers to provide iterator-based hashing.
pub trait HasherExt {
    /// The digest type produced by this hasher.
    type Digest;

    /// Hashes an iterator of byte slices.
    ///
    /// This method allows for more efficient hashing by avoiding the need to
    /// allocate a contiguous buffer when the input data is already available
    /// as discrete slices.
    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest;
}
