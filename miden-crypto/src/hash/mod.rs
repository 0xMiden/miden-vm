//! Cryptographic hash functions used by the Miden protocol.

use crate::{Felt, Word, ZERO};

/// Generic digest types for binary hash functions.
pub(crate) mod digest;

/// Blake3 hash function.
pub mod blake;

/// Keccak hash function.
pub mod keccak;

/// SHA-2 hash functions (SHA-256 and SHA-512).
pub mod sha2;

/// Poseidon2 hash function.
pub mod poseidon2 {
    pub use p3_goldilocks::Poseidon2Goldilocks;

    pub use super::algebraic_sponge::poseidon2::{
        Poseidon2, Poseidon2Challenger, Poseidon2Compression, Poseidon2Hasher,
        Poseidon2Permutation256,
    };
}

/// Rescue Prime Optimized (RPO) hash function.
pub mod rpo {
    pub use super::algebraic_sponge::rescue::rpo::{
        Rpo256, RpoChallenger, RpoCompression, RpoHasher, RpoPermutation256,
    };
}

/// Rescue Prime Extended (RPX) hash function.
pub mod rpx {
    pub use super::algebraic_sponge::rescue::rpx::{
        Rpx256, RpxChallenger, RpxCompression, RpxHasher, RpxPermutation256,
    };
}

mod algebraic_sponge;

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
