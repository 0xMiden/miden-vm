//! Cryptographic hash functions, including standalone application primitives.

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

/// Stateful hashing traits and adapters.
pub mod stateful;

/// Poseidon2 hash function for standalone applications.
///
/// Preserves the original Miden Poseidon2 hashing API and digest format. The VM's native hash
/// function is Eidos; Poseidon2 is not a supported VM or precompile proof hash configuration.
pub mod poseidon2 {
    pub use p3_goldilocks::Poseidon2Goldilocks;

    pub use super::algebraic_sponge::poseidon2::{
        Poseidon2, Poseidon2Challenger, Poseidon2Compression, Poseidon2Hasher,
        Poseidon2Permutation256,
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
