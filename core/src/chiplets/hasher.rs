//! Hasher for the Miden virtual machine based on Rpo256.
//!
//! This module provides wrappers around the [Rpo256] hash function, used in the Miden virtual machine
//! for cryptographic operations such as Merkle tree construction, hashing arrays of field elements, and more.
//!
//! Main features of this module:
//! - Hashing two digests (e.g., for Merkle tree construction).
//! - Hashing an arbitrary number of field elements.
//! - Applying a single round or the full permutation of the sponge function (Rescue-XLIX permutation).
//! - Exporting constants that define the parameters of the sponge construction (state width, rate length).
//!
//! All functions are thin wrappers around the [Rpo256] implementation from the `miden_crypto` crate.
//!
//! # Example usage
//! ```rust
//! use crate::chiplets::hasher::{merge, hash_elements, STATE_WIDTH};
//! // Hashing two digests
//! let digest = merge(&[digest1, digest2]);
//! // Hashing an array of field elements
//! let digest = hash_elements(&elements);
//! ```
//!
//! # Constants
//! - `STATE_WIDTH`: The width of the sponge state (12 field elements).
//! - `RATE_LEN`: The length of the rate portion of the state (8 field elements).
//!
//! # Types
//! - `Felt`: Field element type used in the VM.
//! - `Digest`: 256-bit digest (Word from miden_crypto).
//!
//! # About Rpo256
//! Rpo256 is a hash function built on a sponge construction with the Rescue-XLIX permutation,
//! optimized for use in zero-knowledge protocols and the Miden virtual machine.
//!
//! See also: [miden_crypto documentation](https://github.com/miden/miden-crypto)
//!
use miden_crypto::Word as Digest;

use super::Felt;
pub use crate::crypto::hash::Rpo256 as Hasher;

/// Number of field element needed to represent the sponge state for the hash function.
///
/// This value is set to 12: 8 elements are reserved for rate and the remaining 4 elements are
/// reserved for capacity. This configuration enables computation of 2-to-1 hash in a single
/// permutation.
pub const STATE_WIDTH: usize = Hasher::STATE_WIDTH;

/// Number of field elements in the rate portion of the hasher's state.
pub const RATE_LEN: usize = 8;

// PASS-THROUGH FUNCTIONS
// ================================================================================================

/// Returns a hash of two digests. This method is intended for use in construction of Merkle trees.
#[inline(always)]
pub fn merge(values: &[Digest; 2]) -> Digest {
    Hasher::merge(values)
}

/// Returns a hash of two digests with a specified domain.
#[inline(always)]
pub fn merge_in_domain(values: &[Digest; 2], domain: Felt) -> Digest {
    Hasher::merge_in_domain(values, domain)
}

/// Returns a hash of the provided list of field elements.
#[inline(always)]
pub fn hash_elements(elements: &[Felt]) -> Digest {
    Hasher::hash_elements(elements)
}

/// Applies Rescue-XLIX round function to the provided state.
///
/// The function takes sponge state as an input and applies a single Rescue-XLIX round to it. The
/// round number must be specified via `round` parameter, which must be between 0 and 6 (both
/// inclusive).
#[inline(always)]
pub fn apply_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
    Hasher::apply_round(state, round)
}

/// Applies Rescue-XLIX permutation (7 rounds) to the provided state.
#[inline(always)]
pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
    Hasher::apply_permutation(state)
}
