//! TODO: add docs
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
