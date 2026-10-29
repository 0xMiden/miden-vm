//! Randomness indexing shared by runtime input layouts.

use crate::layout::InputRegion;

/// Derive alpha/beta input indices from a randomness region.
///
/// Returns `(alpha_idx, beta_idx)` matching the memory-word layout `[beta, alpha]`.
pub(crate) fn aux_rand_indices(randomness: InputRegion) -> (usize, usize) {
    // Stored as [beta, alpha] in memory words.
    let beta_idx = randomness.index(0).expect("randomness region must have at least 2 slots");
    let alpha_idx = randomness.index(1).expect("randomness region must have at least 2 slots");
    (alpha_idx, beta_idx)
}
