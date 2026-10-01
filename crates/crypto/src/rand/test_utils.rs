//! Test utility for deterministic random data.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::Felt;

/// Creates a deterministic seeded RNG suitable for tests.
///
/// This function returns a ChaCha20 PRNG seeded with the provided seed, providing
/// deterministic random number generation that works in `no_std` environments.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::seeded_rng;
/// let mut rng = seeded_rng([0u8; 32]);
/// // Use rng with any function that accepts impl Rng
/// ```
pub fn seeded_rng(seed: [u8; 32]) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(seed)
}

/// Array-shaped variant of [`seeded_felts`] for sites that need a
/// fixed-length `[Felt; N]` (e.g. fixed-width state roundtrips).
pub fn seeded_felts_array<const N: usize>(seed: u8) -> [Felt; N] {
    let mut rng = seeded_rng([seed; 32]);
    core::array::from_fn(|_| {
        use rand::Rng;
        Felt::new_unchecked(rng.next_u64())
    })
}

/// Draws `n` field elements from a fixed-seed ChaCha stream: reproducible
/// don't-care test data for oracles that recompute their expectations from
/// the values. The elements use the full internal u64 range (possibly
/// non-canonical representations — fine for these hash oracles, unlike the
/// field crate's canonical-only `Standard` distribution).
pub fn seeded_felts(seed: u8, n: usize) -> alloc::vec::Vec<Felt> {
    use rand::Rng;
    let mut rng = seeded_rng([seed; 32]);
    (0..n)
        .map(|_| Felt::new_unchecked(rng.next_u64()))
        .collect::<alloc::vec::Vec<_>>()
}
