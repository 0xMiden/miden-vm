//! Test utility for deterministic random data.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

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
