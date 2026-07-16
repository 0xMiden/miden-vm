//! Test and benchmark utilities for generating random data.
//!
//! This module provides helper functions for tests and benchmarks that need
//! random data generation. These functions replace the functionality previously
//! provided by winter-rand-utils.
//!
//! # no_std Compatibility
//!
//! This module provides both `std`-dependent and `no_std`-compatible functions:
//!
//! - **`std` required**: [`rand_value`], [`rand_array`], [`rand_vector`] use the thread-local RNG
//!   and require the `std` feature.
//! - **`no_std` compatible**: [`seeded_rng`], [`prng_array`], [`prng_vector`] use deterministic
//!   seeded PRNGs and work in `no_std` environments.
//!
//! For tests that should run in `no_std` mode, prefer using [`seeded_rng`] to obtain
//! a deterministic RNG instead of `rand::rng()`.

use alloc::{vec, vec::Vec};

use rand::{Rng, RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::rand::Randomizable;

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

/// Generates a random value of type T from an RNG.
fn rng_value<T: Randomizable>(rng: &mut impl Rng) -> T {
    let mut bytes = vec![0u8; T::VALUE_SIZE];
    rng.fill(&mut bytes[..]);
    T::from_random_bytes(&bytes).expect("failed to generate random value")
}

/// Generates a random value of type T using the thread-local random number generator.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::rand_value;
/// let x: u64 = rand_value();
/// let y: u128 = rand_value();
/// ```
#[cfg(feature = "std")]
pub fn rand_value<T: Randomizable>() -> T {
    rng_value(&mut rand::rng())
}

/// Generates a deterministic value of type `T` in `no_std` builds.
///
/// This keeps tests and feature-matrix checks buildable without relying on
/// thread-local RNG support.
#[cfg(not(feature = "std"))]
pub fn rand_value<T: Randomizable>() -> T {
    prng_value([0u8; 32])
}

/// Generates a random array of type T with N elements.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::rand_array;
/// let arr: [u64; 4] = rand_array();
/// ```
#[cfg(feature = "std")]
pub fn rand_array<T: Randomizable, const N: usize>() -> [T; N] {
    let mut rng = rand::rng();
    core::array::from_fn(|_| rng_value(&mut rng))
}

/// Generates a random vector of type T with the specified length.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::rand_vector;
/// let vec: Vec<u64> = rand_vector(100);
/// ```
#[cfg(feature = "std")]
pub fn rand_vector<T: Randomizable>(length: usize) -> Vec<T> {
    let mut rng = rand::rng();
    (0..length).map(|_| rng_value(&mut rng)).collect()
}

/// Generates a deterministic value using a PRNG seeded with the provided seed.
///
/// This function uses ChaCha20 PRNG for deterministic random generation, which is
/// useful for reproducible tests and benchmarks.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::prng_value;
/// let seed = [0u8; 32];
/// let val: u64 = prng_value(seed);
/// ```
pub fn prng_value<T: Randomizable>(seed: [u8; 32]) -> T {
    rng_value(&mut seeded_rng(seed))
}

/// Generates a deterministic array using a PRNG seeded with the provided seed.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::prng_array;
/// let seed = [0u8; 32];
/// let arr: [u64; 4] = prng_array(seed);
/// ```
pub fn prng_array<T: Randomizable, const N: usize>(seed: [u8; 32]) -> [T; N] {
    let mut rng = seeded_rng(seed);
    core::array::from_fn(|_| rng_value(&mut rng))
}

/// Generates a deterministic vector using a PRNG seeded with the provided seed.
///
/// # Examples
/// ```
/// # use miden_crypto::rand::test_utils::prng_vector;
/// let seed = [0u8; 32];
/// let vec: Vec<u64> = prng_vector(seed, 100);
/// ```
pub fn prng_vector<T: Randomizable>(seed: [u8; 32], length: usize) -> Vec<T> {
    let mut rng = seeded_rng(seed);
    (0..length).map(|_| rng_value(&mut rng)).collect()
}

// CONTINUOUS RNG
// ================================================================================================

/// A continuous random number generator that works in `no-std` contexts.
#[derive(Debug)]
pub struct ContinuousRng {
    rng: ChaCha20Rng,
}
impl ContinuousRng {
    /// Creates a new instance of the random number generator from the seed.
    pub fn new(seed: [u8; 32]) -> ContinuousRng {
        ContinuousRng { rng: ChaCha20Rng::from_seed(seed) }
    }

    /// Generates a random value of the [`Randomizable`] type `T`.
    pub fn value<T: Randomizable>(&mut self) -> T {
        rng_value(&mut self.rng)
    }
}
