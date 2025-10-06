use core::fmt::Debug;
use std::vec::Vec;

use miden_core::PrimeCharacteristicRing;
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
    prelude::*,
};
pub use winter_rand_utils::*;

use super::{Felt, WORD_SIZE, Word};

// SEEDED GENERATORS
// ================================================================================================

/// Mutates a seed and generates a word deterministically
pub fn seeded_word(seed: &mut u64) -> Word {
    let mut rng = SmallRng::seed_from_u64(*seed);
    *seed = rng.next_u64();
    [
        Felt::new(rng.next_u64()),
        Felt::new(rng.next_u64()),
        Felt::new(rng.next_u64()),
        Felt::new(rng.next_u64()),
    ]
    .into()
}

/// Mutates a seed and generates an element deterministically
pub fn seeded_element(seed: u64) -> Felt {
    let mut rng = SmallRng::seed_from_u64(seed);
    let num = rng.next_u64();
    Felt::new(num)
}

// RANDOM VALUE GENERATION
// ============================================================================================

/// Returns a single random value of the specified type.
///
/// # Panics
/// Panics if:
/// * A valid value requires over 32 bytes.
/// * A valid value could not be generated after 1000 tries.
pub fn rand_value<R>() -> R
where
    R: Default,
    StandardUniform: Distribution<R>,
{
    rand::rng().sample(StandardUniform)
}

/// Returns a vector of random value of the specified type and the specified length.
///
/// # Panics
/// Panics if:
/// * A valid value requires at over 32 bytes.
/// * A valid value could not be generated after 1000 tries.
pub fn rand_vector<R>(n: usize) -> Vec<R>
where
    StandardUniform: Distribution<R>,
{
    let mut result = Vec::with_capacity(n);
    let mut rng: ThreadRng = rand::rng();
    for _ in 0..n {
        result.push(rng.sample(StandardUniform));
    }
    result
}

/// Returns an array of random value of the specified type and the specified length.
///
/// # Panics
/// Panics if:
/// * A valid value requires at over 32 bytes.
/// * A valid value could not be generated after 1000 tries.
pub fn rand_array<R, const N: usize>() -> [R; N]
where
    R: Debug,
    StandardUniform: Distribution<R>,
{
    let elements = rand_vector(N);
    elements.try_into().expect("failed to convert vector to array")
}

/// Returns a vector of value of the specified type and the specified length generated
/// pseudo-randomly from the specified `seed`.
///
/// # Panics
/// Panics if:
/// * A valid value requires at over 32 bytes.
/// * A valid value could not be generated after 1000 tries.
pub fn prng_vector<R>(seed: [u8; 32], n: usize) -> Vec<R>
where
    R: Default,
    StandardUniform: Distribution<R>,
{
    let mut result = Vec::with_capacity(n);
    let mut rng = SmallRng::from_seed(seed);

    for _ in 0..n {
        result.push(rng.sample(StandardUniform));
    }
    result
}

/// Returns an array of value of the specified type and the specified length generated
/// pseudo-randomly from the specified `seed`.
///
/// # Panics
/// Panics if:
/// * A valid value requires at over 32 bytes.
/// * A valid value could not be generated after 1000 tries.
pub fn prng_array<R: Debug + Default, const N: usize>(seed: [u8; 32]) -> [R; N]
where
    R: Default,
    StandardUniform: Distribution<R>,
{
    let elements = prng_vector(seed, N);
    elements.try_into().expect("failed to convert vector to array")
}

// SHUFFLING
// ============================================================================================

/// Randomly shuffles slice elements.
pub fn shuffle<T>(values: &mut [T]) {
    values.shuffle(&mut rand::rng());
}
