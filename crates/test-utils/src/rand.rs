pub use winter_rand_utils::*;

use super::{Felt, WORD_SIZE, Word};

// SEEDED GENERATORS
// ================================================================================================

/// Mutates a seed and generates a word deterministically
pub fn seeded_word(seed: &mut u64) -> Word {
    let seed = generate_bytes_seed(seed);
    prng_array::<Felt, WORD_SIZE>(seed).into()
}

/// Mutates a seed and generates an element deterministically
pub fn seeded_element(seed: &mut u64) -> Felt {
    let seed = generate_bytes_seed(seed);
    let num = prng_array::<u64, 1>(seed)[0];
    Felt::new(num)
}

// HELPERS
// ================================================================================================

/// Generate a bytes seed that can be used as input for rand_utils.
///
/// Increments the argument.
fn generate_bytes_seed(seed: &mut u64) -> [u8; 32] {
    // increment the seed
    *seed = seed.wrapping_add(1);

    // generate a bytes seed
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes
}
