#[cfg(feature = "std")]
pub use miden_crypto::rand::{
    random_felt, random_word,
    test_utils::{rand_array, rand_value, rand_vector},
};

#[cfg(feature = "std")]
use super::QuadFelt;
use super::{Felt, Word};
// RANDOM GENERATORS
// ================================================================================================

/// Generates a random QuadFelt
#[cfg(feature = "std")]
pub fn rand_quad_felt() -> QuadFelt {
    QuadFelt::new_complex(rand_value(), rand_value())
}

// SEEDED GENERATORS
// ================================================================================================

pub fn seeded_word(seed: &mut u64) -> Word {
    let elements = [
        seeded_element(seed),
        seeded_element(seed),
        seeded_element(seed),
        seeded_element(seed),
    ];
    elements.into()
}

pub fn seeded_element(seed: &mut u64) -> Felt {
    *seed = (*seed).wrapping_add(0x9e37_79b9_7f4a_7c15);
    Felt::new(splitmix64(*seed))
}

// HELPERS
// ================================================================================================

/// SplitMix64 hash function for mixing RNG state into high-quality random output.
fn splitmix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}
