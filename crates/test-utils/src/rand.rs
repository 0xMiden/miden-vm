// Re-export miden-crypto's Randomizable trait and core test utilities
#[cfg(feature = "std")]
pub use miden_crypto::test_utils::{prng_array, rand_array, rand_value, rand_vector};
pub use miden_crypto::utils::Randomizable;

use super::{Felt, Word};
#[cfg(feature = "std")]
use super::QuadFelt;

// Helper functions for generating random QuadFelt and Word values
// These work around orphan rules by providing functions instead of trait impls

#[cfg(feature = "std")]
pub fn rand_quad_felt() -> QuadFelt {
    QuadFelt::new_complex(rand_value(), rand_value())
}

#[cfg(feature = "std")]
pub fn rand_word() -> Word {
    Word::new(rand_array())
}

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

/// SplitMix64 hash function for mixing RNG state into high-quality random output.
fn splitmix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}
