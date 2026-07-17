//! Pseudo-random element generation.

use rand::Rng;

use crate::{Felt, Word};

mod coin;
pub use coin::RandomCoin;

// Test utilities for generating random data (used in tests and benchmarks)
#[cfg(any(test, feature = "std"))]
pub mod test_utils;

// RANDOMNESS (ported from Winterfell's winter-utils)
// ================================================================================================

/// Defines how `Self` can be read from a sequence of random bytes.
pub trait Randomizable: Sized {
    /// Size of `Self` in bytes.
    ///
    /// This is used to determine how many bytes should be passed to the
    /// [from_random_bytes()](Self::from_random_bytes) function.
    const VALUE_SIZE: usize;

    /// Returns `Self` if the set of bytes forms a valid value, otherwise returns None.
    fn from_random_bytes(source: &[u8]) -> Option<Self>;
}

impl Randomizable for u128 {
    const VALUE_SIZE: usize = 16;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        let bytes = source.get(..Self::VALUE_SIZE)?.try_into().ok()?;
        Some(u128::from_le_bytes(bytes))
    }
}

impl Randomizable for u64 {
    const VALUE_SIZE: usize = 8;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        let bytes = source.get(..Self::VALUE_SIZE)?.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }
}

impl Randomizable for u32 {
    const VALUE_SIZE: usize = 4;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        let bytes = source.get(..Self::VALUE_SIZE)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }
}

impl Randomizable for u16 {
    const VALUE_SIZE: usize = 2;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        let bytes = source.get(..Self::VALUE_SIZE)?.try_into().ok()?;
        Some(u16::from_le_bytes(bytes))
    }
}

impl Randomizable for u8 {
    const VALUE_SIZE: usize = 1;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        source.first().copied()
    }
}

impl Randomizable for Felt {
    const VALUE_SIZE: usize = 8;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        let bytes = source.get(..Self::VALUE_SIZE)?.try_into().ok()?;
        let value = u64::from_le_bytes(bytes);
        // Ensure the value is within the field modulus
        if value < Felt::ORDER {
            Some(Felt::new_unchecked(value))
        } else {
            None
        }
    }
}

impl Randomizable for Word {
    const VALUE_SIZE: usize = Word::SERIALIZED_SIZE;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes_array: [u8; 32] = bytes.get(..Self::VALUE_SIZE)?.try_into().ok()?;
        Self::try_from(bytes_array).ok()
    }
}

impl<const N: usize> Randomizable for [u8; N] {
    const VALUE_SIZE: usize = N;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        source.get(..N)?.try_into().ok()
    }
}

/// Pseudo-random element generator.
///
/// An instance can be used to draw, uniformly at random, base field elements as well as [Word]s.
pub trait FeltRng: Rng {
    /// Draw, uniformly at random, a base field element.
    fn draw_element(&mut self) -> Felt;

    /// Draw, uniformly at random, a [Word].
    fn draw_word(&mut self) -> Word;
}

// RANDOM VALUE GENERATION FOR TESTING
// ================================================================================================

/// Generates a random field element for testing purposes.
///
/// This function is only available with the `std` feature.
#[cfg(feature = "std")]
pub fn random_felt() -> Felt {
    use rand::RngExt;
    let mut rng = rand::rng();
    // We use the `Felt::new` constructor to do rejection sampling here. It should effectively
    // never repeat, but nevertheless gives us the correct distribution.
    loop {
        if let Ok(felt) = Felt::new(rng.random::<u64>()) {
            return felt;
        }
    }
}

/// Generates a random word (4 field elements) for testing purposes.
///
/// This function is only available with the `std` feature.
#[cfg(feature = "std")]
pub fn random_word() -> Word {
    Word::new([random_felt(), random_felt(), random_felt(), random_felt()])
}

#[cfg(test)]
mod tests {
    use super::Randomizable;
    use crate::{Felt, Word};

    #[test]
    fn randomizable_short_inputs_return_none() {
        assert!(u128::from_random_bytes(&[0; 15]).is_none());
        assert!(u64::from_random_bytes(&[0; 7]).is_none());
        assert!(u32::from_random_bytes(&[0; 3]).is_none());
        assert!(u16::from_random_bytes(&[0; 1]).is_none());
        assert!(u8::from_random_bytes(&[]).is_none());
        assert!(Felt::from_random_bytes(&[0; 7]).is_none());
        assert!(Word::from_random_bytes(&[0; 31]).is_none());
        assert!(<[u8; 4]>::from_random_bytes(&[0; 3]).is_none());
    }
}
