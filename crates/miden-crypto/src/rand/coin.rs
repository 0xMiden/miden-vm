use alloc::string::ToString;

use rand_core::impls;

use super::{Felt, FeltRng, RngCore};
use crate::{
    Word, ZERO,
    field::ExtensionField,
    hash::poseidon2::Poseidon2,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// CONSTANTS
// ================================================================================================

const STATE_WIDTH: usize = Poseidon2::STATE_WIDTH;
const RATE_START: usize = Poseidon2::RATE_RANGE.start;
const RATE_END: usize = Poseidon2::RATE_RANGE.end;
const HALF_RATE_WIDTH: usize = (Poseidon2::RATE_RANGE.end - Poseidon2::RATE_RANGE.start) / 2;

// POSEIDON2 RANDOM COIN
// ================================================================================================
/// A simplified version of the `SPONGE_PRG` reseedable pseudo-random number generator algorithm
/// described in <https://eprint.iacr.org/2011/499.pdf>.
///
/// The simplification is related to the following facts:
/// 1. A call to the reseed method implies one and only one call to the permutation function. This
///    is possible because in our case we never reseed with more than 4 field elements.
/// 2. As a result of the previous point, we don't make use of an input buffer to accumulate seed
///    material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomCoin {
    state: [Felt; STATE_WIDTH],
    current: usize,
}

impl RandomCoin {
    /// Returns a new [RandomCoin] initialized with the specified seed.
    pub fn new(seed: Word) -> Self {
        let mut state = [ZERO; STATE_WIDTH];

        for i in 0..HALF_RATE_WIDTH {
            state[RATE_START + i] += seed[i];
        }

        // Absorb
        Poseidon2::apply_permutation(&mut state);

        RandomCoin { state, current: RATE_START }
    }

    /// Returns a [RandomCoin] instantiated from the provided components.
    ///
    /// # Panics
    /// Panics if `current` is outside of the rate range.
    pub fn from_parts(state: [Felt; STATE_WIDTH], current: usize) -> Self {
        assert!(
            (RATE_START..RATE_END).contains(&current),
            "current value outside of valid range"
        );
        Self { state, current }
    }

    /// Returns components of this random coin.
    pub fn into_parts(self) -> ([Felt; STATE_WIDTH], usize) {
        (self.state, self.current)
    }

    /// Fills `dest` with random data.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        <Self as RngCore>::fill_bytes(self, dest)
    }

    /// Draws a random base field element from the random coin.
    ///
    /// This method applies the Poseidon2 permutation when the rate portion of the state is
    /// exhausted, then returns the next element from the rate portion.
    pub fn draw_basefield(&mut self) -> Felt {
        if self.current == RATE_END {
            Poseidon2::apply_permutation(&mut self.state);
            self.current = RATE_START;
        }

        self.current += 1;
        self.state[self.current - 1]
    }

    /// Draws a random field element.
    ///
    /// This is an alias for [Self::draw_basefield].
    pub fn draw(&mut self) -> Felt {
        self.draw_basefield()
    }

    /// Draws a random extension field element.
    ///
    /// The extension field element is constructed by drawing `E::DIMENSION` base field elements
    /// and interpreting them as basis coefficients.
    pub fn draw_ext_field<E: ExtensionField<Felt>>(&mut self) -> E {
        let ext_degree = E::DIMENSION;
        let mut result = vec![ZERO; ext_degree];
        for r in result.iter_mut().take(ext_degree) {
            *r = self.draw_basefield();
        }
        E::from_basis_coefficients_slice(&result).expect("failed to draw extension field element")
    }

    /// Reseeds the random coin with additional entropy.
    ///
    /// The provided `data` is added to the first half of the rate portion of the state,
    /// then the Poseidon2 permutation is applied. The buffer pointer is reset to the start
    /// of the rate portion.
    pub fn reseed(&mut self, data: Word) {
        // Reset buffer
        self.current = RATE_START;

        // Add the new seed material to the first half of the rate portion of the Poseidon2 state
        self.state[RATE_START] += data[0];
        self.state[RATE_START + 1] += data[1];
        self.state[RATE_START + 2] += data[2];
        self.state[RATE_START + 3] += data[3];

        // Absorb
        Poseidon2::apply_permutation(&mut self.state);
    }
}

// FELT RNG IMPLEMENTATION
// ------------------------------------------------------------------------------------------------

impl FeltRng for RandomCoin {
    fn draw_element(&mut self) -> Felt {
        self.draw_basefield()
    }

    fn draw_word(&mut self) -> Word {
        let mut output = [ZERO; 4];
        for o in output.iter_mut() {
            *o = self.draw_basefield();
        }
        Word::new(output)
    }
}

// RNGCORE IMPLEMENTATION
// ------------------------------------------------------------------------------------------------

impl RngCore for RandomCoin {
    fn next_u32(&mut self) -> u32 {
        self.draw_basefield().as_canonical_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }
}

// SERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for RandomCoin {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.state.iter().for_each(|v| v.write_into(target));
        // casting to u8 is OK because `current` is always within the rate range.
        target.write_u8(self.current as u8);
    }
}

impl Deserializable for RandomCoin {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let state = [
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
        ];
        let current = source.read_u8()? as usize;
        if !(RATE_START..RATE_END).contains(&current) {
            return Err(DeserializationError::InvalidValue(
                "current value outside of valid range".to_string(),
            ));
        }
        Ok(Self { state, current })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{Deserializable, FeltRng, RandomCoin, Serializable, ZERO};
    use crate::{ONE, Word};

    #[test]
    fn test_feltrng_felt() {
        let mut coin = RandomCoin::new([ZERO; 4].into());
        let output = coin.draw_element();

        let mut coin = RandomCoin::new([ZERO; 4].into());
        let expected = coin.draw_basefield();

        assert_eq!(output, expected);
    }

    #[test]
    fn test_feltrng_word() {
        let mut coin = RandomCoin::new([ZERO; 4].into());
        let output = coin.draw_word();

        let mut coin = RandomCoin::new([ZERO; 4].into());
        let mut expected = [ZERO; 4];
        for o in expected.iter_mut() {
            *o = coin.draw_basefield();
        }
        let expected = Word::new(expected);

        assert_eq!(output, expected);
    }

    #[test]
    fn test_feltrng_serialization() {
        let coin1 = RandomCoin::from_parts([ONE; 12], 5);

        let bytes = coin1.to_bytes();
        let coin2 = RandomCoin::read_from_bytes(&bytes).unwrap();
        assert_eq!(coin1, coin2);
    }
}
