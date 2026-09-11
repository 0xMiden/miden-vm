use alloc::string::ToString;

use rand::{
    Rng,
    rand_core::{Infallible, TryRng, utils},
};

use super::{Felt, FeltRng};
use crate::{
    Word,
    field::ExtensionField,
    hash::eidos::{
        Eidos,
        domains::{RANDOM_COIN_OUTPUT, RANDOM_COIN_STATE},
    },
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

const OUTPUT_FELTS: usize = Word::NUM_ELEMENTS;

/// A reseedable random coin built from Eidos compression.
///
/// State derivation and output generation use separate Eidos domains. Output block `i` is the
/// field hash of the internal state and a non-wrapping `u64` counter. Reseeding replaces the state
/// with the field hash of the current state, counter, and supplied data, discards buffered output,
/// and resets the counter. The output path uses only Eidos field elements and is independent of
/// the compression core's output representation. The stored random-coin state is distinct from
/// the temporary, domain-specific chaining value constructed by each framed Eidos hash.
///
/// This counter-mode construction does not provide backtracking resistance within a reseed
/// interval: knowledge of the stored state permits recomputing every output block derived from
/// that state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EidosRandomCoin {
    state: Word,
    output: Word,
    counter: u64,
    current: usize,
}

impl EidosRandomCoin {
    /// Returns a random coin initialized with `seed`.
    pub fn new(seed: Word) -> Self {
        let state = Eidos::hash_elements_in_domain(seed.as_elements(), RANDOM_COIN_STATE);
        Self {
            state,
            output: Word::default(),
            counter: 0,
            current: OUTPUT_FELTS,
        }
    }

    /// Returns a random coin reconstructed from its serialized components.
    ///
    /// `counter` is the index of the next output block and therefore the number of blocks generated
    /// since initialization or the most recent reseed. If `current` is less than four, `output` is
    /// the block at `counter - 1`, and `current` identifies its next candidate Felt. A value of
    /// four means that the buffer is exhausted. This
    /// constructor trusts `output`; it does not recompute the buffered block.
    ///
    /// # Panics
    ///
    /// Panics if `current` is greater than the number of buffered output elements, or if buffered
    /// output is supplied before any output block has been generated.
    pub fn from_parts(state: Word, output: Word, counter: u64, current: usize) -> Self {
        assert!(current <= OUTPUT_FELTS, "current output index is out of range");
        assert!(
            current == OUTPUT_FELTS || counter != 0,
            "buffered output requires a generated block"
        );
        Self { state, output, counter, current }
    }

    /// Returns `(state, output, counter, current)`.
    ///
    /// `counter` is the index of the next output block, and `current` is the next candidate Felt in
    /// `output`. A `current` value equal to four marks an exhausted buffer.
    pub fn into_parts(self) -> (Word, Word, u64, usize) {
        (self.state, self.output, self.counter, self.current)
    }

    /// Fills `dest` with random bytes.
    ///
    /// # Panics
    ///
    /// Panics if output generation requires another block after the `u64` block counter is
    /// exhausted.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        <Self as Rng>::fill_bytes(self, dest)
    }

    /// Draws a uniformly distributed base-field element.
    ///
    /// # Panics
    ///
    /// Panics if output generation requires another block after the `u64` block counter is
    /// exhausted.
    pub fn draw_basefield(&mut self) -> Felt {
        loop {
            let candidate =
                self.try_next_u64().expect("Eidos random-coin generation is infallible");
            if let Ok(value) = Felt::new(candidate) {
                return value;
            }
        }
    }

    /// Draws a uniformly distributed base-field element.
    ///
    /// # Panics
    ///
    /// Panics under the same condition as [`Self::draw_basefield`].
    pub fn draw(&mut self) -> Felt {
        self.draw_basefield()
    }

    /// Draws a uniformly distributed extension-field element.
    ///
    /// # Panics
    ///
    /// Panics under the same condition as [`Self::draw_basefield`].
    pub fn draw_ext_field<E: ExtensionField<Felt>>(&mut self) -> E {
        E::from_basis_coefficients_fn(|_| self.draw_basefield())
    }

    /// Mixes four additional field elements into the random-coin state.
    ///
    /// The current output-block counter is bound into the new state. Any buffered output is
    /// discarded, and the block counter is reset to zero.
    pub fn reseed(&mut self, data: Word) {
        let input = [
            self.state[0],
            self.state[1],
            self.state[2],
            self.state[3],
            Felt::from_u32(self.counter as u32),
            Felt::from_u32((self.counter >> 32) as u32),
            data[0],
            data[1],
            data[2],
            data[3],
        ];
        self.state = Eidos::hash_elements_in_domain(&input, RANDOM_COIN_STATE);
        self.output = Word::default();
        self.counter = 0;
        self.current = OUTPUT_FELTS;
    }

    fn next_output_u32(&mut self) -> u32 {
        loop {
            if self.current == OUTPUT_FELTS {
                self.refill_output();
            }

            let value = self.output[self.current].as_canonical_u64();
            self.current += 1;

            // Masked Eidos outputs already have uniform low-u32 limbs under the pseudorandom-output
            // assumption. For a uniform Goldilocks-field output, p - 1 is the sole extra preimage
            // of zero; removing it leaves exactly 2^32 - 1 preimages for every u32 value.
            if value != Felt::ORDER - 1 {
                return value as u32;
            }
        }
    }

    fn refill_output(&mut self) {
        let counter = self.counter;
        self.counter = counter.checked_add(1).expect("Eidos random-coin counter exhausted");

        let input = [
            self.state[0],
            self.state[1],
            self.state[2],
            self.state[3],
            Felt::from_u32(counter as u32),
            Felt::from_u32((counter >> 32) as u32),
        ];
        self.output = Eidos::hash_elements_in_domain(&input, RANDOM_COIN_OUTPUT);
        self.current = 0;
    }
}

impl FeltRng for EidosRandomCoin {
    fn draw_element(&mut self) -> Felt {
        self.draw_basefield()
    }

    fn draw_word(&mut self) -> Word {
        Word::new(core::array::from_fn(|_| self.draw_basefield()))
    }
}

impl TryRng for EidosRandomCoin {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next_output_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        utils::next_u64_via_u32(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        utils::fill_bytes_via_next_word(dest, || self.try_next_u32())
    }
}

impl Serializable for EidosRandomCoin {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.state.write_into(target);
        self.output.write_into(target);
        target.write_u64(self.counter);
        target.write_u8(self.current as u8);
    }
}

impl Deserializable for EidosRandomCoin {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let state = Word::read_from(source)?;
        let output = Word::read_from(source)?;
        let counter = source.read_u64()?;
        let current = source.read_u8()? as usize;
        if current > OUTPUT_FELTS {
            return Err(DeserializationError::InvalidValue(
                "current output index is out of range".to_string(),
            ));
        }
        if current != OUTPUT_FELTS && counter == 0 {
            return Err(DeserializationError::InvalidValue(
                "buffered output requires a generated block".to_string(),
            ));
        }

        Ok(Self { state, output, counter, current })
    }
}

#[cfg(test)]
mod tests {
    use rand::RngExt;

    use super::*;
    use crate::{ONE, ZERO, field::PrimeCharacteristicRing};

    fn seed() -> Word {
        Word::new([Felt::ONE, Felt::TWO, Felt::from_u8(3), Felt::from_u8(4)])
    }

    #[test]
    fn seed_is_framed_under_the_state_domain() {
        let coin = EidosRandomCoin::new(seed());
        let expected = Eidos::hash_elements_in_domain(seed().as_elements(), RANDOM_COIN_STATE);

        assert_eq!(coin.state, expected);
        assert_eq!(coin.counter, 0);
        assert_eq!(coin.current, OUTPUT_FELTS);
    }

    #[test]
    fn output_matches_the_registered_counter_mode_construction() {
        let mut coin = EidosRandomCoin::new(seed());
        let initial_state = coin.state;
        let input = [
            initial_state[0],
            initial_state[1],
            initial_state[2],
            initial_state[3],
            ZERO,
            ZERO,
        ];
        let expected = Eidos::hash_elements_in_domain(&input, RANDOM_COIN_OUTPUT);

        let actual: [u32; OUTPUT_FELTS] = core::array::from_fn(|_| coin.random::<u32>());

        assert_eq!(actual, expected.into_elements().map(|value| value.as_canonical_u64() as u32));
        assert_eq!(coin.state, initial_state);
        assert_eq!(coin.output, expected);
        assert_eq!(coin.counter, 1);
        assert_eq!(actual, [3_343_138_332, 3_182_666_834, 3_956_264_476, 4_003_292_457]);
    }

    #[test]
    fn base_field_sampling_rejects_noncanonical_candidates() {
        let modulus = Felt::ORDER;
        let output = Word::new([
            Felt::from_u32(modulus as u32),
            Felt::from_u32((modulus >> 32) as u32),
            Felt::from_u32(42),
            ZERO,
        ]);
        let mut coin = EidosRandomCoin::from_parts(Word::default(), output, 1, 0);

        assert_eq!(coin.draw_basefield(), Felt::from_u64(42));
        assert_eq!(coin.current, 4);
    }

    #[test]
    fn u32_sampling_rejects_the_extra_low_limb_preimage() {
        let output =
            Word::new([Felt::new_unchecked(Felt::ORDER - 1), Felt::from_u32(42), ZERO, ZERO]);
        let mut coin = EidosRandomCoin::from_parts(Word::default(), output, 1, 0);

        assert_eq!(coin.random::<u32>(), 42);
        assert_eq!(coin.current, 2);
    }

    #[test]
    fn reseed_uses_the_complete_state_and_input() {
        let data =
            Word::new([Felt::from_u8(5), Felt::from_u8(6), Felt::from_u8(7), Felt::from_u8(8)]);
        let mut coin = EidosRandomCoin::new(seed());
        let old_state = coin.state;
        let _ = coin.random::<u32>();
        assert_eq!(coin.state, old_state);
        assert_eq!(coin.counter, 1);
        coin.reseed(data);

        let input = [
            old_state[0],
            old_state[1],
            old_state[2],
            old_state[3],
            Felt::ONE,
            ZERO,
            data[0],
            data[1],
            data[2],
            data[3],
        ];
        let expected = Eidos::hash_elements_in_domain(&input, RANDOM_COIN_STATE);
        assert_eq!(coin.state, expected);
        assert_eq!(coin.output, Word::default());
        assert_eq!(coin.counter, 0);
        assert_eq!(coin.current, OUTPUT_FELTS);
    }

    #[test]
    fn reseed_binds_the_generated_block_count() {
        let data =
            Word::new([Felt::from_u8(5), Felt::from_u8(6), Felt::from_u8(7), Felt::from_u8(8)]);
        let mut first = EidosRandomCoin::new(seed());
        let mut second = first;

        let _: [u32; OUTPUT_FELTS] = core::array::from_fn(|_| second.random());
        first.reseed(data);
        second.reseed(data);

        assert_ne!(first.state, second.state);
        assert_ne!(first.random::<[u8; 32]>(), second.random::<[u8; 32]>());
    }

    #[test]
    fn reseeded_stream_matches_the_frozen_vector() {
        let data =
            Word::new([Felt::from_u8(5), Felt::from_u8(6), Felt::from_u8(7), Felt::from_u8(8)]);
        let mut coin = EidosRandomCoin::new(seed());
        let _: [u32; OUTPUT_FELTS] = core::array::from_fn(|_| coin.random());
        coin.reseed(data);

        let actual: [u32; OUTPUT_FELTS] = core::array::from_fn(|_| coin.random());
        assert_eq!(actual, [3_145_282_389, 2_211_610_295, 3_232_936_185, 3_064_838_016]);
    }

    #[test]
    fn felt_rng_methods_follow_the_base_field_stream() {
        let mut actual = EidosRandomCoin::new(seed());
        let mut expected = actual;

        assert_eq!(actual.draw_element(), expected.draw_basefield());
        assert_eq!(
            actual.draw_word(),
            Word::new(core::array::from_fn(|_| expected.draw_basefield()))
        );
    }

    #[test]
    fn serialization_preserves_partially_consumed_output() {
        let mut coin = EidosRandomCoin::new(seed());
        let _: [u8; 13] = coin.random();

        let bytes = coin.to_bytes();
        let decoded = EidosRandomCoin::read_from_bytes(&bytes).unwrap();
        assert_eq!(decoded, coin);

        let mut first = coin;
        let mut second = decoded;
        assert_eq!(first.random::<[u8; 64]>(), second.random::<[u8; 64]>());
    }

    #[test]
    fn deserialization_rejects_an_invalid_output_index() {
        let mut bytes = EidosRandomCoin::new(seed()).to_bytes();
        *bytes.last_mut().unwrap() = (OUTPUT_FELTS + 1) as u8;

        assert!(EidosRandomCoin::read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn deserialization_rejects_buffered_output_without_a_generated_block() {
        let mut bytes = EidosRandomCoin::new(seed()).to_bytes();
        *bytes.last_mut().unwrap() = 0;

        assert!(EidosRandomCoin::read_from_bytes(&bytes).is_err());
    }

    #[test]
    #[should_panic(expected = "current output index is out of range")]
    fn from_parts_rejects_an_invalid_output_index() {
        EidosRandomCoin::from_parts(Word::default(), Word::default(), 0, OUTPUT_FELTS + 1);
    }

    #[test]
    #[should_panic(expected = "buffered output requires a generated block")]
    fn from_parts_rejects_buffered_output_without_a_generated_block() {
        EidosRandomCoin::from_parts(Word::default(), Word::default(), 0, 0);
    }

    #[test]
    fn successive_counters_produce_distinct_output_blocks() {
        let mut coin = EidosRandomCoin::new(seed());
        let first: [u32; OUTPUT_FELTS] = core::array::from_fn(|_| coin.random());
        let second: [u32; OUTPUT_FELTS] = core::array::from_fn(|_| coin.random());

        assert_ne!(first, second);
        assert_eq!(coin.counter, 2);
    }

    #[test]
    fn output_binds_both_counter_limbs() {
        let state = EidosRandomCoin::new(seed()).state;
        let mut low = EidosRandomCoin::from_parts(state, Word::default(), 0, OUTPUT_FELTS);
        let mut high =
            EidosRandomCoin::from_parts(state, Word::default(), 1u64 << 32, OUTPUT_FELTS);

        assert_ne!(low.random::<[u8; 16]>(), high.random::<[u8; 16]>());
    }

    #[test]
    #[should_panic(expected = "Eidos random-coin counter exhausted")]
    fn counter_exhaustion_is_detected() {
        let mut coin =
            EidosRandomCoin::from_parts(Word::default(), Word::default(), u64::MAX, OUTPUT_FELTS);
        let _ = coin.random::<u32>();
    }

    #[test]
    fn different_seeds_produce_different_streams() {
        let mut first = EidosRandomCoin::new(seed());
        let mut second = EidosRandomCoin::new(Word::new([ONE; Word::NUM_ELEMENTS]));

        assert_ne!(first.random::<[u8; 64]>(), second.random::<[u8; 64]>());
    }
}
