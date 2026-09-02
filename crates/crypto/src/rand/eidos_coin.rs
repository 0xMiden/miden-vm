use alloc::string::ToString;

use rand::{
    Rng,
    rand_core::{Infallible, TryRng, utils},
};

use super::{Felt, FeltRng};
use crate::{
    Word, ZERO,
    field::ExtensionField,
    hash::eidos::{BLOCK_LEN, Eidos, encoding},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// Registered Eidos domain ID for random-coin state derivation.
pub const RANDOM_COIN_STATE_DOMAIN_ID: u32 = 0x000008;

/// Registered Eidos selector for random-coin state derivation.
pub const RANDOM_COIN_STATE_SELECTOR: u32 = (RANDOM_COIN_STATE_DOMAIN_ID << 8) | 1;

/// Registered Eidos domain ID for random-coin output generation.
pub const RANDOM_COIN_OUTPUT_DOMAIN_ID: u32 = 0x000009;

/// Registered Eidos selector for random-coin output generation.
pub const RANDOM_COIN_OUTPUT_SELECTOR: u32 = (RANDOM_COIN_OUTPUT_DOMAIN_ID << 8) | 1;

const OUTPUT_LANES: usize = 8;

/// A reseedable random coin built from Eidos compression.
///
/// State derivation uses framed Eidos hashes. Output generation compresses the current state under
/// a separate selector and uses the high half of the raw XOF output as the random stream. The low
/// half becomes the next state. Base-field elements are sampled by rejecting raw `u64` values at
/// or above the Goldilocks modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EidosRandomCoin {
    state: Word,
    output: [u32; OUTPUT_LANES],
    current: usize,
}

impl EidosRandomCoin {
    /// Returns a random coin initialized with `seed`.
    pub fn new(seed: Word) -> Self {
        let state = Eidos::hash_elements_in_domain(
            seed.as_elements(),
            Felt::from_u32(RANDOM_COIN_STATE_SELECTOR),
        );
        Self {
            state,
            output: [0; OUTPUT_LANES],
            current: OUTPUT_LANES,
        }
    }

    /// Returns a random coin reconstructed from its serialized components.
    ///
    /// # Panics
    ///
    /// Panics if `current` is greater than the number of buffered output lanes.
    pub fn from_parts(state: Word, output: [u32; OUTPUT_LANES], current: usize) -> Self {
        assert!(current <= OUTPUT_LANES, "current output index is out of range");
        Self { state, output, current }
    }

    /// Returns the components of this random coin.
    pub fn into_parts(self) -> (Word, [u32; OUTPUT_LANES], usize) {
        (self.state, self.output, self.current)
    }

    /// Fills `dest` with random bytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        <Self as Rng>::fill_bytes(self, dest)
    }

    /// Draws a uniformly distributed base-field element.
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
    pub fn draw(&mut self) -> Felt {
        self.draw_basefield()
    }

    /// Draws a uniformly distributed extension-field element.
    pub fn draw_ext_field<E: ExtensionField<Felt>>(&mut self) -> E {
        E::from_basis_coefficients_fn(|_| self.draw_basefield())
    }

    /// Mixes four additional field elements into the random-coin state.
    pub fn reseed(&mut self, data: Word) {
        let words = [self.state, data];
        self.state = Eidos::hash_elements_in_domain(
            Word::words_as_elements(&words),
            Felt::from_u32(RANDOM_COIN_STATE_SELECTOR),
        );
        self.output = [0; OUTPUT_LANES];
        self.current = OUTPUT_LANES;
    }

    fn next_output_lane(&mut self) -> u32 {
        if self.current == OUTPUT_LANES {
            self.refill_output();
        }

        let value = self.output[self.current];
        self.current += 1;
        value
    }

    fn refill_output(&mut self) {
        let init_cv =
            Eidos::init_chaining_word(RANDOM_COIN_OUTPUT_SELECTOR, Word::NUM_ELEMENTS as u32);
        let mut block = [ZERO; BLOCK_LEN];
        block[..Word::NUM_ELEMENTS].copy_from_slice(self.state.as_elements());
        let xof = Eidos::compress_xof_lanes(init_cv, block);

        self.state = encoding::output_cv_to_word(core::array::from_fn(|i| xof[i]));
        self.output.copy_from_slice(&xof[OUTPUT_LANES..]);
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
        Ok(self.next_output_lane())
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
        for &lane in &self.output {
            target.write_u32(lane);
        }
        target.write_u8(self.current as u8);
    }
}

impl Deserializable for EidosRandomCoin {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let state = Word::read_from(source)?;
        let output = [
            source.read_u32()?,
            source.read_u32()?,
            source.read_u32()?,
            source.read_u32()?,
            source.read_u32()?,
            source.read_u32()?,
            source.read_u32()?,
            source.read_u32()?,
        ];
        let current = source.read_u8()? as usize;
        if current > OUTPUT_LANES {
            return Err(DeserializationError::InvalidValue(
                "current output index is out of range".to_string(),
            ));
        }

        Ok(Self { state, output, current })
    }
}

#[cfg(test)]
mod tests {
    use rand::RngExt;

    use super::*;
    use crate::{ONE, field::PrimeCharacteristicRing};

    fn seed() -> Word {
        Word::new([Felt::ONE, Felt::TWO, Felt::from_u8(3), Felt::from_u8(4)])
    }

    #[test]
    fn seed_is_framed_under_the_state_selector() {
        let coin = EidosRandomCoin::new(seed());
        let init_cv =
            Eidos::init_chaining_word(RANDOM_COIN_STATE_SELECTOR, Word::NUM_ELEMENTS as u32);
        let mut block = [ZERO; BLOCK_LEN];
        block[..Word::NUM_ELEMENTS].copy_from_slice(seed().as_elements());
        let expected = Eidos::compress(init_cv, block);

        assert_eq!(coin.state, expected);
        assert_eq!(
            coin.state,
            Eidos::hash_elements_in_domain(
                seed().as_elements(),
                Felt::from_u32(RANDOM_COIN_STATE_SELECTOR),
            )
        );
        assert_eq!(coin.current, OUTPUT_LANES);
    }

    #[test]
    fn raw_output_matches_the_registered_xof_construction() {
        let mut coin = EidosRandomCoin::new(seed());
        let initial_state = coin.state;
        let init_cv =
            Eidos::init_chaining_word(RANDOM_COIN_OUTPUT_SELECTOR, Word::NUM_ELEMENTS as u32);
        let mut block = [ZERO; BLOCK_LEN];
        block[..Word::NUM_ELEMENTS].copy_from_slice(initial_state.as_elements());
        let expected_xof = Eidos::compress_xof_lanes(init_cv, block);

        let actual: [u32; OUTPUT_LANES] = core::array::from_fn(|_| coin.random::<u32>());

        assert_eq!(actual, expected_xof[OUTPUT_LANES..]);
        assert_eq!(
            coin.state,
            encoding::output_cv_to_word(core::array::from_fn(|i| expected_xof[i]))
        );
        assert_eq!(
            actual,
            [
                472_368_570,
                4_205_522_548,
                2_745_539_717,
                671_568_934,
                1_503_986_164,
                3_698_520_159,
                189_494_601,
                4_060_006_346,
            ]
        );
        assert_eq!(
            coin.state.into_elements().map(|value| value.as_canonical_u64()),
            [
                9_207_954_693_737_961_717,
                5_311_354_921_240_716_727,
                8_757_448_831_409_201_738,
                2_359_999_135_837_795_579,
            ]
        );
    }

    #[test]
    fn base_field_sampling_rejects_noncanonical_candidates() {
        let modulus = Felt::ORDER;
        let output = [modulus as u32, (modulus >> 32) as u32, 42, 0, 0, 0, 0, 0];
        let mut coin = EidosRandomCoin::from_parts(Word::default(), output, 0);

        assert_eq!(coin.draw_basefield(), Felt::from_u64(42));
        assert_eq!(coin.current, 4);
    }

    #[test]
    fn reseed_uses_the_complete_state_and_input() {
        let data =
            Word::new([Felt::from_u8(5), Felt::from_u8(6), Felt::from_u8(7), Felt::from_u8(8)]);
        let mut coin = EidosRandomCoin::new(seed());
        let old_state = coin.state;
        let _ = coin.random::<u32>();
        let state_after_refill = coin.state;
        coin.reseed(data);

        let expected = Eidos::compress(
            Eidos::init_chaining_word(RANDOM_COIN_STATE_SELECTOR, BLOCK_LEN as u32),
            [
                state_after_refill[0],
                state_after_refill[1],
                state_after_refill[2],
                state_after_refill[3],
                data[0],
                data[1],
                data[2],
                data[3],
            ],
        );
        assert_ne!(state_after_refill, old_state);
        assert_eq!(coin.state, expected);
        assert_eq!(coin.output, [0; OUTPUT_LANES]);
        assert_eq!(coin.current, OUTPUT_LANES);
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
        *bytes.last_mut().unwrap() = (OUTPUT_LANES + 1) as u8;

        assert!(EidosRandomCoin::read_from_bytes(&bytes).is_err());
    }

    #[test]
    #[should_panic(expected = "current output index is out of range")]
    fn from_parts_rejects_an_invalid_output_index() {
        EidosRandomCoin::from_parts(Word::default(), [0; OUTPUT_LANES], OUTPUT_LANES + 1);
    }

    #[test]
    fn different_seeds_produce_different_streams() {
        let mut first = EidosRandomCoin::new(seed());
        let mut second = EidosRandomCoin::new(Word::new([ONE; Word::NUM_ELEMENTS]));

        assert_ne!(first.random::<[u8; 64]>(), second.random::<[u8; 64]>());
    }
}
