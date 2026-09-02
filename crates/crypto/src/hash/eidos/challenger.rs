//! Fiat-Shamir challenger built from Eidos compression.
//!
//! The challenger keeps a four-Felt chaining value. It compresses observations in eight-Felt
//! blocks and uses a transition tag and counter blocks to generate outputs.

use alloc::vec::Vec;

use p3_challenger::{
    CanFinalizeDigest, CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger,
};
use p3_symmetric::{Hash, MerkleCap};

use super::{BLOCK_LEN, DIGEST_WIDTH, Eidos};
use crate::{
    Felt, Word, ZERO,
    field::{BasedVectorSpace, PrimeField64},
    parallel::*,
};

/// Base value for absorb-to-squeeze transition tags.
const TRANSITION_TAG_BASE: u32 = 1;

/// Squeeze tag used for counter-mode output extension.
const SQUEEZE_TAG: Felt = Felt::new_unchecked((TRANSITION_TAG_BASE + BLOCK_LEN as u32) as u64);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum EidosChallengerMode {
    Absorbing,
    Squeezing,
}

/// Generic Eidos challenger.
///
/// This type supports scalar observation for Plonky3 challenger traits.
/// Each sampled base-field element comes from one packed 63-bit Eidos digest word rather than the
/// full Goldilocks field range.
#[derive(Clone, Debug)]
pub struct EidosChallenger {
    cv: Word,
    buffer: [Felt; BLOCK_LEN],
    buffer_len: usize,
    mode: EidosChallengerMode,
    counter: u32,
    output_word: Word,
    output_len: usize,
}

impl EidosChallenger {
    /// Returns a challenger initialized with the supplied chaining value.
    ///
    /// The caller is responsible for domain-separating this value from message hashes and other
    /// transcript protocols.
    pub fn new(initial_cv: Word) -> Self {
        Self {
            cv: initial_cv,
            buffer: [ZERO; BLOCK_LEN],
            buffer_len: 0,
            mode: EidosChallengerMode::Absorbing,
            counter: 0,
            output_word: Word::default(),
            output_len: 0,
        }
    }

    /// Returns the current chaining value.
    pub fn cv(&self) -> Word {
        self.cv
    }

    /// Observes one scalar felt through the generic streaming interface.
    pub fn observe_felt(&mut self, value: Felt) {
        self.enter_absorbing_mode();

        self.buffer[self.buffer_len] = value;
        self.buffer_len += 1;
        if self.buffer_len == BLOCK_LEN {
            self.compress_pending_buffer();
        }
    }

    /// Samples one base-field element.
    ///
    /// Felts are consumed from a freshly squeezed word in natural index order:
    /// `output_word[0]`, then `[1]`, `[2]`, and `[3]`.
    pub fn sample_felt(&mut self) -> Felt {
        if self.output_len == 0 {
            self.refill_output_word();
        }

        let idx = DIGEST_WIDTH - self.output_len;
        self.output_len -= 1;
        self.output_word[idx]
    }

    /// Samples `bits` low bits from the next sampled field element.
    ///
    /// This follows the existing transcript cadence: `bits == 0` still consumes
    /// one field element and returns zero.
    pub fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < usize::BITS as usize, "bit count must be valid");
        assert!((1u64 << bits) < Felt::ORDER_U64);

        let value = self.sample_felt().as_canonical_u64() as usize;
        value & ((1usize << bits) - 1)
    }

    /// Returns the next fresh squeezed word.
    ///
    /// This API requires that no partially consumed output word is pending.
    ///
    /// # Panics
    ///
    /// Panics if a previous word has been only partially consumed through scalar sampling or
    /// proof-of-work grinding.
    pub fn squeeze_word(&mut self) -> Word {
        assert_eq!(self.output_len, 0, "squeeze_word requires word-aligned output");
        self.refill_output_word();
        let output = self.output_word;
        self.output_len = 0;
        output
    }

    fn absorb_full_block(&mut self, block: [Felt; BLOCK_LEN]) {
        assert_eq!(self.buffer_len, 0, "full-block absorb requires an empty scalar buffer");
        self.enter_absorbing_mode();
        self.cv = Eidos::compress(self.cv, block);
    }

    fn enter_absorbing_mode(&mut self) {
        self.mode = EidosChallengerMode::Absorbing;
        self.counter = 0;
        self.output_len = 0;
    }

    fn compress_pending_buffer(&mut self) {
        debug_assert_eq!(self.buffer_len, BLOCK_LEN);
        self.cv = Eidos::compress(self.cv, self.buffer);
        self.buffer = [ZERO; BLOCK_LEN];
        self.buffer_len = 0;
    }

    fn refill_output_word(&mut self) {
        match self.mode {
            EidosChallengerMode::Absorbing => {
                let tag = transition_tag(self.buffer_len);
                let block = self.buffer;
                self.cv = Eidos::compress(tweak_cv(self.cv, tag), block);
                self.buffer = [ZERO; BLOCK_LEN];
                self.buffer_len = 0;
                self.mode = EidosChallengerMode::Squeezing;
                self.counter = 0;
            },
            EidosChallengerMode::Squeezing => {
                self.counter =
                    self.counter.checked_add(1).expect("squeeze counter exhausted before absorb");
                self.cv =
                    Eidos::compress(tweak_cv(self.cv, SQUEEZE_TAG), counter_block(self.counter));
            },
        }

        self.output_word = self.cv;
        self.output_len = DIGEST_WIDTH;
    }
}

/// Eidos challenger adapter for Miden transcripts.
///
/// The adapter exposes the generic scalar observation and sampling traits required by the STARK
/// transcript. Scalar observations share an eight-felt buffer. Construction binds the relation
/// digest as one dedicated full block before that stream begins.
#[derive(Clone, Debug)]
pub struct MidenEidosChallenger {
    inner: EidosChallenger,
}

impl MidenEidosChallenger {
    /// Initializes the transcript from a precomputed init CV and relation digest.
    pub fn new(transcript_init_cv: Word, relation_digest: Word) -> Self {
        let mut inner = EidosChallenger::new(transcript_init_cv);
        inner.absorb_full_block([
            relation_digest[0],
            relation_digest[1],
            relation_digest[2],
            relation_digest[3],
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ]);
        Self { inner }
    }
}

impl<T> CanObserve<T> for MidenEidosChallenger
where
    EidosChallenger: CanObserve<T>,
{
    fn observe(&mut self, value: T) {
        self.inner.observe(value);
    }
}

impl<T> CanSample<T> for MidenEidosChallenger
where
    EidosChallenger: CanSample<T>,
{
    fn sample(&mut self) -> T {
        self.inner.sample()
    }
}

impl CanSampleBits<usize> for MidenEidosChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}

impl FieldChallenger<Felt> for MidenEidosChallenger {}

impl GrindingChallenger for MidenEidosChallenger {
    type Witness = Felt;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        self.inner.grind(bits)
    }
}

impl CanFinalizeDigest for MidenEidosChallenger {
    type Digest = [Felt; DIGEST_WIDTH];

    fn finalize(self) -> Self::Digest {
        self.inner.finalize()
    }
}

impl CanObserve<Felt> for EidosChallenger {
    fn observe(&mut self, value: Felt) {
        self.observe_felt(value);
    }
}

impl<const N: usize> CanObserve<[Felt; N]> for EidosChallenger {
    fn observe(&mut self, values: [Felt; N]) {
        for value in values {
            self.observe_felt(value);
        }
    }
}

impl<const N: usize> CanObserve<Hash<Felt, Felt, N>> for EidosChallenger {
    fn observe(&mut self, values: Hash<Felt, Felt, N>) {
        for value in values {
            self.observe_felt(value);
        }
    }
}

impl<const N: usize> CanObserve<Hash<Felt, u64, N>> for EidosChallenger {
    fn observe(&mut self, values: Hash<Felt, u64, N>) {
        for value in values {
            self.observe_felt(Felt::new_unchecked(value));
        }
    }
}

impl<const N: usize> CanObserve<&MerkleCap<Felt, [Felt; N]>> for EidosChallenger {
    fn observe(&mut self, cap: &MerkleCap<Felt, [Felt; N]>) {
        for digest in cap.roots() {
            for &value in digest {
                self.observe_felt(value);
            }
        }
    }
}

impl<const N: usize> CanObserve<MerkleCap<Felt, [Felt; N]>> for EidosChallenger {
    fn observe(&mut self, cap: MerkleCap<Felt, [Felt; N]>) {
        self.observe(&cap);
    }
}

impl<const N: usize> CanObserve<&MerkleCap<Felt, [u64; N]>> for EidosChallenger {
    fn observe(&mut self, cap: &MerkleCap<Felt, [u64; N]>) {
        for digest in cap.roots() {
            for &value in digest {
                self.observe_felt(Felt::new_unchecked(value));
            }
        }
    }
}

impl<const N: usize> CanObserve<MerkleCap<Felt, [u64; N]>> for EidosChallenger {
    fn observe(&mut self, cap: MerkleCap<Felt, [u64; N]>) {
        self.observe(&cap);
    }
}

impl CanObserve<Vec<Vec<Felt>>> for EidosChallenger {
    fn observe(&mut self, rows: Vec<Vec<Felt>>) {
        for values in rows {
            for value in values {
                self.observe_felt(value);
            }
        }
    }
}

impl<EF: BasedVectorSpace<Felt>> CanSample<EF> for EidosChallenger {
    fn sample(&mut self) -> EF {
        EF::from_basis_coefficients_fn(|_| self.sample_felt())
    }
}

impl CanSampleBits<usize> for EidosChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        EidosChallenger::sample_bits(self, bits)
    }
}

impl FieldChallenger<Felt> for EidosChallenger {}

impl GrindingChallenger for EidosChallenger {
    type Witness = Felt;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert!(bits < usize::BITS as usize, "bit count must be valid");
        assert!((1u64 << bits) < Felt::ORDER_U64);

        if bits == 0 {
            return ZERO;
        }

        let witness = (0..Felt::ORDER_U64)
            .into_par_iter()
            .map(Felt::new_unchecked)
            .find_any(|&witness| self.clone().check_witness(bits, witness))
            .expect("failed to find proof-of-work witness");

        assert!(self.check_witness(bits, witness));
        witness
    }
}

impl CanFinalizeDigest for EidosChallenger {
    type Digest = [Felt; DIGEST_WIDTH];

    fn finalize(mut self) -> Self::Digest {
        self.output_len = 0;
        let digest = self.squeeze_word();
        digest.into()
    }
}

fn transition_tag(buffer_len: usize) -> Felt {
    debug_assert!(buffer_len < BLOCK_LEN);
    Felt::new_unchecked((TRANSITION_TAG_BASE + buffer_len as u32) as u64)
}

fn tweak_cv(mut cv: Word, tag: Felt) -> Word {
    // This is Goldilocks field addition on the packed fourth digest word, not independent addition
    // on either underlying u32 lane.
    cv[3] += tag;
    cv
}

fn counter_block(counter: u32) -> [Felt; BLOCK_LEN] {
    let mut block = [ZERO; BLOCK_LEN];
    block[0] = Felt::from_u32(counter);
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSITION_TAG: Felt = Felt::new_unchecked(TRANSITION_TAG_BASE as u64);

    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    struct ChallengerSnapshot {
        cv: Word,
        mode: EidosChallengerMode,
        counter: u32,
        buffer: [Felt; BLOCK_LEN],
        buffer_len: usize,
        output_word: Word,
        output_len: usize,
    }

    impl ChallengerSnapshot {
        const SERIALIZED_LEN: usize = 20;

        fn to_canonical_u64s(self) -> [u64; Self::SERIALIZED_LEN] {
            let mut row = [0u64; Self::SERIALIZED_LEN];
            row[0] = self.cv[0].as_canonical_u64();
            row[1] = self.cv[1].as_canonical_u64();
            row[2] = self.cv[2].as_canonical_u64();
            row[3] = self.cv[3].as_canonical_u64();
            row[4] = mode_as_u64(self.mode);
            row[5] = self.counter as u64;
            for (i, value) in self.buffer.iter().enumerate() {
                row[6 + i] = value.as_canonical_u64();
            }
            row[14] = self.buffer_len as u64;
            row[15] = self.output_word[0].as_canonical_u64();
            row[16] = self.output_word[1].as_canonical_u64();
            row[17] = self.output_word[2].as_canonical_u64();
            row[18] = self.output_word[3].as_canonical_u64();
            row[19] = self.output_len as u64;
            row
        }
    }

    fn felt(value: u64) -> Felt {
        Felt::new_unchecked(value)
    }

    fn word(values: [u64; DIGEST_WIDTH]) -> Word {
        Word::new(values.map(felt))
    }

    fn snapshot(challenger: &EidosChallenger) -> ChallengerSnapshot {
        ChallengerSnapshot {
            cv: challenger.cv,
            mode: challenger.mode,
            counter: challenger.counter,
            buffer: challenger.buffer,
            buffer_len: challenger.buffer_len,
            output_word: challenger.output_word,
            output_len: challenger.output_len,
        }
    }

    fn miden_snapshot(challenger: &MidenEidosChallenger) -> ChallengerSnapshot {
        snapshot(&challenger.inner)
    }

    const fn mode_as_u64(mode: EidosChallengerMode) -> u64 {
        match mode {
            EidosChallengerMode::Absorbing => 0,
            EidosChallengerMode::Squeezing => 1,
        }
    }

    #[test]
    fn miden_init_absorbs_relation_digest_as_one_full_block() {
        let init = word([1, 2, 3, 4]);
        let relation_digest = word([10, 11, 12, 13]);

        let challenger = MidenEidosChallenger::new(init, relation_digest);

        let expected = Eidos::compress(
            init,
            [
                relation_digest[0],
                relation_digest[1],
                relation_digest[2],
                relation_digest[3],
                ZERO,
                ZERO,
                ZERO,
                ZERO,
            ],
        );

        let snapshot = miden_snapshot(&challenger);
        assert_eq!(snapshot.cv, expected);
        assert_eq!(snapshot.mode, EidosChallengerMode::Absorbing);
        assert_eq!(snapshot.counter, 0);
        assert_eq!(snapshot.buffer_len, 0);
        assert_eq!(snapshot.output_len, 0);
    }

    #[test]
    fn first_squeeze_uses_zero_len_transition_tweak_and_zero_block() {
        let init = word([1, 2, 3, 4]);
        let mut challenger = EidosChallenger::new(init);

        let output = challenger.squeeze_word();

        let expected = Eidos::compress(tweak_cv(init, TRANSITION_TAG), [ZERO; BLOCK_LEN]);
        assert_eq!(output, expected);

        let snapshot = snapshot(&challenger);
        assert_eq!(snapshot.mode, EidosChallengerMode::Squeezing);
        assert_eq!(snapshot.counter, 0);
        assert_eq!(snapshot.output_len, 0);
    }

    #[test]
    fn second_squeeze_uses_counter_block_one() {
        let init = word([1, 2, 3, 4]);
        let mut challenger = EidosChallenger::new(init);

        let first = challenger.squeeze_word();
        let second = challenger.squeeze_word();

        let expected = Eidos::compress(tweak_cv(first, SQUEEZE_TAG), counter_block(1));
        assert_eq!(second, expected);
        assert_eq!(snapshot(&challenger).counter, 1);
    }

    #[test]
    fn scalar_transition_tag_binds_pending_buffer_length() {
        let init = word([1, 2, 3, 4]);
        let value = felt(7);

        let mut one = EidosChallenger::new(init);
        one.observe_felt(value);
        let one_output = one.squeeze_word();

        let mut two = EidosChallenger::new(init);
        two.observe_felt(value);
        two.observe_felt(ZERO);
        let two_output = two.squeeze_word();

        let expected_one = Eidos::compress(
            tweak_cv(init, transition_tag(1)),
            [value, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO],
        );

        assert_eq!(one_output, expected_one);
        assert_ne!(one_output, two_output);
    }

    #[test]
    fn sample_felt_consumes_squeezed_word_from_the_front() {
        let init = word([1, 2, 3, 4]);

        let mut word_challenger = EidosChallenger::new(init);
        let output = word_challenger.squeeze_word();

        let mut scalar_challenger = EidosChallenger::new(init);
        assert_eq!(scalar_challenger.sample_felt(), output[0]);
        assert_eq!(scalar_challenger.sample_felt(), output[1]);
        assert_eq!(scalar_challenger.sample_felt(), output[2]);
        assert_eq!(scalar_challenger.sample_felt(), output[3]);
        assert_eq!(snapshot(&scalar_challenger).output_len, 0);
    }

    #[test]
    fn sample_bits_returns_requested_width() {
        let init = word([1, 2, 3, 4]);
        let mut challenger = EidosChallenger::new(init);

        let sample = challenger.sample_bits(13);

        assert!(sample < (1 << 13));
    }

    #[test]
    fn sample_bits_zero_consumes_one_felt() {
        let init = word([1, 2, 3, 4]);
        let mut challenger = EidosChallenger::new(init);

        assert_eq!(challenger.sample_bits(0), 0);
        assert_eq!(snapshot(&challenger).output_len, DIGEST_WIDTH - 1);
    }

    #[test]
    fn zero_bit_grinding_and_verification_leave_the_transcript_unchanged() {
        let mut challenger = EidosChallenger::new(word([1, 2, 3, 4]));
        challenger.observe_felt(felt(9));
        let before = snapshot(&challenger);

        assert_eq!(challenger.grind(0), ZERO);
        assert_eq!(snapshot(&challenger), before);

        let mut verifier = challenger.clone();
        assert!(verifier.check_witness(0, ZERO));
        assert_eq!(snapshot(&verifier), before);
    }

    #[test]
    fn observe_after_partial_sample_discards_remaining_output() {
        let init = word([1, 2, 3, 4]);
        let value = felt(7);

        let mut challenger = EidosChallenger::new(init);
        let first_output = challenger.squeeze_word();
        let expected = Eidos::compress(
            tweak_cv(first_output, transition_tag(1)),
            [value, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO],
        );

        let mut challenger = EidosChallenger::new(init);
        let _ = challenger.sample_felt();
        challenger.observe_felt(value);

        assert_eq!(challenger.squeeze_word(), expected);
    }

    #[test]
    fn finalize_after_partial_sample_uses_fresh_squeeze() {
        let init = word([1, 2, 3, 4]);
        let mut challenger = EidosChallenger::new(init);

        let first = challenger.squeeze_word();
        let expected = Eidos::compress(tweak_cv(first, SQUEEZE_TAG), counter_block(1));

        let mut challenger = EidosChallenger::new(init);
        let _ = challenger.sample_felt();
        let finalized = challenger.finalize();

        assert_eq!(Word::new(finalized), expected);
    }

    #[test]
    fn snapshot_serialization_order_is_stable() {
        let mut challenger = EidosChallenger::new(word([1, 2, 3, 4]));
        challenger.observe_felt(felt(9));
        challenger.observe_felt(felt(10));

        let row = snapshot(&challenger).to_canonical_u64s();

        assert_eq!(row.len(), ChallengerSnapshot::SERIALIZED_LEN);
        assert_eq!(row[0..4], [1, 2, 3, 4]);
        assert_eq!(row[4], 0);
        assert_eq!(row[5], 0);
        assert_eq!(row[6..14], [9, 10, 0, 0, 0, 0, 0, 0]);
        assert_eq!(row[14], 2);
        assert_eq!(row[15..20], [0, 0, 0, 0, 0]);
    }
}
