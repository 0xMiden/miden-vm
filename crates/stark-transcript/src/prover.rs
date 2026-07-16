//! Prover-side transcript channel.

use alloc::vec::Vec;

use p3_challenger::{CanSample, CanSampleBits, CanSampleUniformBits};
use p3_field::{BasedVectorSpace, Field};

use crate::{
    TranscriptData,
    channel::{Channel, TranscriptChallenger},
};

/// Prover channel that records transcript data and observes into the challenger.
#[derive(Clone, Debug)]
pub struct ProverTranscript<F, C, Ch> {
    challenger: Ch,
    fields: Vec<F>,
    commitments: Vec<C>,
}

impl<F, C, Ch> ProverTranscript<F, C, Ch> {
    /// Creates a new prover transcript backed by the provided challenger.
    pub fn new(challenger: Ch) -> Self {
        Self {
            challenger,
            fields: Vec::new(),
            commitments: Vec::new(),
        }
    }

    /// Finalize the transcript, producing a binding digest and returning the proof data.
    ///
    /// Delegates to [`CanFinalizeDigest::finalize`](p3_challenger::CanFinalizeDigest::finalize) on
    /// the inner challenger, which unconditionally applies a final state transition before
    /// extracting the digest. The digest commits to the entire transcript interaction.
    pub fn finalize(self) -> (Ch::Digest, TranscriptData<F, C>)
    where
        F: Field,
        C: Clone,
        Ch: TranscriptChallenger<F, C>,
    {
        let digest = self.challenger.finalize();
        (digest, TranscriptData::new(self.fields, self.commitments))
    }

    /// Returns the total byte size of the recorded transcript data.
    pub fn size_in_bytes(&self) -> usize {
        size_of_val(self.fields.as_slice()) + size_of_val(self.commitments.as_slice())
    }
}

/// Prover-side channel interface for transcript operations.
pub trait ProverChannel: Channel {
    fn send_field_slice(&mut self, values: &[Self::F]);

    fn send_commitment_slice(&mut self, values: &[Self::Commitment]);

    fn send_field_element(&mut self, value: Self::F) {
        self.send_field_slice(core::slice::from_ref(&value));
    }

    fn send_algebra_element<A>(&mut self, value: A)
    where
        A: BasedVectorSpace<Self::F>,
    {
        self.send_field_slice(value.as_basis_coefficients_slice());
    }

    fn send_algebra_slice<A>(&mut self, values: &[A])
    where
        A: BasedVectorSpace<Self::F>,
    {
        for value in values {
            self.send_field_slice(value.as_basis_coefficients_slice());
        }
    }

    fn send_commitment(&mut self, value: Self::Commitment) {
        self.send_commitment_slice(core::slice::from_ref(&value));
    }

    fn hint_field_slice(&mut self, values: &[Self::F]);

    fn hint_commitment_slice(&mut self, values: &[Self::Commitment]);

    fn hint_field_element(&mut self, value: Self::F) {
        self.hint_field_slice(core::slice::from_ref(&value));
    }

    fn hint_commitment(&mut self, value: Self::Commitment) {
        self.hint_commitment_slice(core::slice::from_ref(&value));
    }

    fn grind(&mut self, bits: usize) -> Self::F;
}

impl<F, C, Ch> Channel for ProverTranscript<F, C, Ch>
where
    F: Field,
    C: Clone,
    Ch: TranscriptChallenger<F, C>,
{
    type F = F;
    type Commitment = C;
    type Challenger = Ch;

    fn sample(&mut self) -> F {
        self.challenger.sample()
    }

    fn sample_bits(&mut self, bits: usize) -> usize {
        self.challenger.sample_bits(bits)
    }
}

impl<F, C, Ch> ProverChannel for ProverTranscript<F, C, Ch>
where
    F: Field,
    C: Clone,
    Ch: TranscriptChallenger<F, C>,
{
    fn send_field_slice(&mut self, values: &[Self::F]) {
        self.fields.extend_from_slice(values);
        self.challenger.observe_slice(values);
    }

    fn send_commitment_slice(&mut self, values: &[Self::Commitment]) {
        self.commitments.extend_from_slice(values);
        self.challenger.observe_slice(values);
    }

    fn hint_field_slice(&mut self, values: &[Self::F]) {
        self.fields.extend_from_slice(values);
    }

    fn hint_commitment_slice(&mut self, values: &[Self::Commitment]) {
        self.commitments.extend_from_slice(values);
    }

    fn grind(&mut self, bits: usize) -> Self::F {
        let witness = self.challenger.grind(bits);
        self.fields.push(witness);
        witness
    }
}

impl<F, C, Ch, T> CanSample<T> for ProverTranscript<F, C, Ch>
where
    Ch: CanSample<T>,
{
    #[inline]
    fn sample(&mut self) -> T {
        self.challenger.sample()
    }
}

impl<F, C, Ch> CanSampleBits<usize> for ProverTranscript<F, C, Ch>
where
    Ch: CanSampleBits<usize>,
{
    #[inline]
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.challenger.sample_bits(bits)
    }
}

impl<F, C, Ch> CanSampleUniformBits<F> for ProverTranscript<F, C, Ch>
where
    Ch: CanSampleUniformBits<F>,
{
    #[inline]
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, p3_challenger::ResamplingError> {
        self.challenger.sample_uniform_bits::<RESAMPLE>(bits)
    }
}
