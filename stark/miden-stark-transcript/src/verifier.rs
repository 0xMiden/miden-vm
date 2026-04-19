//! Verifier-side transcript channel.

use alloc::vec::Vec;

use p3_challenger::{CanSample, CanSampleBits, CanSampleUniformBits};
use p3_field::{BasedVectorSpace, Field};
use thiserror::Error;

use crate::{
    TranscriptData,
    channel::{Channel, TranscriptChallenger},
};

/// Verifier channel that reads transcript data and observes into the challenger.
#[derive(Clone, Debug)]
pub struct VerifierTranscript<'a, F, C, Ch> {
    challenger: Ch,
    fields: &'a [F],
    commitments: &'a [C],
}

impl<'a, F, C, Ch> VerifierTranscript<'a, F, C, Ch> {
    /// Creates a new verifier transcript backed by the provided challenger.
    pub fn new(challenger: Ch, fields: &'a [F], commitments: &'a [C]) -> Self {
        Self { challenger, fields, commitments }
    }

    /// Creates a verifier transcript backed by a `TranscriptData` container.
    pub fn from_data(challenger: Ch, data: &'a TranscriptData<F, C>) -> Self {
        let (fields, commitments) = data.as_slices();
        Self::new(challenger, fields, commitments)
    }

    /// Finalize the transcript, checking emptiness and producing a binding digest.
    ///
    /// Returns [`TranscriptError::TrailingData`] if any unread fields or commitments
    /// remain. On success, delegates to
    /// [`CanFinalizeDigest::finalize`](p3_challenger::CanFinalizeDigest::finalize) on the inner
    /// challenger — the digest must match the prover's digest for the proof to be valid.
    pub fn finalize(self) -> Result<Ch::Digest, TranscriptError>
    where
        F: Field,
        C: Clone,
        Ch: TranscriptChallenger<F, C>,
    {
        if !self.fields.is_empty() || !self.commitments.is_empty() {
            return Err(TranscriptError::TrailingData);
        }
        Ok(self.challenger.finalize())
    }

    /// Returns the total byte size of the remaining unconsumed transcript data.
    pub fn size_in_bytes(&self) -> usize {
        size_of_val(self.fields) + size_of_val(self.commitments)
    }
}

/// Verifier-side channel interface for transcript operations.
pub trait VerifierChannel: Channel {
    fn receive_field_slice(&mut self, count: usize) -> Result<&[Self::F], TranscriptError>;

    fn receive_commitment_slice(
        &mut self,
        count: usize,
    ) -> Result<&[Self::Commitment], TranscriptError>;

    fn receive_field(&mut self) -> Result<&Self::F, TranscriptError> {
        self.receive_field_slice(1).map(|values| values.first().unwrap())
    }

    fn receive_algebra_element<A>(&mut self) -> Result<A, TranscriptError>
    where
        Self::F: Field,
        A: BasedVectorSpace<Self::F>,
    {
        let coeffs = self.receive_field_slice(A::DIMENSION)?;
        Ok(A::from_basis_coefficients_slice(coeffs).unwrap())
    }

    fn receive_algebra_slice<A>(&mut self, count: usize) -> Result<Vec<A>, TranscriptError>
    where
        Self::F: Field,
        A: BasedVectorSpace<Self::F>,
    {
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let coeffs = self.receive_field_slice(A::DIMENSION)?;
            values.push(A::from_basis_coefficients_slice(coeffs).unwrap());
        }
        Ok(values)
    }

    fn receive_commitment(&mut self) -> Result<&Self::Commitment, TranscriptError> {
        self.receive_commitment_slice(1).map(|values| values.first().unwrap())
    }

    fn receive_hint_field_slice(&mut self, count: usize) -> Result<&[Self::F], TranscriptError>;

    fn receive_hint_commitment_slice(
        &mut self,
        count: usize,
    ) -> Result<&[Self::Commitment], TranscriptError>;

    fn receive_hint_field(&mut self) -> Result<&Self::F, TranscriptError> {
        self.receive_hint_field_slice(1).map(|values| values.first().unwrap())
    }

    /// Read exactly `N` hint field elements as a fixed-size array.
    fn receive_hint_field_array<const N: usize>(&mut self) -> Result<[Self::F; N], TranscriptError>
    where
        Self::F: Copy,
    {
        self.receive_hint_field_slice(N)?
            .try_into()
            .map_err(|_| TranscriptError::NoMoreFields)
    }

    fn receive_hint_commitment(&mut self) -> Result<&Self::Commitment, TranscriptError> {
        self.receive_hint_commitment_slice(1).map(|values| values.first().unwrap())
    }

    fn grind(&mut self, bits: usize) -> Result<Self::F, TranscriptError>;

    fn is_empty(&self) -> bool;
}

impl<'a, F, C, Ch> Channel for VerifierTranscript<'a, F, C, Ch>
where
    F: Field,
    C: Clone,
    Ch: TranscriptChallenger<F, C>,
{
    type F = F;
    type Commitment = C;
    type Challenger = Ch;

    fn sample(&mut self) -> F {
        CanSample::<F>::sample(&mut self.challenger)
    }

    fn sample_bits(&mut self, bits: usize) -> usize {
        self.challenger.sample_bits(bits)
    }
}

impl<'a, F, C, Ch> VerifierChannel for VerifierTranscript<'a, F, C, Ch>
where
    F: Field,
    C: Clone,
    Ch: TranscriptChallenger<F, C>,
{
    // === Observed data ===
    fn receive_field_slice(&mut self, count: usize) -> Result<&'a [Self::F], TranscriptError> {
        let values = pop_slice(&mut self.fields, count).ok_or(TranscriptError::NoMoreFields)?;
        self.challenger.observe_slice(values);
        Ok(values)
    }

    fn receive_commitment_slice(
        &mut self,
        count: usize,
    ) -> Result<&'a [Self::Commitment], TranscriptError> {
        let values =
            pop_slice(&mut self.commitments, count).ok_or(TranscriptError::NoMoreCommitments)?;
        self.challenger.observe_slice(values);
        Ok(values)
    }

    fn receive_hint_field_slice(&mut self, count: usize) -> Result<&'a [Self::F], TranscriptError> {
        pop_slice(&mut self.fields, count).ok_or(TranscriptError::NoMoreFields)
    }

    fn receive_hint_commitment_slice(
        &mut self,
        count: usize,
    ) -> Result<&'a [Self::Commitment], TranscriptError> {
        pop_slice(&mut self.commitments, count).ok_or(TranscriptError::NoMoreCommitments)
    }

    fn grind(&mut self, bits: usize) -> Result<Self::F, TranscriptError> {
        let (witness, rest) = self.fields.split_first().ok_or(TranscriptError::NoMoreFields)?;
        self.fields = rest;
        if self.challenger.check_witness(bits, *witness) {
            Ok(*witness)
        } else {
            Err(TranscriptError::InvalidGrinding)
        }
    }

    fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.commitments.is_empty()
    }
}

impl<'a, F, C, Ch, T> CanSample<T> for VerifierTranscript<'a, F, C, Ch>
where
    Ch: CanSample<T>,
{
    #[inline]
    fn sample(&mut self) -> T {
        self.challenger.sample()
    }
}

impl<'a, F, C, Ch> CanSampleBits<usize> for VerifierTranscript<'a, F, C, Ch>
where
    Ch: CanSampleBits<usize>,
{
    #[inline]
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.challenger.sample_bits(bits)
    }
}

impl<'a, F, C, Ch> CanSampleUniformBits<F> for VerifierTranscript<'a, F, C, Ch>
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

fn pop_slice<'a, T>(values: &mut &'a [T], count: usize) -> Option<&'a [T]> {
    if values.len() < count {
        return None;
    }
    let (slice, rest) = values.split_at(count);
    *values = rest;
    Some(slice)
}

/// Errors that can occur during transcript consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TranscriptError {
    #[error("no more field elements in transcript")]
    NoMoreFields,
    #[error("no more commitments in transcript")]
    NoMoreCommitments,
    #[error("invalid grinding witness")]
    InvalidGrinding,
    #[error("trailing data in transcript")]
    TrailingData,
}
