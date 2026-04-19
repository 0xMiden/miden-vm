//! FRI transcript data structures.

use alloc::vec::Vec;

use miden_stark_transcript::{TranscriptError, VerifierChannel};
use p3_field::{ExtensionField, TwoAdicField};

use crate::pcs::fri::FriParams;

/// Structured transcript view for a single FRI folding round.
pub struct FriRoundTranscript<F, EF, Commitment> {
    /// Commitment to the folded evaluation matrix for this round.
    pub commitment: Commitment,
    /// Proof-of-work witness sampled before `beta`.
    pub pow_witness: F,
    /// Folding challenge `β` for this round.
    pub beta: EF,
}

/// Structured transcript view for the full FRI interaction.
pub struct FriTranscript<F, EF, Commitment> {
    /// Per-round commitments and challenges.
    pub rounds: Vec<FriRoundTranscript<F, EF, Commitment>>,
    /// Coefficients of the final low-degree polynomial in descending degree order
    /// `[cₙ, ..., c₁, c₀]`, ready for direct Horner evaluation.
    pub final_poly: Vec<EF>,
}

impl<F, EF, Commitment> FriTranscript<F, EF, Commitment>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    Commitment: Clone,
{
    /// Parse a FRI transcript from a verifier channel.
    ///
    /// Reads commitments, verifies PoW witnesses, samples challenges, and
    /// reads the final polynomial. Does not verify low-degree claims;
    /// that validation happens in `FriOracle::test_low_degree`.
    pub fn from_verifier_channel<Ch>(
        params: &FriParams,
        log_domain_size: u8,
        channel: &mut Ch,
    ) -> Result<Self, TranscriptError>
    where
        Ch: VerifierChannel<F = F, Commitment = Commitment>,
    {
        let num_rounds = params.num_rounds(log_domain_size);
        let mut rounds = Vec::with_capacity(num_rounds);

        for _ in 0..num_rounds {
            let commitment = channel.receive_commitment()?.clone();

            let pow_witness = channel.grind(params.folding_pow_bits)?;

            let beta: EF = channel.sample_algebra_element();
            rounds.push(FriRoundTranscript { commitment, pow_witness, beta });
        }

        let final_degree = params.final_poly_degree(log_domain_size);
        let final_poly = channel.receive_algebra_slice(final_degree)?;

        Ok(Self { rounds, final_poly })
    }
}
