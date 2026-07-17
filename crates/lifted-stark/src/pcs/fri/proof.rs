//! FRI structured proof types — parsed view of the FRI sub-transcript.

use alloc::vec::Vec;

use miden_stark_transcript::{TranscriptError, VerifierChannel};
use p3_field::{ExtensionField, TwoAdicField};

use crate::{domain::LiftedDomain, pcs::fri::FriParams};

/// Structured view of a single FRI folding round.
pub struct FriRoundProof<F, EF, Commitment> {
    /// Commitment to the folded evaluation matrix for this round.
    pub commitment: Commitment,
    /// Proof-of-work witness sampled before `beta`.
    pub pow_witness: F,
    /// Folding challenge `β` for this round.
    pub beta: EF,
}

/// Structured view of the full FRI sub-proof.
pub struct FriProof<F, EF, Commitment> {
    /// Per-round commitments and challenges.
    pub rounds: Vec<FriRoundProof<F, EF, Commitment>>,
    /// Coefficients of the final low-degree polynomial in descending degree order
    /// `[cₙ, ..., c₁, c₀]`, ready for direct Horner evaluation.
    pub final_poly: Vec<EF>,
}

impl<F, EF, Commitment> FriProof<F, EF, Commitment>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    Commitment: Clone,
{
    /// Parse a [`FriProof`] from a verifier channel.
    ///
    /// Reads commitments, verifies PoW witnesses, samples challenges, and
    /// reads the final polynomial. Does not verify low-degree claims;
    /// that validation happens in `FriOracle::test_low_degree`.
    pub(in crate::pcs) fn read_from_channel<Ch>(
        params: &FriParams,
        domain: &LiftedDomain<F>,
        channel: &mut Ch,
    ) -> Result<Self, TranscriptError>
    where
        Ch: VerifierChannel<F = F, Commitment = Commitment>,
    {
        let num_rounds = params.num_rounds(domain);
        let mut rounds = Vec::with_capacity(num_rounds);

        for _ in 0..num_rounds {
            let commitment = channel.receive_commitment()?.clone();

            let pow_witness = channel.grind(params.folding_pow_bits)?;

            let beta: EF = channel.sample_algebra_element();
            rounds.push(FriRoundProof { commitment, pow_witness, beta });
        }

        let final_degree = params.final_poly_degree(domain);
        let final_poly = channel.receive_algebra_slice(final_degree)?;

        Ok(Self { rounds, final_poly })
    }
}
