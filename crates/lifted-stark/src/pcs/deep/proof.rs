//! DEEP structured proof types — parsed view of the DEEP sub-transcript.

use alloc::vec::Vec;

use miden_stark_transcript::{Channel, TranscriptError, VerifierChannel};
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

use crate::pcs::deep::{DeepParams, read_eval_matrices};

/// Opened evaluations grouped by commitment group and matrix.
///
/// `opened[g][m]` is a `RowMajorMatrix<EF>` with one row per evaluation point,
/// where `g` is the commitment group index and `m` the matrix index within that group.
pub type OpenedValues<EF> = Vec<Vec<RowMajorMatrix<EF>>>;

/// Structured view of the DEEP sub-proof.
///
/// This records the prover's PoW witness and the two challenges sampled
/// from the Fiat-Shamir transcript after observing evaluations.
///
/// `evals[g][m]` is a `RowMajorMatrix<EF>` with `num_eval_points` rows for
/// commitment group `g`, matrix `m`. Widths include alignment padding (matching
/// the committed rows).
pub struct DeepProof<F: Field, EF: ExtensionField<F>> {
    /// `evals[g][m]` is a `RowMajorMatrix` with `num_eval_points` rows.
    pub evals: OpenedValues<EF>,
    /// Proof-of-work witness sampled before DEEP challenges.
    pub pow_witness: F,
    /// Challenge `α` for batching columns into `f_reduced`.
    pub challenge_columns: EF,
    /// Challenge `β` for batching opening points.
    pub challenge_points: EF,
}

impl<F, EF> DeepProof<F, EF>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
{
    /// Parse a [`DeepProof`] from a verifier channel.
    ///
    /// Reads OOD evaluations, verifies the PoW witness, and samples batching
    /// challenges. Does not verify the DEEP quotient itself; that validation
    /// happens in the DEEP verifier. Commitment widths must match the
    /// committed rows (including any alignment padding).
    pub(in crate::pcs) fn read_from_channel<Ch>(
        params: DeepParams,
        commitments: &[(<Ch as Channel>::Commitment, Vec<usize>)],
        num_eval_points: usize,
        channel: &mut Ch,
    ) -> Result<Self, TranscriptError>
    where
        Ch: VerifierChannel<F = F>,
    {
        let group_widths: Vec<&[usize]> = commitments.iter().map(|(_, gw)| gw.as_slice()).collect();
        let evals = read_eval_matrices::<F, EF, Ch>(&group_widths, num_eval_points, channel)?;

        let pow_witness = channel.grind(params.deep_pow_bits)?;
        let challenge_columns: EF = channel.sample_algebra_element();
        let challenge_points: EF = channel.sample_algebra_element();

        Ok(Self {
            evals,
            pow_witness,
            challenge_columns,
            challenge_points,
        })
    }
}
