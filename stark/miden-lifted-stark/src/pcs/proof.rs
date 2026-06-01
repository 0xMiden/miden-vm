//! PCS structured proof types — parsed view of the PCS sub-transcript.

use alloc::vec::Vec;

use miden_stark_transcript::{TranscriptError, VerifierChannel};
use p3_field::{ExtensionField, Field, TwoAdicField};

use crate::{
    domain::LiftedDomain,
    lmcs::{Lmcs, LmcsError, tree_indices::TreeIndices},
    pcs::{deep::proof::DeepProof, fri::proof::FriProof, params::PcsParams},
};

/// Structured view of the full PCS sub-proof.
///
/// Captures observed transcript data plus parsed LMCS batch openings for inspection.
pub struct PcsProof<EF, L>
where
    L: Lmcs,
    L::F: Field,
    EF: ExtensionField<L::F>,
{
    /// DEEP sub-proof (evals, PoW witness, challenges).
    pub deep_proof: DeepProof<L::F, EF>,
    /// FRI sub-proof (round commitments/challenges, final polynomial).
    pub fri_proof: FriProof<L::F, EF, L::Commitment>,
    /// Proof-of-work witness for query sampling.
    pub query_pow_witness: L::F,
    /// Query indices in sampling order (domain indices, may contain duplicates).
    pub query_indices: Vec<usize>,
    /// Batch witness per trace tree (leaf data + Merkle witness).
    pub deep_witnesses: Vec<L::BatchProof>,
    /// Batch witness per FRI round (leaf data + Merkle witness).
    pub fri_witnesses: Vec<L::BatchProof>,
}

impl<EF, L> PcsProof<EF, L>
where
    L: Lmcs,
    L::F: TwoAdicField,
    EF: ExtensionField<L::F>,
{
    /// Parse a [`PcsProof`] from a verifier channel without validation.
    ///
    /// Composes [`DeepProof`], [`FriProof`], and per-query LMCS batch proofs.
    /// Does not verify any claims; validation happens in
    /// [`verify`](crate::verify).
    /// Commitment widths must match the committed rows (including any alignment padding),
    /// and all commitments are expected to be lifted to `coset.lde_height()`.
    pub(crate) fn read_from_channel<Ch, const N: usize>(
        params: &PcsParams,
        lmcs: &L,
        commitments: &[(L::Commitment, Vec<usize>)],
        domain: &LiftedDomain<L::F>,
        eval_points: [EF; N],
        channel: &mut Ch,
    ) -> Result<Self, TranscriptError>
    where
        L::F: TwoAdicField,
        Ch: VerifierChannel<F = L::F, Commitment = L::Commitment>,
    {
        let log_lde_height = domain.log_lde_height();
        if commitments.is_empty() {
            return Err(TranscriptError::NoMoreFields);
        }

        let deep_proof = DeepProof::read_from_channel::<Ch>(
            params.deep,
            commitments,
            eval_points.len(),
            channel,
        )?;

        let fri_proof = FriProof::read_from_channel(&params.fri, domain, channel)?;

        let query_pow_witness = channel.grind(params.query_pow_bits())?;

        // Sample query indices (domain indices), matching the prover/verifier convention.
        let query_indices: Vec<usize> = (0..params.num_queries())
            .map(|_| channel.sample_bits(log_lde_height as usize))
            .collect();
        let tree_indices = TreeIndices::new(query_indices.iter().copied(), log_lde_height)
            .expect("sampled indices are in range");

        let deep_witnesses: Vec<_> = commitments
            .iter()
            .map(|(_commitment, widths)| {
                lmcs.read_batch_proof(widths, &tree_indices, channel).map_err(|e| match e {
                    LmcsError::TranscriptError(te) => te,
                    _ => TranscriptError::NoMoreFields,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let log_arity = params.fri.fold.log_arity();
        let arity = params.fri.fold.arity();
        let num_rounds = params.fri.num_rounds(domain);

        let mut fri_witnesses = Vec::with_capacity(num_rounds);
        let mut round_indices = tree_indices;
        for _round in 0..num_rounds {
            round_indices.shrink_depth(log_arity);
            let base_width = arity * EF::DIMENSION;
            // FRI round openings are unaligned, so use the base width directly.
            let round_widths = [base_width];
            let batch = lmcs.read_batch_proof(&round_widths, &round_indices, channel).map_err(
                |e| match e {
                    LmcsError::TranscriptError(te) => te,
                    _ => TranscriptError::NoMoreFields,
                },
            )?;
            fri_witnesses.push(batch);
        }

        Ok(Self {
            deep_proof,
            fri_proof,
            query_pow_witness,
            query_indices,
            deep_witnesses,
            fri_witnesses,
        })
    }
}
