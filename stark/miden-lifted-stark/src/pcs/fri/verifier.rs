//! FRI Verifier
//!
//! Verifies that a committed polynomial is close to low-degree.
//!
//! # Domain Structure
//!
//! The prover commits to evaluations on domain D of size 2^log_domain_size. The LMCS tree
//! is indexed by domain order (natural index). Internally, evaluations are in bit-reversed
//! order within the committed matrix (wrapped in `BitReversedMatrixView`).
//!
//! # Index Semantics
//!
//! The query `index` is a domain index. For each folding round:
//!   - Low bits (`index & (folded_size - 1)`): which row (coset) in the committed matrix
//!   - High bits (`index >> (log_domain_size - log_arity)`): position within the coset
//!
//! After each fold, we mask to the new folded domain size.

use alloc::{collections::BTreeMap, vec::Vec};

use miden_stark_transcript::{TranscriptError, VerifierChannel};
use p3_field::{ExtensionField, TwoAdicField};
use p3_util::reverse_bits_len;
use thiserror::Error;

use crate::{
    domain::{Coset, TwoAdicSubgroup},
    lmcs::{Lmcs, LmcsError, tree_indices::TreeIndices},
    pcs::fri::FriParams,
    util::horner::horner,
};

/// FRI low-degree test oracle.
///
/// Created via [`FriOracle::new`], which samples folding challenges from
/// the Fiat-Shamir transcript. The oracle verifies that evaluations are close
/// to a low-degree polynomial by checking that each folding round was performed
/// correctly via spot-check queries, and that the final (small) polynomial
/// matches the prover's claim exactly.
///
/// Uses a single base-field LMCS. Opened base field values are reconstructed
/// to extension field for folding verification.
pub struct FriOracle<F, EF, L>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    L: Lmcs<F = F>,
{
    /// Initial round's domain (the LDE evaluation subgroup).
    subgroup: TwoAdicSubgroup<F>,
    /// Per-round commitment and folding challenge.
    rounds: Vec<FriRoundOracle<L::Commitment, EF>>,
    /// Coefficients of the final low-degree polynomial in descending degree order
    /// `[cₙ, ..., c₁, c₀]`, ready for direct Horner evaluation.
    final_poly: Vec<EF>,
}

struct FriRoundOracle<Commitment, EF> {
    commitment: Commitment,
    beta: EF,
}

impl<F, EF, L> FriOracle<F, EF, L>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + Clone,
    L: Lmcs<F = F>,
{
    /// Create oracle by reading from a verifier channel.
    pub fn new<Ch>(
        params: &FriParams,
        subgroup: TwoAdicSubgroup<F>,
        channel: &mut Ch,
    ) -> Result<Self, FriError>
    where
        Ch: VerifierChannel<F = F, Commitment = L::Commitment>,
    {
        let log_domain_size = subgroup.log_size();
        let num_rounds = params.num_rounds(log_domain_size);
        let mut rounds = Vec::with_capacity(num_rounds);

        for _ in 0..num_rounds {
            let commitment = channel.receive_commitment()?.clone();

            channel.grind(params.folding_pow_bits)?;

            let beta: EF = channel.sample_algebra_element();
            rounds.push(FriRoundOracle { commitment, beta });
        }

        let final_degree = params.final_poly_degree(log_domain_size);
        let final_poly = channel.receive_algebra_slice(final_degree)?;

        Ok(Self { subgroup, rounds, final_poly })
    }

    /// Test low-degree proximity by reading openings from a verifier channel.
    ///
    /// `evals` maps domain indices to DEEP evaluations.
    /// Domain point for index `d` = `g·ω^d`.
    ///
    /// Empty `evals` will fail at the first round's LMCS `open_batch` call,
    /// which rejects empty indices.
    ///
    /// For each query, the verifier opens the committed row and re-computes the fold
    /// locally. A mismatch at any round indicates that the prover did not fold honestly.
    /// After all rounds, the final polynomial is checked exactly against the prover's claim.
    pub fn test_low_degree<Ch>(
        &self,
        lmcs: &L,
        params: &FriParams,
        mut evals: BTreeMap<usize, EF>,
        mut tree_indices: TreeIndices,
        channel: &mut Ch,
    ) -> Result<(), FriError>
    where
        Ch: VerifierChannel<F = F, Commitment = L::Commitment>,
    {
        let log_arity = params.fold.log_arity();
        let arity = params.fold.arity();
        // FRI commits base-field values; each extension element spans DIMENSION base elements.
        let base_width = arity * EF::DIMENSION;
        let widths = [base_width];

        let mut log_domain_size = self.subgroup.log_size();
        let mut g_inv = self.subgroup.generator_inverse();

        for (round_idx, round) in self.rounds.iter().enumerate() {
            let log_folded_domain_size = log_domain_size - log_arity;

            // Shrink indices by log_arity to get this round's row indices.
            tree_indices.shrink_depth(log_arity);

            let opened_rows = lmcs
                .open_batch(&round.commitment, &widths, &tree_indices, channel)
                .map_err(|source| FriError::LmcsError { source, round: round_idx })?;

            // Drain, verify, fold, and rebuild with new keys.
            //
            // SOUNDNESS NOTE: Multiple indices can map to the same row_idx after folding
            // (they share the same coset). This is safe because:
            //
            // 1. Each closure verifies its specific position: `row[position] == eval`. All closures
            //    execute (Rust's collect drives the full iterator).
            //
            // 2. The folded value depends only on (row, s_inv, beta), not on position. Indices in
            //    the same coset share the same row and s_inv, so they fold to identical values.
            //    Keeping any one in the BTreeMap is correct.
            //
            // 3. The prover cannot provide different row data for the same row_idx. LMCS opens each
            //    row exactly once via `opened_rows[&row_idx]`.
            let folded_size = 1usize << log_folded_domain_size;
            evals = evals
                .into_iter()
                .map(|(idx, eval)| {
                    // Decompose domain index: low bits = row (coset), high bits = position.
                    // The position bits must be bit-reversed within `log_arity` bits
                    // because the physical matrix rows store coset evaluations in
                    // bit-reversed order within each row.
                    let row_idx = idx & (folded_size - 1);
                    let position =
                        reverse_bits_len(idx >> log_folded_domain_size, log_arity as usize);

                    // FRI commits one matrix per round; iter_rows().next() yields it safely.
                    let flat_row =
                        opened_rows.get(&row_idx).and_then(|rows| rows.iter_rows().next()).ok_or(
                            FriError::InvalidOpening { tree_index: row_idx, round: round_idx },
                        )?;
                    // Reinterpret base-field elements as extension field for folding.
                    let row: Vec<EF> = EF::reconstitute_from_base(flat_row.to_vec());

                    if row.get(position) != Some(&eval) {
                        return Err(FriError::EvaluationMismatch {
                            round: round_idx,
                            tree_index: row_idx,
                            position,
                        });
                    }

                    // s⁻¹ = ω_N^{-row_idx}, needed for iFFT over <s>.
                    // In domain order, row_idx is the domain index directly.
                    let s_inv = g_inv.exp_u64(row_idx as u64);
                    let folded = params.fold.fold_evals(&row, s_inv, round.beta);
                    Ok((row_idx, folded))
                })
                .collect::<Result<_, _>>()?;

            log_domain_size = log_folded_domain_size;
            g_inv = g_inv.exp_power_of_2(log_arity as usize);
        }

        // After all folding rounds, the polynomial has been reduced to degree < final_degree.
        // The prover sent this final polynomial's coefficients; we evaluate it at each
        // folded query point on the final domain and check consistency with the folded
        // values. This closes the FRI proximity argument: if the original codeword was
        // far from low-degree, at least one query fails with high probability.
        //
        // `final_poly` is in descending degree order [cₙ, ..., c₁, c₀], which is
        // the native order for Horner evaluation.
        // After all rounds, the final-round subgroup has size 2^log_domain_size
        // (after num_rounds * log_arity shrinks). Derive its generator from the
        // initial subgroup via `shrink` rather than a fresh `two_adic_generator` call.
        let final_subgroup_log_factor = self.subgroup.log_size() - log_domain_size;
        let generator = self.subgroup.shrink(final_subgroup_log_factor).generator();
        for (idx, eval) in evals {
            // Domain index directly gives the exponent (no bit-reversal needed).
            let x = generator.exp_u64(idx as u64);
            let final_eval: EF = horner(x, self.final_poly.iter().copied());

            if final_eval != eval {
                return Err(FriError::FinalPolyMismatch { tree_index: idx });
            }
        }

        Ok(())
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during FRI verification.
#[derive(Debug, Error)]
pub enum FriError {
    #[error("LMCS verification failed at round {round}: {source}")]
    LmcsError { source: LmcsError, round: usize },
    #[error("invalid opening for tree index {tree_index} at round {round}")]
    InvalidOpening { tree_index: usize, round: usize },
    #[error(
        "evaluation mismatch at round {round}, tree index {tree_index}, coset position {position}"
    )]
    EvaluationMismatch {
        round: usize,
        tree_index: usize,
        position: usize,
    },
    #[error("final polynomial mismatch at tree index {tree_index}")]
    FinalPolyMismatch { tree_index: usize },
    #[error("transcript error: {0}")]
    TranscriptError(#[from] TranscriptError),
}
