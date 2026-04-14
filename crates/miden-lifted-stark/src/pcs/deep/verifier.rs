use alloc::{collections::BTreeMap, vec::Vec};
use core::{iter::zip, marker::PhantomData};

use miden_stark_transcript::{TranscriptError, VerifierChannel};
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::Matrix;
use thiserror::Error;

use crate::{
    lmcs::{Lmcs, LmcsError, tree_indices::TreeIndices},
    pcs::{
        deep::{DeepParams, proof::OpenedValues, read_eval_matrices},
        utils::horner_acc,
    },
};

/// Verifier's view of the DEEP quotient as a point-query oracle.
///
/// The prover claims OOD evaluations for all committed columns at a small set of points
/// `zⱼ`. The verifier uses a random `α` to reduce (batch) all columns into a single
/// polynomial `f_red`, and a random `β` to combine multiple opening points into one
/// DEEP quotient polynomial:
///
/// ```text
/// Q(X) = Σⱼ βʲ · (f_red(zⱼ) − f_red(X)) / (zⱼ − X)
/// ```
///
/// This oracle stores the commitments and the reduced OOD claims `(zⱼ, f_red(zⱼ))`.
/// At query time it:
/// - verifies Merkle openings for all committed matrices at the query index,
/// - reduces the opened row to `f_red(X)` using Horner with the same `α`,
/// - reconstructs `Q(X)` and returns it to the FRI verifier.
///
/// Lifting is transparent at this layer: the prover commits to lifted codewords, so
/// every opened column is interpreted as a polynomial over the same max domain.
pub struct DeepOracle<F: TwoAdicField, EF: ExtensionField<F>, L: Lmcs<F = F>> {
    /// Trace commitments with their widths (one per trace tree).
    ///
    /// Widths must match the committed rows (including any alignment padding if
    /// `build_aligned_tree` was used).
    commitments: Vec<(L::Commitment, Vec<usize>)>,

    /// Log₂ of the LDE domain height (tree has 2^log_lde_height leaves).
    /// Verifier expects all commitments to be lifted to this same LDE height.
    log_lde_height: u8,

    /// Reduced openings: pairs of `(zⱼ, f_reduced(zⱼ))` from the prover's claims.
    reduced_openings: Vec<(EF, EF)>,

    /// Challenge `α` for batching columns into `f_reduced`.
    challenge_columns: EF,
    /// Challenge `β` for batching opening points.
    challenge_points: EF,

    _marker: PhantomData<F>,
}

impl<F: TwoAdicField, EF: ExtensionField<F>, L: Lmcs<F = F>> DeepOracle<F, EF, L> {
    /// Construct by reading evaluations, checking PoW, and sampling challenges.
    ///
    /// Commitment widths must match the committed rows (including any alignment padding).
    /// All commitments are expected to be lifted to the same `log_lde_height`.
    ///
    /// Preconditions: `eval_points` must be distinct and lie outside the trace subgroup `H`
    /// and LDE evaluation coset `gK`. The outer protocol is expected to enforce this.
    ///
    /// `log_lde_height` is the log₂ of the LDE evaluation domain height (i.e. the height of
    /// the committed LDE matrices). When a trace degree is known, it is typically
    /// `log_trace_height + params.fri.log_blowup` (plus any extension used by the caller).
    ///
    /// Returns the oracle and per-matrix evaluations: `evals[g][m]` is a
    /// `RowMajorMatrix<EF>` with one row per evaluation point.
    pub fn new<Ch>(
        params: DeepParams,
        eval_points: &[EF],
        commitments: Vec<(L::Commitment, Vec<usize>)>,
        log_lde_height: u8,
        channel: &mut Ch,
    ) -> Result<(Self, OpenedValues<EF>), DeepError>
    where
        Ch: VerifierChannel<F = F, Commitment = L::Commitment>,
    {
        let group_widths: Vec<&[usize]> = commitments.iter().map(|(_, gw)| gw.as_slice()).collect();
        let evals = read_eval_matrices::<F, EF, Ch>(&group_widths, eval_points.len(), channel)?;

        // 1. Check grinding witness
        channel.grind(params.deep_pow_bits)?;

        // 2. Sample DEEP challenges
        let challenge_columns: EF = channel.sample_algebra_element();
        let challenge_points: EF = channel.sample_algebra_element();

        // Horner reduction: fold across all evals for each evaluation point
        let reduced_openings: Vec<(EF, EF)> = eval_points
            .iter()
            .enumerate()
            .map(|(p, &point)| {
                let val = evals.iter().flat_map(|g| g.iter()).fold(EF::ZERO, |acc, mat| {
                    // mat has num_eval_points rows (one per z), p < num_eval_points.
                    horner_acc(
                        acc,
                        challenge_columns,
                        mat.row(p).expect("eval point index in range"),
                    )
                });
                (point, val)
            })
            .collect();

        let oracle = Self {
            commitments,
            log_lde_height,
            reduced_openings,
            challenge_columns,
            challenge_points,
            _marker: PhantomData,
        };

        Ok((oracle, evals))
    }

    /// Open the oracle at given tree indices by reading proofs from a verifier channel.
    ///
    /// `tree_indices` are domain indices (sorted, deduplicated).
    /// Returns a map from domain index to DEEP evaluation at that point.
    ///
    /// The reduction to `f_red` must match the prover's exactly.
    ///
    /// In particular, the prover streams columns in a fixed commitment-group order
    /// (e.g. main, aux, quotient). The verifier must iterate groups in the same order so
    /// that `horner_acc` assigns the same `α` powers to the same columns; otherwise the
    /// reconstructed `Q(X)` will not match the FRI-committed codeword.
    pub fn open_batch<Ch>(
        &self,
        lmcs: &L,
        tree_indices: &TreeIndices,
        channel: &mut Ch,
    ) -> Result<BTreeMap<usize, EF>, DeepError>
    where
        Ch: VerifierChannel<F = F, Commitment = L::Commitment>,
    {
        let mut reduced_rows: BTreeMap<usize, EF> =
            tree_indices.iter().map(|&idx| (idx, EF::ZERO)).collect();

        for (group_idx, (commit, widths)) in self.commitments.iter().enumerate() {
            let opened_rows = lmcs
                .open_batch(commit, widths, tree_indices, channel)
                .map_err(|source| DeepError::LmcsError { source, tree: group_idx })?;

            // Reduce opened rows via Horner: f_reduced(X) = Σᵢ αᵂ⁻¹⁻ⁱ · fᵢ(X).
            //
            // `horner_acc` continues the running accumulation across commitment groups:
            // group 0's columns get the highest powers, group 1's continue from where
            // group 0 left off. The coefficient ordering must match the prover's exactly;
            // otherwise the reconstructed DEEP quotient diverges from the FRI-committed
            // codeword, causing verification failure.
            for (tree_idx, acc) in reduced_rows.iter_mut() {
                let rows_for_query = opened_rows
                    .get(tree_idx)
                    .ok_or(DeepError::InvalidOpening { tree: group_idx, tree_index: *tree_idx })?;
                *acc = horner_acc(*acc, self.challenge_columns, rows_for_query.iter_values());
            }
        }

        let generator = F::two_adic_generator(self.log_lde_height as usize);
        let shift = F::GENERATOR;

        // Reconstruct Q(x) at each queried domain point x from the opened row data.
        // If the prover's OOD claims were correct, these values lie on the
        // low-degree polynomial committed via FRI.
        let evals: BTreeMap<usize, EF> = reduced_rows
            .into_iter()
            .map(|(tree_idx, reduced_row)| {
                // Recover domain point X = g·ω^{tree_idx} (tree index = domain index)
                let row_point = shift * generator.exp_u64(tree_idx as u64);

                // DEEP quotient: Q(X) = Σⱼ βʲ · (f_reduced(zⱼ) - f_reduced(X)) / (zⱼ - X)
                // Precondition: eval points lie outside the LDE domain.
                let mut deep_eval = EF::ZERO;
                for ((point, reduced_eval), coeff_point) in
                    zip(&self.reduced_openings, self.challenge_points.powers())
                {
                    let denom_inv = (*point - row_point)
                        .try_inverse()
                        .ok_or(DeepError::EvalPointOnDomain { tree_index: tree_idx })?;
                    deep_eval += coeff_point * (*reduced_eval - reduced_row) * denom_inv;
                }
                Ok((tree_idx, deep_eval))
            })
            .collect::<Result<_, DeepError>>()?;

        Ok(evals)
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during DEEP oracle construction or verification.
#[derive(Debug, Error)]
pub enum DeepError {
    #[error("LMCS verification failed for commitment group {tree}: {source}")]
    LmcsError { source: LmcsError, tree: usize },
    #[error("invalid opening for tree index {tree_index} in commitment group {tree}")]
    InvalidOpening { tree: usize, tree_index: usize },
    #[error("evaluation point coincides with domain point at tree index {tree_index}")]
    EvalPointOnDomain { tree_index: usize },
    #[error("transcript error: {0}")]
    TranscriptError(#[from] TranscriptError),
}
