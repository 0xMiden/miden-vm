//! PCS Verifier
//!
//! Verifies polynomial evaluation claims against commitments.
//!
//! Two entry points with the same signature, differing only in alignment handling:
//!
//! | Function          | Alignment |
//! |-------------------|-----------|
//! | [`verify`]        | caller    |
//! | [`verify_aligned`]| automatic |
//!
//! Callers should use
//! [`VerifierTranscript::finalize`](miden_stark_transcript::VerifierTranscript::finalize)
//! after verification to check that the transcript is fully consumed.

use alloc::vec::Vec;

use miden_stark_transcript::{TranscriptError, VerifierChannel};
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::{Matrix, horizontally_truncated::HorizontallyTruncated};
use thiserror::Error;

use crate::{
    domain::LiftedDomain,
    lmcs::{Lmcs, tree_indices::TreeIndices},
    pcs::{
        deep::{
            proof::OpenedValues,
            verifier::{DeepError, DeepOracle},
        },
        fri::verifier::{FriError, FriOracle},
        params::PcsParams,
    },
    util::align::aligned_widths,
};

/// Verify polynomial evaluation claims against commitments.
///
/// Commitment widths must match the committed rows (including any alignment padding
/// from `build_aligned_tree`). The PCS is alignment-agnostic; callers that use
/// aligned trees must pass aligned widths and handle truncation themselves.
/// See [`verify_aligned`] for automatic alignment handling.
///
/// Does **not** check that the channel is fully consumed after verification.
/// Callers should use
/// [`VerifierTranscript::finalize`](miden_stark_transcript::VerifierTranscript::finalize) to
/// enforce transcript exhaustion.
///
/// # Preconditions
/// - `eval_points` must lie outside both the trace-domain subgroup `H` and the LDE evaluation coset
///   `gK`. Otherwise denominators `(zⱼ − X)` in the DEEP quotient become zero, making it undefined.
/// - All commitments must be lifted to the same LDE height `2^log_lde_height`.
///
/// # Returns
/// `opened[group][matrix]` as a `RowMajorMatrix<EF>` with `N` rows
/// (one per evaluation point), using the same widths that were passed in.
pub fn verify<F, EF, L, Ch, const N: usize>(
    params: &PcsParams,
    lmcs: &L,
    commitments: &[(L::Commitment, Vec<usize>)],
    domain: &LiftedDomain<F>,
    eval_points: [EF; N],
    channel: &mut Ch,
) -> Result<OpenedValues<EF>, PcsError>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + PartialEq + Clone,
    L: Lmcs<F = F>,
    Ch: VerifierChannel<F = F, Commitment = L::Commitment>,
{
    const { assert!(N > 0, "at least one evaluation point required") };

    if commitments.is_empty() {
        return Err(PcsError::NoCommitments);
    }

    let log_lde_height = domain.log_lde_height();

    // Construct verifier's DEEP oracle (observes evals, checks PoW, samples α/β)
    let (deep_oracle, evals) = DeepOracle::<F, EF, L>::new(
        params.deep,
        &eval_points,
        commitments.to_vec(),
        domain,
        channel,
    )?;

    // Create FRI oracle (observes commitments + final poly, checks per-round PoW)
    let fri_oracle = FriOracle::new(&params.fri, *domain.lde_coset().subgroup(), channel)?;

    // Check query PoW witness and sample query indices
    channel.grind(params.query_pow_bits())?;

    // Sample query indices (domain indices). The LMCS tree is indexed by domain order.
    let sampled_indices_iter =
        (0..params.num_queries()).map(|_| channel.sample_bits(log_lde_height as usize));
    let tree_indices = TreeIndices::new(sampled_indices_iter, log_lde_height)
        .expect("sampled indices are in range");

    // Verify DEEP openings for all queries at once
    // tree_indices are bit-reversed positions; deep_evals is keyed by tree index
    let deep_evals = deep_oracle.open_batch(lmcs, &tree_indices, channel)?;

    // Test low-degree proximity for all queries at once
    fri_oracle.test_low_degree(lmcs, &params.fri, deep_evals, tree_indices, channel)?;

    Ok(evals)
}

/// Like [`verify`], but handles LMCS alignment automatically.
///
/// Commitment widths should be the original (unpadded) data widths. This function:
/// 1. Aligns widths to `lmcs.alignment()`
/// 2. Calls [`verify`] with aligned widths
/// 3. Truncates returned evals back to original widths
pub fn verify_aligned<F, EF, L, Ch, const N: usize>(
    params: &PcsParams,
    lmcs: &L,
    commitments: &[(L::Commitment, Vec<usize>)],
    domain: &LiftedDomain<F>,
    eval_points: [EF; N],
    channel: &mut Ch,
) -> Result<OpenedValues<EF>, PcsError>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + PartialEq + Clone,
    L: Lmcs<F = F>,
    Ch: VerifierChannel<F = F, Commitment = L::Commitment>,
{
    let alignment = lmcs.alignment();
    let aligned_commitments: Vec<_> = commitments
        .iter()
        .map(|(c, widths)| (c.clone(), aligned_widths(widths.clone(), alignment)))
        .collect();

    let evals = verify(params, lmcs, &aligned_commitments, domain, eval_points, channel)?;

    // Truncate each matrix back to original widths, removing alignment padding.
    let truncated = evals
        .into_iter()
        .zip(commitments)
        .map(|(group, (_, orig_widths))| {
            group
                .into_iter()
                .zip(orig_widths)
                .map(|(mat, &orig_w)| {
                    HorizontallyTruncated::new(mat, orig_w)
                        .expect("original width must not exceed aligned width")
                        .to_row_major_matrix()
                })
                .collect()
        })
        .collect();

    Ok(truncated)
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during PCS verification.
#[derive(Debug, Error)]
pub enum PcsError {
    #[error("no commitments provided")]
    NoCommitments,
    #[error("DEEP error: {0}")]
    DeepError(#[from] DeepError),
    #[error("FRI error: {0}")]
    FriError(#[from] FriError),
    #[error("transcript error: {0}")]
    TranscriptError(#[from] TranscriptError),
}
