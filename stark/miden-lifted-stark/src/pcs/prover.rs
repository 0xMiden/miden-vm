//! PCS Prover
//!
//! Opens committed matrices at out-of-domain evaluation points.

use miden_stark_transcript::ProverChannel;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::Matrix;
use tracing::{info_span, instrument};

use crate::{
    domain::LiftedDomain,
    lmcs::{Lmcs, LmcsTree, tree_indices::TreeIndices},
    pcs::{deep::prover::DeepPoly, fri::prover::FriPolys, params::PcsParams},
};

/// Open committed matrices at N evaluation points, writing to a prover channel.
///
/// # Preconditions
/// - `eval_points` must lie outside both the trace-domain subgroup `H` and the LDE evaluation coset
///   `gK` used by the PCS. If a point lies in either set, denominators `(zⱼ − X)` in the DEEP
///   quotient become zero for some domain element, making the quotient undefined.
/// - All trace trees must be built at the same LDE height `coset.lde_height()`. Multiple LDE
///   heights are not supported yet and will panic.
///
/// `domain` is the max LDE coset the trace trees were committed on; `domain.log_lde_height`
/// equals `log_trace_height + domain.log_blowup()` for the tallest trace.
///
/// Alignment is derived from the trace trees to pad DEEP evaluations consistently.
/// Trace trees must be built with `build_aligned_tree` to match this padding.
#[instrument(name = "PCS opening", skip_all)]
pub fn open_with_channel<F, EF, L, M, Ch, const N: usize>(
    params: &PcsParams,
    lmcs: &L,
    domain: &LiftedDomain<F>,
    eval_points: [EF; N],
    trace_trees: &[&L::Tree<M>],
    channel: &mut Ch,
) where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    L: Lmcs<F = F>,
    M: Matrix<F>,
    Ch: ProverChannel<F = F, Commitment = L::Commitment>,
{
    const { assert!(N > 0, "at least one evaluation point required") };

    // Determine LDE domain size from the supplied LDE coset.
    // For now, all trace trees must share this height; mixed LDE heights are not supported yet.
    assert!(!trace_trees.is_empty(), "at least one trace tree required");
    let log_lde_height = domain.log_lde_height();
    let expected_height = domain.lde_height();
    assert!(
        trace_trees.iter().all(|tree| tree.height() == expected_height),
        "mixed LDE heights are not supported yet",
    );
    // ─────────────────────────────────────────────────────────────────────────
    // Construct DEEP quotient (observes evals, grinds, samples alpha and beta)
    // ─────────────────────────────────────────────────────────────────────────
    let deep_poly = info_span!("DEEP quotient").in_scope(|| {
        DeepPoly::from_trees::<L, M, N, Ch>(params.deep, domain, trace_trees, eval_points, channel)
    });

    // ─────────────────────────────────────────────────────────────────────────
    // FRI commit phase (observes commitments, grinds per-round, samples betas)
    // ─────────────────────────────────────────────────────────────────────────
    // The deep_poly contains evaluations on the LDE domain (size 2^log_lde_height).
    // FRI will prove that this polynomial is low-degree.
    let fri_polys = info_span!("FRI commit phase").in_scope(|| {
        FriPolys::<F, EF, L>::new(&params.fri, lmcs, domain, deep_poly.deep_evals, channel)
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Grind for query sampling
    // ─────────────────────────────────────────────────────────────────────────
    let _query_pow_witness = info_span!("query grind", bits = params.query_pow_bits())
        .in_scope(|| channel.grind(params.query_pow_bits()));

    // ─────────────────────────────────────────────────────────────────────────
    // Sample query indices (domain indices)
    // ─────────────────────────────────────────────────────────────────────────
    // Sampled indices are domain indices: domain point = g·ω^{index}.
    // The LMCS tree is indexed by domain order (no bit-reversal needed).
    let sampled_indices_iter =
        (0..params.num_queries()).map(|_| channel.sample_bits(log_lde_height as usize));
    let tree_indices = TreeIndices::new(sampled_indices_iter, log_lde_height)
        .expect("sampled indices are in range");

    // ─────────────────────────────────────────────────────────────────────────
    // Generate query proofs
    // ─────────────────────────────────────────────────────────────────────────
    info_span!("query phase").in_scope(|| {
        // Open input trees at all query indices at once (one proof per tree)
        info_span!("open input trees", n_trees = trace_trees.len()).in_scope(|| {
            for tree in trace_trees {
                tree.prove_batch(&tree_indices, channel);
            }
        });

        // Open all FRI rounds at all query indices at once (one proof per round)
        info_span!("open FRI trees").in_scope(|| {
            fri_polys.prove_queries(&params.fri, tree_indices, channel);
        });
    });
}
