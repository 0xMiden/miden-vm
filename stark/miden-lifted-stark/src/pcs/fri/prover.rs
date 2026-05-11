use alloc::vec::Vec;

use miden_stark_transcript::ProverChannel;
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::{bitrev::BitReversalPerm, dense::RowMajorMatrix, extension::FlatMatrixView};
use p3_maybe_rayon::prelude::*;
use p3_util::reverse_slice_index_bits;
use tracing::{debug_span, info_span};

use crate::{
    domain::{Coset, TwoAdicSubgroup},
    lmcs::{Lmcs, LmcsTree, tree_indices::TreeIndices},
    pcs::fri::FriParams,
};

/// Tree type for FRI folding rounds.
///
/// Stores extension field evaluations flattened to base field via `FlatMatrixView`.
/// The LMCS internally bit-reverses leaf digests so the tree is indexed by domain order.
type FoldedTree<F, EF, L> = <L as Lmcs>::Tree<FlatMatrixView<F, EF, RowMajorMatrix<EF>>>;

// ============================================================================
// Prover Data Structure
// ============================================================================

/// Prover's state from the FRI commit phase.
///
/// Contains the data needed to answer queries (LMCS trees).
/// Commitments, PoW witnesses, and the final polynomial (in descending degree
/// order) are written to the transcript channel during construction.
///
/// Uses a single base-field LMCS. Extension field evaluations are flattened
/// to base field before commitment.
pub struct FriPolys<F, EF, L>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    L: Lmcs<F = F>,
{
    /// Trees for each folding round, used to open multiple query indices at once.
    /// Stores flattened base-field matrices (EF elements flattened to F via FlatMatrixView).
    folded_trees: Vec<FoldedTree<F, EF, L>>,
}

// ============================================================================
// Commit Phase (Prover)
// ============================================================================
//
// The FRI commit phase iteratively folds a polynomial until it reaches a
// target degree, committing to intermediate evaluations along the way.
//
// ## Algorithm
//
// Given polynomial f of degree d with evaluations on domain D of size n = d·blowup:
//
// 1. Reshape evaluations into matrix M with `arity` columns
//    - Row i contains the coset {f(s·ωʲ) : j ∈ [0, arity)} where s = g^{bitrev(i)} and ω is a
//      primitive `arity`-th root of unity
//
// 2. Commit to M via Merkle tree
//
// 3. Sample folding challenge β from verifier
//
// 4. Fold each row: for coset evaluations [y₀, ..., y_{arity-1}], compute f(β)
//    - This reduces degree by factor of `arity`
//    - New evaluations live on domain D' of size n/arity
//
// 5. Repeat until degree ≤ final_degree
//
// 6. Send final polynomial coefficients to verifier (descending degree order)
//
// ## Coset Structure in Bit-Reversed Order
//
// For domain D = g·H where H = ⟨ω⟩ has order n:
//   - Row i contains evaluations at s·⟨ω_arity⟩ where s = g·ω^{bitrev(i)} and ω_arity is a
//     primitive `arity`-th root of unity (ω_arity = ω^{n/arity})
//   - Adjacent rows have s values that are negatives (for arity=2)
//   - After folding, row i maps to row i in the halved domain

impl<F, EF, L> FriPolys<F, EF, L>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    L: Lmcs<F = F>,
{
    /// Execute the FRI commit phase.
    ///
    /// Iteratively folds the polynomial by arity at each round — committing intermediate
    /// evaluations and sampling a random challenge `beta` — until the degree is small enough to
    /// send the polynomial directly. The query phase then spot-checks that each fold was
    /// performed correctly.
    pub fn new<Ch>(
        params: &FriParams,
        lmcs: &L,
        subgroup: TwoAdicSubgroup<F>,
        evals: Vec<EF>,
        channel: &mut Ch,
    ) -> Self
    where
        Ch: ProverChannel<F = F, Commitment = L::Commitment>,
    {
        let log_arity = params.fold.log_arity();
        let arity = params.fold.arity();

        let mut folded_trees = Vec::new();

        let mut domain_size = evals.len();
        debug_assert_eq!(domain_size, subgroup.size(), "evals length must match subgroup size");
        let final_poly_degree = params.final_poly_degree(subgroup.log_size());
        let final_domain_size = final_poly_degree << params.log_blowup;

        // ─────────────────────────────────────────────────────────────────────────
        // Precompute s_inv for all cosets
        // ─────────────────────────────────────────────────────────────────────────
        // The fold performs an iFFT over the coset s * <omega>. This is equivalent to an
        // iFFT on the subgroup <omega> after the variable substitution X -> s_inv * X,
        // which is why s_inv appears as a twiddle factor in the fold formula.
        //
        // Evaluations are in bit-reversed order: evals[i] = f(g^{bitrev(i)})
        // Row k contains [evals[k*arity], evals[k*arity+1], ...] which correspond
        // to evaluations at points forming a coset s·⟨ω⟩ where:
        //   - s = g^{bitrev(k*arity, log_domain_size)} = g^{bitrev(k, log_folded_domain_size)}
        //     where log_folded_domain_size = log_domain_size - log_arity (because bitrev(k*arity,
        //     log_domain_size) = bitrev(k, log_folded_domain_size) when arity = 2^log_arity)
        //   - ω is a primitive arity-th root of unity
        //
        // We compute s_inv for each row k, where s = g^{bitrev(k, log_folded_domain_size)}
        // and g has order 2^log_domain_size.
        //
        // We generate sequential powers of g_inv and bit-reverse to get s_inv values
        // in the correct order for each row. Per-round we square g_inv `log_arity` times.
        let g_inv = subgroup.generator_inverse();
        let mut s_invs: Vec<F> = g_inv.powers().take(domain_size >> log_arity as usize).collect();
        reverse_slice_index_bits(&mut s_invs);

        let mut folded_evals = evals;
        while domain_size > final_domain_size {
            let round = folded_trees.len();
            // ─────────────────────────────────────────────────────────────────────
            // Reshape into matrix and wrap with FlatMatrixView for commitment
            // ─────────────────────────────────────────────────────────────────────
            // domain_size evaluations → matrix with folded_domain_size rows × arity columns.
            // FlatMatrixView presents the EF matrix as F matrix without copying.
            let folded_domain_size = domain_size >> log_arity as usize;
            let matrix = RowMajorMatrix::new(folded_evals, arity);
            let flat_view = FlatMatrixView::new(matrix);
            // FRI round commitments use `build_tree` (unaligned) rather than
            // `build_aligned_tree` because each round commits a single matrix, so there
            // is no multi-matrix row interleaving that would require padding to the hash
            // rate boundary.
            // Wrap in BitReversedMatrixView to present domain order to the LMCS.
            // The LMCS extracts the inner FlatMatrixView and stores it.
            let natural_view = BitReversalPerm::new_view(flat_view);
            let tree = info_span!("FRI round commit", round, domain_size)
                .in_scope(|| lmcs.build_tree(alloc::vec![natural_view]));
            let commitment = tree.root();
            channel.send_commitment(commitment.clone());

            // ─────────────────────────────────────────────────────────────────────
            // Grind and sample folding challenge beta
            // ─────────────────────────────────────────────────────────────────────
            let _pow_witness =
                info_span!("FRI folding grind", round, bits = params.folding_pow_bits)
                    .in_scope(|| channel.grind(params.folding_pow_bits));
            let beta: EF = channel.sample_algebra_element();

            // ─────────────────────────────────────────────────────────────────────
            // Fold all rows: interpolate coset evaluations and evaluate at β
            // ─────────────────────────────────────────────────────────────────────
            // Get the underlying EF matrix from the FlatMatrixView via Deref for folding.
            let flat_view_ref = &tree.leaves()[0];
            let ef_matrix: &RowMajorMatrix<EF> = flat_view_ref;
            folded_evals = info_span!("FRI fold", round, domain_size)
                .in_scope(|| params.fold.fold_matrix(ef_matrix.as_view(), &s_invs, beta));
            // No bit-reversal needed: folded evals maintain bit-reversed order
            // because s_invs are already bit-reversed to match.

            folded_trees.push(tree);

            // Output of folding becomes the input domain for the next round.
            domain_size = folded_domain_size;

            // ─────────────────────────────────────────────────────────────────────
            // Update s⁻¹ for next round
            // ─────────────────────────────────────────────────────────────────────
            // After folding, domain shrinks by `arity`. The new generator g' = g^arity.
            // Let L = log(folded_domain_size) and L' = L - log_arity (next folded size).
            // We need: s'_inv[k] = g'^{-bitrev(k, L')} = g^{-arity · bitrev(k, L')}
            //
            // Using the identity bitrev(k, L-log_arity) = bitrev(k·arity, L):
            //   s'_inv[k] = g^{-arity · bitrev(k·arity, L)}
            //             = (g^{-bitrev(k·arity, L)})^arity
            //             = s_inv[k·arity]^arity
            //
            // So we select every `arity`-th element and raise to power `arity`.
            let next_folded_size = domain_size >> log_arity as usize;
            s_invs = (0..next_folded_size)
                .into_par_iter()
                .map(|k| s_invs[k * arity].exp_power_of_2(log_arity as usize))
                .collect();
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Extract final polynomial coefficients
        // ─────────────────────────────────────────────────────────────────────────
        // The remaining evaluations are on a domain of size `final_domain_size`.
        // The polynomial has degree < `final_poly_degree` where
        // `final_poly_degree = final_domain_size / blowup`. We extract its coefficients:
        // 1. Take the first `final_poly_degree` evaluations (others are redundant due to blowup)
        // 2. Convert from bit-reversed to standard order
        // 3. Apply inverse DFT to get coefficients
        // 4. Reverse to descending degree order for direct Horner evaluation
        //
        // The polynomial has degree < final_poly_degree, so it is determined by that many
        // evaluations. In bit-reversed order, the first final_poly_degree entries form a
        // valid sub-coset (the "squaring prefix" property), so iDFT on them recovers the
        // polynomial exactly.
        folded_evals.truncate(final_poly_degree);
        reverse_slice_index_bits(&mut folded_evals);

        let mut final_poly = debug_span!("idft final poly")
            .in_scope(|| Radix2DFTSmallBatch::default().idft_algebra(folded_evals));

        // Store in descending degree order [cₙ, ..., c₁, c₀] so the verifier
        // can evaluate via Horner without reversing.
        final_poly.reverse();

        // Observe final polynomial coefficients for Fiat-Shamir
        channel.send_algebra_slice(&final_poly);

        Self { folded_trees }
    }

    /// Stream all FRI query proofs into a transcript channel.
    ///
    /// `tree_indices` are bit-reversed tree positions (sorted, deduplicated).
    ///
    /// Indices shift by `log_arity` per round because each FRI folding round groups `arity`
    /// consecutive bit-reversed indices into one coset, reducing the domain size by `arity`.
    /// The committed matrix at round r has height `domain_size / arity^r`, so the tree index
    /// for a query at round r is the original index right-shifted by `log_arity * r` bits —
    /// the high bits select the coset (row), and the discarded low bits identify which
    /// position within the coset the original query fell in.
    pub fn prove_queries<Ch>(
        &self,
        params: &FriParams,
        mut tree_indices: TreeIndices,
        channel: &mut Ch,
    ) where
        Ch: ProverChannel<F = F, Commitment = L::Commitment>,
    {
        let log_arity = params.fold.log_arity();

        // Shrink indices by log_arity per round, reusing the allocation.
        for tree in &self.folded_trees {
            tree_indices.shrink_depth(log_arity);
            tree.prove_batch(&tree_indices, channel);
        }
    }
}
