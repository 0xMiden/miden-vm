//! Quotient polynomial helpers used by the prover's per-AIR pipeline.
//!
//! - [`upsample_evals`]: Low-degree extend coset evaluations onto a larger two-adic coset (the
//!   constraint-degree axis: `D_j -> D_max`, same polynomial, denser evaluations).
//! - [`cyclic_extend_and_accumulate`]: Lift the running accumulator along the trace-height axis
//!   (`n_j -> N`) by cyclic repetition, and Horner-fold a new AIR's contribution in via beta.
//! - [`commit_quotient`]: Decompose Q(gJ) into chunks and commit on gK.

use alloc::{format, vec, vec::Vec};

use p3_dft::TwoAdicSubgroupDft;
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, TwoAdicField, par_add_scaled_slice_in_place,
    par_scale_slice_in_place,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use tracing::info_span;

use crate::{
    StarkConfig,
    domain::{Coset, EvaluationDomain},
    lmcs::Lmcs,
    prover::commit::Committed,
    util::bitrev::materialize_bitrev,
};

// ============================================================================
// Domain lifting and accumulation
// ============================================================================

/// Low-degree extend coset evaluations onto a larger two-adic coset.
///
/// Treats `evals` as evaluations of a polynomial `p` on a coset `g*H` of size
/// `evals.len()`, and returns evaluations of the same `p` on the coset `g*K`
/// of size `evals.len() << added_bits` (same shift `g`, larger two-adic
/// subgroup).
///
/// # Precondition
///
/// `deg(p) < evals.len()`. If the input evaluations are of a polynomial whose
/// actual degree is `>= evals.len()`, this function silently returns evaluations
/// of a different polynomial (the unique degree-`< evals.len()` interpolant of
/// the input). The caller is responsible for ensuring the degree bound.
pub(crate) fn upsample_evals<F, EF, DFT>(dft: &DFT, evals: Vec<EF>, added_bits: usize) -> Vec<EF>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    DFT: TwoAdicSubgroupDft<F>,
{
    if added_bits == 0 {
        return evals;
    }

    dft.lde_algebra_batch(RowMajorMatrix::new_col(evals), added_bits).values
}

/// Fold a new AIR's quotient contribution into the cross-AIR accumulator via one
/// Horner step, after lifting the prior accumulator onto the larger coset:
///
/// ```text
/// acc <- lift_r(acc) * beta + contribution,    r = contribution.len() / acc.len()
/// ```
///
/// On return, `accumulator.len() == contribution.len()`. `contribution.len()` and
/// (when non-empty) `accumulator.len()` must be powers of two, with
/// `contribution.len() >= accumulator.len()`.
///
/// # Why
///
/// - **Scale before extend.** Horner-multiplying the smaller buffer is strictly less work than the
///   lifted one, and the lifted values are determined entirely by the smaller buffer via cyclic
///   repetition.
/// - **Cyclic repetition = polynomial lift on two-adic cosets.** In natural-order coset
///   evaluations, `extended[i] = original[i mod n_old]` realises the composition `P(X) -> P(X^r)`:
///   iterating `gJ` in natural order and raising to the `r`-th power cycles through `(gJ)^r` with
///   period `|(gJ)^r|`.
pub(super) fn cyclic_extend_and_accumulate<EF: Field>(
    accumulator: &mut Vec<EF>,
    contribution: Vec<EF>,
    beta: EF,
) {
    debug_assert!(contribution.len().is_power_of_two());
    debug_assert!(accumulator.is_empty() || accumulator.len().is_power_of_two());
    debug_assert!(contribution.len() >= accumulator.len());

    if accumulator.is_empty() {
        accumulator.extend(contribution);
        return;
    }

    if accumulator.len() == contribution.len() {
        // No lift needed; fuse the Horner mul and add into a single packed pass by
        // computing `contribution + beta * accumulator` in place on the (owned)
        // contribution buffer and swapping it in.
        let mut contribution = contribution;
        par_add_scaled_slice_in_place(&mut contribution, accumulator, beta);
        *accumulator = contribution;
        return;
    }

    par_scale_slice_in_place(accumulator, beta);
    while accumulator.len() < contribution.len() {
        accumulator.extend_from_within(..);
    }
    // TODO: use parallel packed addition
    accumulator
        .par_iter_mut()
        .zip(contribution.into_par_iter())
        .for_each(|(a, c)| *a += c);
}

// ============================================================================
// Quotient decomposition + commitment
// ============================================================================

/// Commit the quotient polynomial by splitting across the `D` quotient cosets.
///
/// The quotient is naturally evaluated on the quotient evaluation coset `gJ` of size
/// `N·D` (N = trace height, D = constraint degree). We view `J` as `D` disjoint
/// `H`-cosets: `J = ⋃_{t=0..D−1} ω_Jᵗ·H`. Reshaping `Q(gJ)` into an `N×D`
/// matrix makes column `t` the evaluations of a degree-`< N` polynomial qₜ on the
/// coset `g·ω_Jᵗ·H`.
///
/// We commit to all qₜ by LDE-extending them to the PCS domain `gK` (size `N·B`) and
/// hashing the resulting matrix. Naïvely this would require `D` separate coset-iDFT /
/// coset-DFT pairs (one per chunk). The "fused scaling" trick below collapses all of
/// them into a single plain iDFT, a diagonal scaling pass, and one plain DFT:
///
/// - a plain iDFT on each column yields coefficients multiplied by `(g·ω_Jᵗ)ᵏ` (the inverse coset
///   shift is absorbed into the coefficients),
/// - multiplying by `(ω_J⁻ᵏ)ᵗ` removes the per-chunk shift ω_Jᵗ while keeping the common factor gᵏ
///   baked in,
/// - a plain (unshifted) forward DFT then evaluates directly on the shifted coset `gK`, because gᵏ
///   already accounts for the coset offset.
///
/// `q_evals` is consumed and flattened to the base field for commitment.
///
/// # Panics
///
/// - If `q_evals.len()` is not divisible by N
/// - If blowup B < constraint degree D
pub fn commit_quotient<F, EF, SC>(
    config: &SC,
    q_evals: Vec<EF>,
    domain: &EvaluationDomain<F>,
) -> Committed<F, RowMajorMatrix<F>, SC::Lmcs>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
{
    let n = domain.trace_height();
    let d = domain.quotient_degree();
    let lde_height = domain.lifted().lde_height();

    debug_assert_eq!(q_evals.len(), n * d, "q_evals length must equal N · D");
    // D ≤ B (i.e. lde_height ≥ N · D) is enforced by `EvaluationDomain::new`.

    // ═══════════════════════════════════════════════════════════════════════
    // Step 0: Reshape to N × D matrix
    // ═══════════════════════════════════════════════════════════════════════
    // q_evals[r·D + t] = Q(g·ω_Jᵗ·ω_Hʳ), so column t gives
    // qₜ evaluated on the coset g·ω_Jᵗ·H.
    let m = RowMajorMatrix::new(q_evals, d);

    // ═══════════════════════════════════════════════════════════════════════
    // Step 1: Batched iDFT over H
    // ═══════════════════════════════════════════════════════════════════════
    // iDFT treats each column as evaluations on H (not the actual coset
    // g·ω_Jᵗ·H), producing shifted coefficients:
    //   c_hat[t, k] = a[t, k]·(g·ω_Jᵗ)ᵏ
    // where a[t, k] are the true coefficients of qₜ.
    let mut coeffs = info_span!("quotient iDFT", dims = %format!("{n}x{d}"))
        .in_scope(|| config.dft().idft_algebra_batch(m));

    // ═══════════════════════════════════════════════════════════════════════
    // Step 2: Fused coefficient scaling
    // ═══════════════════════════════════════════════════════════════════════
    // Multiply c_hat[t, k] by (ω_Jᵗ)⁻ᵏ → a[t, k]·gᵏ.
    // This removes the per-coset shift ω_Jᵗ while keeping gᵏ baked in.
    info_span!("quotient scaling", n).in_scope(|| {
        let omega_j_inv = domain.subgroup().generator_inverse();

        // Precompute ω_J⁻ᵏ for k = 0..N with sequential multiplications
        let row_bases: Vec<F> = omega_j_inv.powers().take(n).collect();

        // Row k, column t: multiply by (ω_J⁻ᵏ)ᵗ
        coeffs.par_rows_mut().zip(row_bases.par_iter()).for_each(|(row, &row_base)| {
            for (val, scale) in row.iter_mut().zip(row_base.powers()) {
                *val *= scale;
            }
        });
    });

    // ═══════════════════════════════════════════════════════════════════════
    // Step 3: Flatten EF → F, zero-pad to LDE height (N·B rows)
    // ═══════════════════════════════════════════════════════════════════════
    // We flatten before the DFT (rather than using dft_algebra_batch) because
    // we need base field for commitment anyway — this skips the reconstitute.
    //
    // Zero-padding from N to lde_height rows is needed because `dft_batch`
    // expects the full target-size buffer. The extra rows are zero because each
    // qₜ has degree < N. We pad here (after iDFT + scaling) so those two steps
    // work on the smaller N-row buffer.
    //
    // PERF: the full N·B-size DFT processes N·(B−1) zero rows through every
    // butterfly stage, costing O(N·B·log(N·B)) instead of O(N·B·log N). For
    // B = 4, N = 2^20 that is ≈ 9% overhead on this step (small relative to
    // total proving time since the quotient matrix has only D·DIM columns).
    //
    // The existing `lde_batch`/`coset_lde_batch` APIs cannot help: they take
    // *evaluations*, not coefficients. Using them would add a redundant DFT(N)
    // → iDFT(N) round-trip.
    //
    // What is conceptually missing from `TwoAdicSubgroupDft` is an
    // `added_bits` parameter on `dft_batch` / `coset_dft_batch` that evaluates
    // degree-< N coefficients on a larger domain of size N·2^added_bits. The
    // default would be zero-pad + the existing same-size DFT, but an optimized
    // implementation (like `Radix2DftParallel`) could run B separate N-size
    // DFTs — one per coset of H inside K — matching what its `coset_lde_batch`
    // already does internally after the iDFT phase.
    let base_width = d * EF::DIMENSION;
    let mut base_coeffs = <EF as BasedVectorSpace<F>>::flatten_to_base(coeffs.values);
    base_coeffs.resize(lde_height * base_width, F::ZERO);
    let coeffs_padded = RowMajorMatrix::new(base_coeffs, base_width);

    // ═══════════════════════════════════════════════════════════════════════
    // Step 4: Plain DFT (not coset DFT) on base field
    // ═══════════════════════════════════════════════════════════════════════
    // Because gᵏ is baked into the coefficients, the plain DFT evaluates
    // on gK directly: entry (i, t) gives qₜ(g·ω_Kⁱ).
    let quotient_matrix = info_span!("quotient DFT", dims = %format!("{lde_height}x{base_width}"))
        .in_scope(|| {
            let lde = config.dft().dft_batch(coeffs_padded);

            // ═══════════════════════════════════════════════════════════════
            // Step 5: Wrap for commitment
            // ═══════════════════════════════════════════════════════════════
            materialize_bitrev(lde)
        });

    let tree = config.lmcs().build_aligned_tree(vec![quotient_matrix]);

    // The quotient is committed on the same LDE coset as the trace commits.
    Committed::new(tree)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_dft::{NaiveDft, TwoAdicSubgroupDft};
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_matrix::dense::RowMajorMatrix;

    use super::upsample_evals;
    use crate::testing::configs::goldilocks_poseidon2::{Felt, QuadFelt};

    fn coeffs(height: usize) -> Vec<QuadFelt> {
        (0..height).map(|i| QuadFelt::from_u64((i as u64) + 1)).collect()
    }

    /// Checks that `upsample_evals` on `dft` produces the same result as a direct
    /// coset DFT of zero-padded coefficients.
    fn assert_upsample_matches_direct<D: TwoAdicSubgroupDft<Felt>>(dft: &D, shift: Felt) {
        let small_height = 8;
        let added_bits = 2;
        let large_height = small_height << added_bits;

        let small_coeffs = RowMajorMatrix::new(coeffs(small_height), 1);
        let small_evals = NaiveDft.coset_dft_algebra_batch(small_coeffs, shift).values;

        let mut large_coeffs = coeffs(small_height);
        large_coeffs.resize(large_height, QuadFelt::ZERO);
        let direct_large = NaiveDft
            .coset_dft_algebra_batch(RowMajorMatrix::new(large_coeffs, 1), shift)
            .values;

        let upsampled = upsample_evals::<Felt, QuadFelt, _>(dft, small_evals, added_bits);
        assert_eq!(upsampled, direct_large);
    }

    #[test]
    fn upsample_evals_matches_direct_coset_dft() {
        assert_upsample_matches_direct(&NaiveDft, Felt::GENERATOR.exp_power_of_2(2));
    }

    /// Same check with the production DFT backend.
    #[test]
    fn upsample_evals_with_radix2_dit_parallel_matches_naive() {
        use p3_dft::Radix2DitParallel;
        let dft = Radix2DitParallel::<Felt>::default();
        assert_upsample_matches_direct(&dft, Felt::GENERATOR.exp_power_of_2(2));
    }

    #[test]
    fn upsample_evals_with_zero_added_bits_returns_input_unchanged() {
        let evals = coeffs(8);
        let out = upsample_evals::<Felt, QuadFelt, _>(&NaiveDft, evals.clone(), 0);
        assert_eq!(out, evals);
    }
}
