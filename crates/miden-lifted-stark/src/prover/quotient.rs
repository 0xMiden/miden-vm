//! Quotient polynomial helpers: accumulation, vanishing division, decomposition.
//!
//! The prover orchestrates the quotient pipeline (loop over instances, accumulate,
//! divide, commit). This module provides the building blocks:
//!
//! - `cyclic_extend_and_scale`: Horner-style beta scaling + cyclic extension
//! - `divide_by_vanishing_in_place`: Divide by Z_H on the quotient evaluation domain
//! - [`commit_quotient`]: Decompose Q(gJ) into chunks and commit on gK

use alloc::{format, vec, vec::Vec};

use p3_dft::TwoAdicSubgroupDft;
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, TwoAdicField, batch_multiplicative_inverse,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;
use tracing::info_span;

use crate::{
    StarkConfig,
    coset::LiftedCoset,
    lmcs::{Lmcs, bitrev::materialize_bitrev},
    prover::commit::Committed,
};

// ============================================================================
// Accumulation
// ============================================================================

/// Cyclically extend the accumulator to `target_len` and scale every element by `β`.
///
/// On the first call (empty accumulator) this simply zero-fills to `target_len`.
/// On subsequent calls it scales the existing buffer by `β` (Horner folding)
/// then doubles via `extend_from_within` until it reaches `target_len`.
///
/// Both `accumulator.len()` and `target_len` must be powers of two, and
/// `target_len ≥ accumulator.len()`.
///
/// Cyclic extension is valid because H_small is a subgroup of H_big, so
/// evaluations repeat cyclically. The β scaling implements Horner folding for
/// multi-trace accumulation: `acc = acc·β + Nⱼ`.
pub fn cyclic_extend_and_scale<EF: Field>(accumulator: &mut Vec<EF>, target_len: usize, beta: EF) {
    if accumulator.is_empty() {
        accumulator.resize(target_len, EF::ZERO);
    } else {
        // Horner: scale the smaller buffer by beta before upsampling
        accumulator.par_iter_mut().for_each(|v| *v *= beta);
        // Cyclic extension by repeated doubling (all sizes are powers of 2)
        while accumulator.len() < target_len {
            accumulator.extend_from_within(..);
        }
    }
}

// ============================================================================
// Vanishing division
// ============================================================================

/// Divide quotient numerator by vanishing polynomial in-place (natural order).
///
/// Replaces each `numerator[i]` with `numerator[i] / Z_H(xᵢ)` where
/// `Z_H(X) = Xᴺ − 1` and `N` is the trace height.
///
/// This uses a periodicity trick: on the quotient evaluation coset `gJ` of size `N·D`,
/// the values `Z_H(x)` take only `D` distinct values, so we can batch-invert those `D`
/// values once and reuse them by modular indexing.
///
/// Note that here `coset.log_blowup()` is `log2(D)` because `coset` is the *quotient*
/// domain (blowup = constraint degree), not the PCS/FRI blowup `B`.
pub fn divide_by_vanishing_in_place<F, EF>(numerator: &mut [EF], coset: &LiftedCoset)
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
{
    // D = constraint degree. On the quotient coset, log_blowup() = log₂(D).
    let log_blowup = coset.log_blowup();
    let num_distinct = 1 << log_blowup;

    // The D distinct values of Z_H on gJ:
    // Z_H(g·ω_Jⁱ) = sᴺ·ω_Dⁱ − 1 where
    // - s is the coset shift
    // - ω_D is a D-th root of unity.
    let shift: F = coset.lde_shift();
    let s_pow_n = shift.exp_power_of_2(coset.log_trace_height as usize);
    let z_h_evals: Vec<F> = F::two_adic_generator(log_blowup)
        .powers()
        .take(num_distinct)
        .map(|x| s_pow_n * x - F::ONE)
        .collect();

    let inv_van = batch_multiplicative_inverse(&z_h_evals);

    // Parallel division using modular indexing for periodicity.
    // Z_H has only num_distinct unique values on gJ; power-of-2 size
    // lets us use bitmask: i & (num_distinct - 1) == i % num_distinct.
    numerator.par_iter_mut().enumerate().for_each(|(i, n)| {
        *n *= inv_van[i & (num_distinct - 1)];
    });
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
    coset: &LiftedCoset,
) -> Committed<F, RowMajorMatrix<F>, SC::Lmcs>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
{
    let n = coset.trace_height();
    let d = q_evals.len() / n;
    let log_d = log2_strict_usize(d);
    let log_blowup = config.pcs().log_blowup();
    let b = 1usize << log_blowup;

    debug_assert_eq!(q_evals.len() % n, 0, "q_evals length must be divisible by N");
    debug_assert!(b >= d, "blowup B must be >= constraint degree D");

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
        let omega_j_inv = F::two_adic_generator(coset.log_trace_height as usize + log_d).inverse();

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
    // Step 3: Flatten EF → F, zero-pad to N·B rows
    // ═══════════════════════════════════════════════════════════════════════
    // We flatten before the DFT (rather than using dft_algebra_batch) because
    // we need base field for commitment anyway — this skips the reconstitute.
    //
    // Zero-padding from N to N·B rows is needed because `dft_batch` expects
    // the full target-size buffer. The extra rows are zero because each qₜ has
    // degree < N. We pad here (after iDFT + scaling) so those two steps work
    // on the smaller N-row buffer.
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
    base_coeffs.resize(n * b * base_width, F::ZERO);
    let coeffs_padded = RowMajorMatrix::new(base_coeffs, base_width);

    // ═══════════════════════════════════════════════════════════════════════
    // Step 4: Plain DFT (not coset DFT) on base field
    // ═══════════════════════════════════════════════════════════════════════
    // Because gᵏ is baked into the coefficients, the plain DFT evaluates
    // on gK directly: entry (i, t) gives qₜ(g·ω_Kⁱ).
    let quotient_matrix = info_span!("quotient DFT", dims = %format!("{}x{base_width}", n * b))
        .in_scope(|| {
            let lde = config.dft().dft_batch(coeffs_padded);

            // ═══════════════════════════════════════════════════════════════
            // Step 5: Wrap for commitment
            // ═══════════════════════════════════════════════════════════════
            materialize_bitrev(lde)
        });

    let tree = config.lmcs().build_aligned_tree(vec![quotient_matrix]);

    Committed::new(tree, log_blowup)
}
