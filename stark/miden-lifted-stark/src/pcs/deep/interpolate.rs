//! Barycentric interpolation for DEEP openings (with lifting).
//!
//! The DEEP technique needs values `f(z)` for many committed polynomials `f` at a
//! small number of out-of-domain (OOD) points `z`. Interpolating a degree-`< d`
//! polynomial from `d` samples naively is `O(d²)`; barycentric interpolation makes
//! it `O(d)` once we precompute the expensive inverses.
//!
//! # Notation
//! - Domain points: `xᵢ = g·ωⁱ` for `i = 0..d−1` (a coset `gH` of size `d`).
//! - OOD points: `zⱼ`, chosen so `zⱼ ≠ xᵢ` for all `i, j`.
//! - Vanishing on `gH`: `V_{gH}(X) = (X/g)ᵈ − 1`.
//!
//! # Barycentric form
//! For `deg(f) < d`:
//!
//! ```text
//! f(z) = s(z) · Σᵢ wᵢ(z) · f(xᵢ)
//! s(z) = V_{gH}(z) / d = ((z/g)ᵈ − 1) / d
//! wᵢ(z) = xᵢ / (z − xᵢ)
//! ```
//!
//! The implementation factors `wᵢ(z) = xᵢ/(z − xᵢ) = z · (1/(z − xᵢ) − 1/z)`, replacing
//! each base×extension product `xᵢ · qᵢ(z)` with an extension subtraction `qᵢ(z) − 1/z`
//! and pulling the shared `z` into the scaling `s(z)`. This requires `z ≠ 0`.
//!
//! # Point quotients
//! We precompute `qᵢ(zⱼ) = 1/(zⱼ − xᵢ)` for all domain points `xᵢ` and all
//! opening points `zⱼ` using batch inversion (Montgomery's trick). This single
//! table is reused for:
//! - barycentric weights: `wᵢ(zⱼ) = zⱼ · (qᵢ(zⱼ) − 1/zⱼ)`
//! - DEEP quotients: `(f(zⱼ) − f(X)) / (zⱼ − X)`
//!
//! # Lifting and weight folding
//! In lifted STARKs, different matrices correspond to polynomials on different
//! (power-of-two) domain sizes. A polynomial on a smaller domain is embedded into
//! the max domain by composing with an r-th power map: `f_lift(X) = f(Xʳ)`.
//! The verifier always queries at `z`, so the prover reports `f(zʳ)` for that
//! matrix; equivalently, it is evaluating `f_lift(z)`.
//!
//! To avoid recomputing barycentric weights for every height, we exploit the
//! bit-reversed ordering used by commitments: on a two-adic coset, points come in
//! adjacent `(+x, −x)` pairs. When lifting by a factor of 2, the lifted polynomial
//! `f(X²)` takes the same value on each adjacent pair, so we can fold the barycentric
//! sum by *summing the corresponding weights*. Repeating this `k` times handles lift
//! factors `r = 2ᵏ`.
//!
//! **Why weight summing is correct.** In bit-reversed order, `x_{2i+1} = −x_{2i}`.
//! Adding the two barycentric weights gives
//! `w_{2i} + w_{2i+1} = x/(z−x) + (−x)/(z+x) = 2x²/(z²−x²) = 2·w'ᵢ(z²)`,
//! where `w'ᵢ` is the weight on the squared domain. The factor of 2 cancels with the
//! halved scaling `s'(z²) = 2·s(z)`, so the interpolation identity is preserved.

use alloc::{collections::BTreeSet, vec::Vec};
use core::marker::PhantomData;

use p3_field::{ExtensionField, FieldArray, TwoAdicField, batch_multiplicative_inverse};
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
use p3_util::{linear_map::LinearMap, log2_strict_usize, reconstitute_from_base};
use tracing::{debug_span, info_span};

use crate::lmcs::row_list::RowList;

/// Precomputed `1/(zⱼ − xᵢ)` for N evaluation points.
///
/// This enables batched `O(d)` barycentric evaluation and DEEP quotient construction
/// without repeating inversions.
pub struct PointQuotients<F: TwoAdicField, EF: ExtensionField<F>, const N: usize> {
    /// The evaluation points `[z₀, z₁, ..., z_{N-1}]`.
    points: FieldArray<EF, N>,
    /// `point_quotient[i][j] = 1/(zⱼ − xᵢ)` for domain point xᵢ and eval point zⱼ.
    pub(super) point_quotient: Vec<FieldArray<EF, N>>,
    _marker: PhantomData<F>,
}

impl<F: TwoAdicField, EF: ExtensionField<F>, const N: usize> PointQuotients<F, EF, N> {
    /// Create precomputation for N evaluation points via batched inversion.
    ///
    /// Preconditions: all evaluation points must be outside the LDE evaluation coset
    /// `gK` represented by `coset_points` (i.e., `zⱼ ≠ xᵢ` for all i, j). Otherwise
    /// division by zero occurs in the barycentric weights and DEEP quotient. Points must
    /// also be nonzero, since [`Self::batch_eval_lifted`] inverts them.
    ///
    /// In the common case where the trace domain `H` is a sub-coset of `gK`, avoiding
    /// `gK` also avoids `H`. If a caller uses a different domain relationship, it must
    /// additionally ensure points are outside the trace domain.
    pub fn new(points: FieldArray<EF, N>, coset_points: &[F]) -> Self {
        let _span = info_span!("PointQuotients::new", n = coset_points.len()).entered();
        let n_points = coset_points.len();

        // Compute differences in parallel: for each domain point x, compute [z₀ - x, z₁ - x, ...]
        let diffs: Vec<FieldArray<EF, N>> =
            coset_points.par_iter().map(|&x| points.map(|z| z - x)).collect();

        // Flatten FieldArray slice for batch inversion (zero-copy), then reconstitute.
        let diffs_flat = FieldArray::as_raw_slice(&diffs).as_flattened();
        let invs_flat = batch_multiplicative_inverse(diffs_flat);
        debug_assert_eq!(invs_flat.len(), N * n_points);
        // SAFETY: `reconstitute_from_base` requires:
        // - Same alignment: `FieldArray<EF, N>` is `#[repr(transparent)]` over `[EF; N]`, so it has
        //   the same alignment as `EF`.
        // - Length is a multiple of N: `invs_flat` has length `N * n_points` (one inverse per OOD
        //   point per domain element).
        let point_quotient: Vec<FieldArray<EF, N>> = unsafe { reconstitute_from_base(invs_flat) };

        debug_assert_eq!(point_quotient.len(), n_points);

        Self {
            points,
            point_quotient,
            _marker: PhantomData,
        }
    }

    /// Evaluate all matrix columns at `[z₀ʳ, z₁ʳ, …, z_{N−1}ʳ]`.
    ///
    /// Here `r = domain_size / matrix_height` is the lift factor for that matrix.
    ///
    /// Returns evaluations grouped by commitment: `groups[group_idx][matrix_idx][col_idx]`
    /// where each element is a `FieldArray<EF, N>` containing evaluations at all N points.
    /// This batches N evaluation points together, using `columnwise_dot_product_batched<N>`
    /// for better cache utilization than N separate calls.
    ///
    /// Implementation note: we compute barycentric weights for the maximum domain once,
    /// then derive weights for smaller heights by folding (summing blocks). All heights
    /// share the same precomputed point quotients `1/(zⱼ − xᵢ)`.
    pub fn batch_eval_lifted<M: Matrix<F>>(
        &self,
        matrices_groups: &[Vec<&M>],
        coset_points: &[F],
        log_blowup: u8,
    ) -> RowList<FieldArray<EF, N>> {
        let _span = info_span!("batch_eval_lifted", n_groups = matrices_groups.len()).entered();
        let n = coset_points.len();
        let d = n >> log_blowup as usize;
        let log_d = log2_strict_usize(d);

        let shift = coset_points[0]; // g in bit-reversed order
        let shift_inverse = shift.inverse();

        // Compute barycentric scaling factors for each point, folding in the `zⱼ` shared by
        // the factored weights below: zⱼ · sⱼ(zⱼ) = zⱼ · ((zⱼ/g)ᵈ − 1) / d
        let barycentric_scalings = self.points.map(|point| {
            let z_over_shift = point * shift_inverse;
            let t = z_over_shift.exp_power_of_2(log_d) - EF::ONE;
            point * t.div_2exp_u64(log_d as u64)
        });

        let used_degrees: BTreeSet<usize> = matrices_groups
            .iter()
            .flat_map(|g| g.iter().map(|m| m.height() >> log_blowup as usize))
            .collect();

        // Compute factored barycentric weights for each point at each height:
        // aᵢⱼ(zⱼ) = point_quotient[i][j] − 1/zⱼ, with the shared zⱼ carried by
        // `barycentric_scalings` so that zⱼ · aᵢⱼ = xᵢ / (zⱼ − xᵢ).
        // For smaller domains, sum chunks (weight folding).
        let inv_points = self.points.map(|point| point.inverse());
        let barycentric_weights: LinearMap<usize, Vec<FieldArray<EF, N>>> =
            debug_span!("barycentric_weights", d).in_scope(|| {
                assert_eq!(*used_degrees.last().unwrap(), d);
                // Initial weights at full domain size
                let top_weights: Vec<FieldArray<EF, N>> =
                    self.point_quotient[..d].par_iter().map(|invs| *invs - inv_points).collect();

                let mut weights = Vec::with_capacity(used_degrees.len());
                weights.push(top_weights);

                // Descending order: progressively sum chunks to shrink weights
                for &next_degree in used_degrees.iter().rev().skip(1) {
                    let prev_weights = weights.last().unwrap();
                    let chunk_size = prev_weights.len() / next_degree;
                    let next_weights = prev_weights
                        .par_chunks_exact(chunk_size)
                        .map(|chunk| chunk.iter().copied().sum())
                        .collect();
                    weights.push(next_weights);
                }

                weights.into_iter().map(|w| (w.len(), w)).collect()
            });

        // f(zⱼʳ) = sⱼ(zⱼ)·Σᵢ wᵢⱼ(zⱼ)·f(xᵢ)
        // For each group, evaluate at all N points using columnwise_dot_product_batched
        // Returns Vec<[EF; N]> where result[col][point] = eval of column col at point point
        let all_evals: Vec<Vec<FieldArray<EF, N>>> = matrices_groups
            .iter()
            .flat_map(|group| {
                group.iter().map(|m| {
                    let weights = &barycentric_weights[&(m.height() >> log_blowup as usize)];
                    let _guard =
                        debug_span!("evaluate matrix", height = weights.len(), width = m.width())
                            .entered();
                    let mut results = m.columnwise_dot_product_batched(weights);
                    for batch_evals in results.iter_mut() {
                        *batch_evals *= barycentric_scalings;
                    }
                    results
                })
            })
            .collect();

        RowList::from_rows(&all_evals)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_dft::{NaiveDft, TwoAdicSubgroupDft};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::{
        bitrev::BitReversibleMatrix,
        dense::RowMajorMatrix,
        interpolation::{Interpolate, compute_adjusted_weights},
    };
    use p3_util::reverse_slice_index_bits;
    use rand::{RngExt, SeedableRng, distr::StandardUniform, prelude::SmallRng};

    use super::*;
    use crate::{
        domain::Coset,
        testing::{
            canonical_domain,
            configs::goldilocks_poseidon2::{Felt, QuadFelt},
        },
    };

    /// Verify `batch_eval_lifted` matches `interpolate_coset` for various lift factors.
    ///
    /// This test creates matrices of varying heights and verifies that lifting produces
    /// the correct evaluation. To satisfy `batch_eval_lifted`'s requirement that at least
    /// one matrix fills the domain, we include a full-height dummy matrix alongside
    /// each smaller test matrix.
    #[test]
    fn batch_eval_matches_interpolate_coset() {
        let rng = &mut SmallRng::seed_from_u64(42);
        let log_blowup = 2;
        let log_n = 8; // Full LDE domain size = 256
        let n = 1 << log_n;
        let domain = canonical_domain::<Felt>(log_n, 0);
        let shift = domain.lde_shift();

        // Coset points in bit-reversed order for our barycentric evaluation
        let coset_points_br = domain.lde_coset().bit_reversed_points();

        // Random out-of-domain evaluation point
        let z: QuadFelt = rng.sample(StandardUniform);

        // Test multiple polynomial degrees
        for log_scaling in 0..=2 {
            // Polynomial degree (trace height before LDE)
            let poly_degree = (n >> log_blowup) >> log_scaling;
            // LDE evaluation count = poly_degree * blowup
            let lde_height = poly_degree << log_blowup;
            let width = 3;

            // For lifted polynomials, the coset becomes (gK)ʳ = gʳ · Kʳ
            // So the shift for the smaller coset is shiftʳ
            let lifted_shift = shift.exp_power_of_2(log_scaling);

            // Generate random polynomial coefficients and pad to LDE size
            let mut coeffs_values = RowMajorMatrix::<Felt>::rand(rng, poly_degree, width).values;
            coeffs_values.resize(lde_height * width, Felt::ZERO);
            let padded_coeffs = RowMajorMatrix::new(coeffs_values, width);

            // Compute evaluations on the lifted coset via DFT (standard order)
            let evals_std = NaiveDft.coset_dft_batch(padded_coeffs, lifted_shift);

            // Convert to bit-reversed order for our evaluation
            let evals_br: RowMajorMatrix<Felt> =
                evals_std.clone().bit_reverse_rows().to_row_major_matrix();

            // Our method computes f(zʳ) where r = n / lde_height = 2^log_scaling
            let z_lifted = z.exp_power_of_2(log_scaling);

            // Create a full-height dummy matrix to satisfy batch_eval_lifted's domain requirement
            // (at least one matrix must fill the domain)
            let dummy_matrix = RowMajorMatrix::new(vec![Felt::ZERO; n], 1);

            // Our barycentric evaluation using PointQuotients<1>
            // Include both the dummy (full height) and the test matrix (possibly smaller)
            let quotient =
                PointQuotients::<Felt, QuadFelt, 1>::new(FieldArray([z]), &coset_points_br);
            let result = quotient.batch_eval_lifted(
                &[vec![&dummy_matrix, &evals_br]],
                &coset_points_br,
                log_blowup,
            );
            // Skip the 1-column dummy, unwrap FieldArray<EF, 1> → EF
            let our_evals: Vec<QuadFelt> =
                result.as_slice()[1..].iter().map(|arr| arr[0]).collect();

            // Standard interpolation on the lifted coset
            let expected_evals = evals_std.interpolate_coset(lifted_shift, z_lifted);

            assert_eq!(
                our_evals.len(),
                expected_evals.len(),
                "log_scaling={log_scaling}: length mismatch"
            );
            for (col, (our, expected)) in our_evals.iter().zip(expected_evals.iter()).enumerate() {
                assert_eq!(
                    our, expected,
                    "log_scaling={log_scaling}, col={col}: evaluation mismatch"
                );
            }
        }
    }

    /// Verify `batch_eval_lifted` matches `interpolate_coset_with_precomputation`.
    #[test]
    fn batch_eval_matches_interpolate_with_precomputation() {
        let rng = &mut SmallRng::seed_from_u64(123);
        let log_blowup = 2;
        let log_n = 8;
        let n = 1 << log_n;
        let domain = canonical_domain::<Felt>(log_n, 0);
        let shift = domain.lde_shift();

        // Coset points in bit-reversed order
        let coset_points_br = domain.lde_coset().bit_reversed_points();

        // Random out-of-domain evaluation point
        let z: QuadFelt = rng.sample(StandardUniform);

        // Create quotient for bit-reversed coset using PointQuotients<1>
        let quotient = PointQuotients::<Felt, QuadFelt, 1>::new(FieldArray([z]), &coset_points_br);

        // Test polynomial with no lifting (log_scaling = 0, full LDE domain)
        let poly_degree = n >> log_blowup; // = 64
        let lde_height = n; // = 256, full LDE
        let width = 4;

        // Generate random polynomial coefficients and pad to LDE size
        let mut coeffs_values = RowMajorMatrix::<Felt>::rand(rng, poly_degree, width).values;
        coeffs_values.resize(lde_height * width, Felt::ZERO);
        let padded_coeffs = RowMajorMatrix::new(coeffs_values, width);

        // Compute evaluations on coset via DFT (standard order)
        let evals_std = NaiveDft.coset_dft_batch(padded_coeffs, shift);

        // Convert to bit-reversed order
        let evals_br = evals_std.clone().bit_reverse_rows();

        // Our barycentric evaluation (no lifting since lde_height = n)
        let result = quotient.batch_eval_lifted(&[vec![&evals_br]], &coset_points_br, log_blowup);
        // Unwrap FieldArray<EF, 1> → EF
        let our_evals: Vec<QuadFelt> = result.as_slice().iter().map(|arr| arr[0]).collect();

        // Convert our diff_invs from bit-reversed to standard order for precomputation
        let mut diff_invs_std: Vec<QuadFelt> =
            quotient.point_quotient[..lde_height].iter().map(|arr| arr[0]).collect();
        reverse_slice_index_bits(&mut diff_invs_std);

        // Interpolation with precomputation (standard order)
        let adjusted_weights = compute_adjusted_weights(z, &diff_invs_std);
        let expected_evals =
            evals_std.interpolate_coset_with_precomputation(shift, z, &adjusted_weights);

        assert_eq!(our_evals.len(), expected_evals.len(), "length mismatch");
        for (col, (&our, &expected)) in our_evals.iter().zip(expected_evals.iter()).enumerate() {
            assert_eq!(our, expected, "col={col}: evaluation mismatch");
        }
    }

    /// Verify `PointQuotients<2>` produces consistent results with separate `PointQuotients<1>`
    /// calls.
    #[test]
    fn point_quotients_matches_single_point() {
        use alloc::vec::Vec;

        use p3_matrix::Matrix;

        let rng = &mut SmallRng::seed_from_u64(999);
        let log_blowup = 2;
        let log_n = 8;
        let n = 1 << log_n;
        let domain = canonical_domain::<Felt>(log_n, 0);
        let shift = domain.lde_shift();

        // Coset points in bit-reversed order
        let coset_points_br = domain.lde_coset().bit_reversed_points();

        // Two random out-of-domain evaluation points
        let z1: QuadFelt = rng.sample(StandardUniform);
        let z2: QuadFelt = rng.sample(StandardUniform);

        // Generate test matrices of varying heights
        let poly_degree_1 = n >> log_blowup; // Full size
        let poly_degree_2 = poly_degree_1 >> 1; // Half size
        let width = 3;

        let lifted_shift_1 = shift;
        let lifted_shift_2 = shift.square();

        let mut coeffs1 = RowMajorMatrix::<Felt>::rand(rng, poly_degree_1, width).values;
        coeffs1.resize(n * width, Felt::ZERO);
        let evals1_std =
            NaiveDft.coset_dft_batch(RowMajorMatrix::new(coeffs1, width), lifted_shift_1);
        let evals1_br: RowMajorMatrix<Felt> = evals1_std.bit_reverse_rows().to_row_major_matrix();

        let mut coeffs2 = RowMajorMatrix::<Felt>::rand(rng, poly_degree_2, width).values;
        coeffs2.resize((n >> 1) * width, Felt::ZERO);
        let evals2_std =
            NaiveDft.coset_dft_batch(RowMajorMatrix::new(coeffs2, width), lifted_shift_2);
        let evals2_br: RowMajorMatrix<Felt> = evals2_std.bit_reverse_rows().to_row_major_matrix();

        let matrices_groups: Vec<Vec<&RowMajorMatrix<Felt>>> = vec![vec![&evals1_br, &evals2_br]];

        // --- Single-point evaluation using PointQuotients<1> (baseline) ---
        let sq1 = PointQuotients::<Felt, QuadFelt, 1>::new(FieldArray([z1]), &coset_points_br);
        let sq2 = PointQuotients::<Felt, QuadFelt, 1>::new(FieldArray([z2]), &coset_points_br);
        let single_evals1 = sq1.batch_eval_lifted(&matrices_groups, &coset_points_br, log_blowup);
        let single_evals2 = sq2.batch_eval_lifted(&matrices_groups, &coset_points_br, log_blowup);

        // --- Multi-point evaluation ---
        let mq = PointQuotients::<Felt, QuadFelt, 2>::new(FieldArray([z1, z2]), &coset_points_br);
        let multi_evals = mq.batch_eval_lifted(&matrices_groups, &coset_points_br, log_blowup);

        // Verify point_quotient matches
        for (i, (sq1_q, sq2_q)) in
            sq1.point_quotient.iter().zip(sq2.point_quotient.iter()).enumerate()
        {
            let mq_q = &mq.point_quotient[i];
            assert_eq!(sq1_q[0], mq_q[0], "point_quotient mismatch at {i} for z1");
            assert_eq!(sq2_q[0], mq_q[1], "point_quotient mismatch at {i} for z2");
        }

        // Verify batch_eval_lifted results match.
        // Single-point evals have FieldArray<EF, 1>; multi-point evals have FieldArray<EF, 2>.
        assert_eq!(multi_evals.num_rows(), single_evals1.num_rows());
        for (row_idx, ((multi_row, single_row1), single_row2)) in multi_evals
            .iter_rows()
            .zip(single_evals1.iter_rows())
            .zip(single_evals2.iter_rows())
            .enumerate()
        {
            assert_eq!(
                multi_row.len(),
                single_row1.len(),
                "length mismatch for z1 at row {row_idx}"
            );

            for (col, (m, s)) in multi_row.iter().zip(single_row1.iter()).enumerate() {
                assert_eq!(m[0], s[0], "mismatch at row {row_idx}, col {col} for z1");
            }

            for (col, (m, s)) in multi_row.iter().zip(single_row2.iter()).enumerate() {
                assert_eq!(m[1], s[0], "mismatch at row {row_idx}, col {col} for z2");
            }
        }
    }

    /// Verify two-point `PointQuotients<2>` produces correct results for mixed-height
    /// matrices, checked against `interpolate_coset`.
    #[test]
    fn two_point_quotients_match_interpolate_coset() {
        let rng = &mut SmallRng::seed_from_u64(999);
        let log_blowup = 2;
        let log_n = 8;
        let n = 1 << log_n;
        let domain = canonical_domain::<Felt>(log_n, 0);
        let shift = domain.lde_shift();

        let coset_points_br = domain.lde_coset().bit_reversed_points();

        let z1: QuadFelt = rng.sample(StandardUniform);
        let z2: QuadFelt = rng.sample(StandardUniform);

        // Matrix 1: full height (no lifting)
        let poly_degree_1 = n >> log_blowup;
        let width = 3;
        let lifted_shift_1 = shift;

        let mut coeffs1 = RowMajorMatrix::<Felt>::rand(rng, poly_degree_1, width).values;
        coeffs1.resize(n * width, Felt::ZERO);
        let evals1_std =
            NaiveDft.coset_dft_batch(RowMajorMatrix::new(coeffs1, width), lifted_shift_1);
        let evals1_br: RowMajorMatrix<Felt> =
            evals1_std.clone().bit_reverse_rows().to_row_major_matrix();

        // Matrix 2: half height (lift factor 2)
        let poly_degree_2 = poly_degree_1 >> 1;
        let lifted_shift_2 = shift.square();

        let mut coeffs2 = RowMajorMatrix::<Felt>::rand(rng, poly_degree_2, width).values;
        coeffs2.resize((n >> 1) * width, Felt::ZERO);
        let evals2_std =
            NaiveDft.coset_dft_batch(RowMajorMatrix::new(coeffs2, width), lifted_shift_2);
        let evals2_br: RowMajorMatrix<Felt> =
            evals2_std.clone().bit_reverse_rows().to_row_major_matrix();

        let matrices_groups: Vec<Vec<&RowMajorMatrix<Felt>>> = vec![vec![&evals1_br, &evals2_br]];

        // Evaluate at both points using PointQuotients<2>
        let pq = PointQuotients::<Felt, QuadFelt, 2>::new(FieldArray([z1, z2]), &coset_points_br);
        let result = pq.batch_eval_lifted(&matrices_groups, &coset_points_br, log_blowup);
        let rows: Vec<&[FieldArray<QuadFelt, 2>]> = result.iter_rows().collect();
        assert_eq!(rows.len(), 2, "expected 2 matrix rows");

        // Verify each point against reference
        for (point_idx, (label, z)) in
            [(0, "z1", z1), (1, "z2", z2)].into_iter().map(|(i, l, z)| (i, (l, z)))
        {
            // Matrix 1 (no lifting): evaluate at z directly
            let expected1 = evals1_std.interpolate_coset(lifted_shift_1, z);
            for (col, (&our, &exp)) in rows[0].iter().zip(expected1.iter()).enumerate() {
                assert_eq!(our[point_idx], exp, "{label}, mat1, col={col}: mismatch");
            }

            // Matrix 2 (lift factor 2): evaluate at z^2
            let z_lifted = z.square();
            let expected2 = evals2_std.interpolate_coset(lifted_shift_2, z_lifted);
            for (col, (&our, &exp)) in rows[1].iter().zip(expected2.iter()).enumerate() {
                assert_eq!(our[point_idx], exp, "{label}, mat2, col={col}: mismatch");
            }
        }
    }
}
