use alloc::vec::Vec;
use core::iter::zip;

use miden_lifted_air::log2_strict_u8;
use miden_stark_transcript::ProverChannel;
use p3_field::{
    ExtensionField, Field, FieldArray, PackedFieldExtension, PackedValue, TwoAdicField,
};
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
use tracing::info_span;

use crate::{
    lmcs::{Lmcs, LmcsTree, row_list::RowList},
    pcs::deep::{DeepParams, interpolate::PointQuotients},
    util::{
        align::aligned_widths, bitrev::bit_reversed_coset_points, horner::horner,
        packing::PackedFieldExtensionExt,
    },
};

/// The DEEP quotient `Q(X)` evaluated over the LDE domain.
///
/// Combines all polynomial evaluation claims into a single low-degree polynomial.
///
/// Intuition: DEEP turns many separate opening claims into a single polynomial identity.
///
/// After reducing all opened columns with a random `α` into one polynomial `f_red(X)`,
/// DEEP defines
///
/// ```text
/// Q(X) = Σⱼ βʲ · (f_red(zⱼ) − f_red(X)) / (zⱼ − X)
/// ```
///
/// If the claimed OOD values `f_red(zⱼ)` are correct, each numerator vanishes at
/// `X = zⱼ` and cancels the denominator, so `Q` is a (low-degree) polynomial.
/// If any claim is wrong, the corresponding term has a pole and `Q` is not even a
/// polynomial; committing to `Q` via FRI then detects the inconsistency.
pub struct DeepPoly<EF> {
    /// The DEEP quotient polynomial evaluated over the domain.
    /// `deep_evals[i]` is the evaluation at the i-th domain point (bit-reversed order).
    pub(crate) deep_evals: Vec<EF>,
}

impl<EF> DeepPoly<EF> {
    /// Construct `Q(X)` by evaluating trace trees at the opening points.
    ///
    /// This computes the LDE coset points from the trace tree height, evaluates the committed
    /// matrices at `eval_points`, and then calls [`Self::from_evals`].
    ///
    /// Preconditions: `eval_points` must be distinct and lie outside the trace subgroup `H`
    /// and LDE evaluation coset `gK`. The outer protocol is expected to enforce this.
    pub fn from_trees<L, M, const N: usize, Ch>(
        params: DeepParams,
        trace_trees: &[&L::Tree<M>],
        eval_points: [EF; N],
        log_blowup: u8,
        channel: &mut Ch,
    ) -> Self
    where
        L: Lmcs,
        L::F: TwoAdicField,
        EF: ExtensionField<L::F>,
        M: Matrix<L::F>,
        Ch: ProverChannel<F = L::F, Commitment = L::Commitment>,
    {
        let lde_height = trace_trees.first().expect("at least one trace tree required").height();
        assert!(
            trace_trees.iter().all(|tree| tree.height() == lde_height),
            "mixed trace tree heights are not supported"
        );

        let log_lde_height = log2_strict_u8(lde_height);
        let coset_points = bit_reversed_coset_points::<L::F>(log_lde_height);

        let matrices_groups: Vec<Vec<&M>> =
            trace_trees.iter().map(|tree| tree.leaves().iter().collect()).collect();

        let quotient = PointQuotients::new(FieldArray::from(eval_points), &coset_points);
        let batched_evals = info_span!("evaluate at OOD points")
            .in_scope(|| quotient.batch_eval_lifted(&matrices_groups, &coset_points, log_blowup));

        let (deep_poly, _evals) =
            Self::from_evals::<L, M, N, Ch>(params, trace_trees, batched_evals, &quotient, channel);
        deep_poly
    }

    /// Construct `Q(X)` from committed matrices and batched evaluations at N opening points.
    ///
    /// # Arguments
    /// - `trace_trees`: Trace trees used to derive alignment and matrix groups. All trees must
    ///   share the same alignment; mixed alignments are not supported.
    /// - `batched_evals`: One row per matrix, each row holding `FieldArray<EF, N>` per column.
    ///   Widths match the unpadded matrices; alignment padding is applied lazily during channel
    ///   writes and Horner reduction.
    /// - `quotient`: Precomputed `1/(zⱼ − xᵢ)` for all opening points zⱼ and domain points xᵢ.
    ///
    /// Returns the constructed `DeepPoly` and the (unaligned) `batched_evals` for test inspection.
    ///
    /// Columns are reduced with a random `α` using Horner
    /// (`f_red(X) = Σᵢ α^{W−1−i} · fᵢ(X)`). This lets the verifier stream the
    /// reduction as it reads opened rows, and ensures a cheating prover cannot satisfy
    /// some constraints while failing others with non-negligible probability.
    ///
    /// Implementation note: we fuse a sign change into the per-column coefficient stream
    /// so reduction and quotient assembly can share a single traversal over the domain.
    pub fn from_evals<L, M, const N: usize, Ch>(
        params: DeepParams,
        trace_trees: &[&L::Tree<M>],
        batched_evals: RowList<FieldArray<EF, N>>,
        quotient: &PointQuotients<L::F, EF, N>,
        channel: &mut Ch,
    ) -> (Self, RowList<FieldArray<EF, N>>)
    where
        L: Lmcs,
        L::F: TwoAdicField,
        EF: ExtensionField<L::F>,
        M: Matrix<L::F>,
        Ch: ProverChannel<F = L::F, Commitment = L::Commitment>,
    {
        // The alignment of the trees defines the number of virtual zero-values columns were
        // inserted while hashing the rows of the matrices. The prover pads the opened rows of each
        // matrix with zeros, so that the length of the row is a multiple of the alignment.
        // The alignment is tied to the underlying cryptographic permutation's rate.
        let alignment =
            trace_trees.first().expect("at least one tree must be provided").alignment();
        assert!(
            trace_trees.iter().all(|tree| tree.alignment() == alignment),
            "mixed trace tree alignments are not supported"
        );

        // Collect the LDE matrices from each committed tree, grouped by commitment.
        // matrices_groups[group_idx][matrix_idx] is a reference to the LDE matrix
        // whose rows are bit-reversed coset evaluations at height `lde_height`.
        let matrices_groups: Vec<Vec<&M>> =
            trace_trees.iter().map(|tree| tree.leaves().iter().collect()).collect();

        // 1. Bind the prover's OOD evaluation claims into the Fiat-Shamir transcript. The DEEP
        //    challenges (alpha, beta) are derived after this, so a cheating prover cannot adapt its
        //    claims to the challenges. Each matrix row is zero-padded to the tree alignment,
        //    matching the virtual zero columns the LMCS inserts when hashing rows. All matrices are
        //    concatenated into a single flat slice per eval point.
        for point_idx in 0..N {
            let flat: Vec<EF> =
                batched_evals.iter_aligned(alignment).map(|fa| fa[point_idx]).collect();
            channel.send_algebra_slice(&flat);
        }

        // 2. Grind for proof-of-work witness
        let _pow_witness = info_span!("DEEP grind", bits = params.deep_pow_bits)
            .in_scope(|| channel.grind(params.deep_pow_bits));

        // 3. Sample DEEP challenges
        let challenge_columns: EF = channel.sample_algebra_element();
        let challenge_points: EF = channel.sample_algebra_element();

        // Pre-compute f_reduced(zⱼ) for all N points using Horner.
        // Reduces across all matrices' aligned columns in flat order.
        let f_reduced_at_points: FieldArray<EF, N> =
            horner(challenge_columns, batched_evals.iter_aligned(alignment));

        let w = <L::F as Field>::Packing::WIDTH;
        let point_quotient = &quotient.point_quotient;
        let n = point_quotient.len();

        let group_sizes: Vec<usize> = matrices_groups.iter().map(Vec::len).collect();
        let widths: Vec<usize> =
            matrices_groups.iter().flat_map(|g| g.iter().map(|m| m.width())).collect();

        // Align each matrix width so padding is explicit in the transcript.
        let aligned_widths = aligned_widths(widths, alignment);

        // Compute explicit coefficients for -f_reduced(X) = -Σᵢ α^{W−1−i}·fᵢ(X).
        //
        // The verifier computes f_reduced via `horner(alpha, columns)`, which assigns
        // the highest power to the first column: column 0 gets α^{W−1}, column W-1
        // gets α⁰. To match this with an explicit dot-product (needed for the LDE
        // evaluation), we need coefficient[i] = −α^{W−1−i}.
        //
        // Construction:
        //   shifted_powers(NEG_ONE) produces [−1, −α, −α², …, −α^{W−1}]
        //   .rev() reverses to [−α^{W−1}, …, −α, −1]
        //   Split into per-matrix chunks in commitment order.
        //
        // The negation is folded into the coefficients so the DEEP quotient loop can
        // compute f_reduced(zⱼ) + neg_f_reduced(X) = f_reduced(zⱼ) − f_reduced(X)
        // without a separate negation pass.
        let total_width: usize = aligned_widths.iter().sum();
        let mut neg_powers_iter = challenge_columns
            .shifted_powers(EF::NEG_ONE)
            .collect_n(total_width)
            .into_iter()
            .rev();
        let neg_column_coeffs: Vec<Vec<EF>> = aligned_widths
            .iter()
            .map(|&width| neg_powers_iter.by_ref().take(width).collect())
            .collect();

        // Compute -f_reduced(X) = -Σᵢ α^{W−1−i}·fᵢ(X) over the LDE domain, then
        // transform in-place into the DEEP quotient:
        //   Q(X) = Σⱼ βʲ·(f_reduced(zⱼ) − f_reduced(X))·1/(zⱼ − X)
        //
        // The column reduction and quotient assembly are fused: the `neg_f_reduced`
        // vector is consumed in-place to produce `deep_evals`, avoiding a separate
        // full-domain allocation and improving cache locality.

        let deep_evals = info_span!("DEEP reduce + assemble").in_scope(|| {
            let mut neg_column_coeffs_iter = neg_column_coeffs.iter();
            let mut neg_f_reduced = zip(matrices_groups.iter(), &group_sizes)
                .map(|(matrices_group, &size)| {
                    let group_coeffs: Vec<&Vec<EF>> =
                        neg_column_coeffs_iter.by_ref().take(size).collect();
                    accumulate_matrices(matrices_group, &group_coeffs)
                })
                .reduce(|mut acc, next| {
                    debug_assert_eq!(acc.len(), next.len());
                    acc.par_chunks_mut(w).zip(next.par_chunks(w)).for_each(
                        |(acc_chunk, next_chunk)| {
                            EF::add_slices(acc_chunk, next_chunk);
                        },
                    );
                    acc
                })
                .unwrap_or_else(|| EF::zero_vec(n));

            // Pre-compute βʲ for all N points
            let point_coeffs: [EF; N] =
                core::array::from_fn(|j| challenge_points.exp_u64(j as u64));

            // Transform neg_f_reduced in-place into deep_evals.
            // Q(x) = Σⱼ βʲ·qⱼ(x)·(f_reduced(zⱼ) + neg_f_reduced(x))
            if w == 1 || n < w {
                neg_f_reduced
                    .par_iter_mut()
                    .zip(point_quotient.par_iter())
                    .for_each(|(neg, q)| {
                        let mut result = q[0] * (f_reduced_at_points[0] + *neg);
                        for j in 1..N {
                            result += point_coeffs[j] * q[j] * (f_reduced_at_points[j] + *neg);
                        }
                        *neg = result;
                    });
            } else {
                let f_reduced_packed: [EF::ExtensionPacking; N] =
                    f_reduced_at_points.0.map(EF::ExtensionPacking::from);
                let point_coeffs_packed: [EF::ExtensionPacking; N] =
                    point_coeffs.map(EF::ExtensionPacking::from);

                neg_f_reduced
                    .par_chunks_exact_mut(w)
                    .zip(point_quotient.par_chunks_exact(w))
                    .for_each(|(neg_chunk, q_chunk)| {
                        let neg_p = EF::ExtensionPacking::from_ext_slice(neg_chunk);

                        // Transpose quotients: q_chunk[lane][point] -> q_packed[point] packs all
                        // lanes
                        let q_packed: [EF::ExtensionPacking; N] =
                            EF::ExtensionPacking::pack_ext_columns(FieldArray::as_raw_slice(
                                q_chunk,
                            ));

                        // First point (j=0) has coefficient β⁰ = 1, compute directly
                        let mut result_p = q_packed[0] * (f_reduced_packed[0] + neg_p);

                        // Remaining points (j>0) multiply by βʲ
                        for j in 1..N {
                            result_p += point_coeffs_packed[j]
                                * q_packed[j]
                                * (f_reduced_packed[j] + neg_p);
                        }
                        result_p.to_ext_slice(neg_chunk);
                    });
            }

            neg_f_reduced // now contains deep_evals
        });

        (Self { deep_evals }, batched_evals)
    }
}

/// Accumulate `f_reduced(X) = Σᵢ α^{W−1−i}·fᵢ(X)` across matrices of varying heights.
///
/// In bit-reversed order, the lifted polynomial `f(Xʳ)` repeats each evaluation r times
/// (because adjacent bit-reversed indices differ only in their low bits, mapping to points
/// that are r-th roots of the same value). This lets us upsample by repetition instead of
/// recomputing the lifted polynomial: when crossing a height boundary, repeat entries to
/// match the new height, then continue accumulating. Matrices must be sorted by ascending
/// height.
fn accumulate_matrices<F: Field, EF: ExtensionField<F>, M: Matrix<F>, C: AsRef<[EF]>>(
    matrices: &[&M],
    coeffs: &[C],
) -> Vec<EF> {
    debug_assert!(
        matrices.windows(2).all(|w| w[0].height() <= w[1].height()),
        "matrices must be sorted by ascending height"
    );
    let n = matrices.last().unwrap().height();

    let mut acc = EF::zero_vec(n);
    let mut scratch = EF::zero_vec(n);

    let mut active_height = matrices.first().unwrap().height();

    for (&matrix, coeffs) in zip(matrices, coeffs) {
        let coeffs = coeffs.as_ref();
        let height = matrix.height();
        debug_assert!(height.is_power_of_two(), "matrix height must be a power of two");
        debug_assert!(
            matrix.width() <= coeffs.len(),
            "matrix width {} exceeds coeffs length {}",
            matrix.width(),
            coeffs.len()
        );

        // Upsample: [a, b] → [a, a, b, b] when height doubles
        if height > active_height {
            let scaling_factor = height / active_height;
            scratch[..height]
                .par_chunks_mut(scaling_factor)
                .zip(acc[..active_height].par_iter())
                .for_each(|(chunk, &val)| chunk.fill(val));
            acc[..height].swap_with_slice(&mut scratch[..height]);
        }

        // SIMD path using horizontal packing.
        // Slice to matrix width to avoid packing alignment-padding coefficients.
        let w = F::Packing::WIDTH;
        let active_coeffs = &coeffs[..matrix.width()];
        let packed_coeffs: Vec<EF::ExtensionPacking> = active_coeffs
            .chunks(w)
            .map(|chunk| {
                if chunk.len() == w {
                    EF::ExtensionPacking::from_ext_slice(chunk)
                } else {
                    // Pad with zeros for the last chunk
                    let mut padded = EF::zero_vec(w);
                    padded[..chunk.len()].copy_from_slice(chunk);
                    EF::ExtensionPacking::from_ext_slice(&padded)
                }
            })
            .collect();

        matrix
            .rowwise_packed_dot_product::<EF>(&packed_coeffs)
            .zip(acc[..height].par_iter_mut())
            .for_each(|(dot_result, acc_val)| {
                *acc_val += dot_result;
            });

        active_height = height;
    }

    acc
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_field::{PrimeCharacteristicRing, dot_product};

    use super::*;
    use crate::testing::configs::goldilocks_poseidon2::{Felt, QuadFelt};

    /// `reduce_with_powers` (Horner) must match explicit negative coeffs + dot product.
    #[test]
    fn neg_coeffs_match_neg_horner() {
        let c: QuadFelt = QuadFelt::from_u64(2);
        let alignment = 3;
        let widths = [2usize, 3];
        let aligned_widths = aligned_widths(widths.to_vec(), alignment);
        let rows: Vec<Vec<Felt>> = vec![
            vec![Felt::from_u64(1), Felt::from_u64(2)],
            vec![Felt::from_u64(3), Felt::from_u64(4), Felt::from_u64(5)],
        ];
        let padded = RowList::from_rows_aligned(&rows, alignment);

        let mut neg_powers_iter = c
            .shifted_powers(QuadFelt::NEG_ONE)
            .collect_n(aligned_widths.iter().sum())
            .into_iter()
            .rev();
        let neg_coeffs: Vec<Vec<QuadFelt>> = aligned_widths
            .iter()
            .map(|&width| neg_powers_iter.by_ref().take(width).collect())
            .collect();

        // Explicit coefficient sum: Σᵢ coeffs[i] · rows[i]
        let explicit: QuadFelt =
            dot_product(neg_coeffs.iter().flatten().copied(), padded.iter_values());

        // Horner using reduce_with_powers (same as used in verifier)
        let horner: QuadFelt = horner(c, padded.iter_values());

        assert_eq!(explicit, QuadFelt::NEG_ONE * horner);
    }

    /// Padding: negative coeffs match -Horner for various width/alignment combos.
    #[test]
    fn neg_coeffs_alignment() {
        let c: QuadFelt = QuadFelt::from_u64(7);
        let alignment = 4;
        let widths = [3usize, 5, 2];
        let aligned_widths = aligned_widths(widths.to_vec(), alignment);

        let mut neg_powers_iter = c
            .shifted_powers(QuadFelt::NEG_ONE)
            .collect_n(aligned_widths.iter().sum())
            .into_iter()
            .rev();
        let coeffs: Vec<Vec<QuadFelt>> = aligned_widths
            .iter()
            .map(|&width| neg_powers_iter.by_ref().take(width).collect())
            .collect();

        // Verify lengths match aligned widths
        assert_eq!(coeffs[0].len(), aligned_widths[0]);
        assert_eq!(coeffs[1].len(), aligned_widths[1]);
        assert_eq!(coeffs[2].len(), aligned_widths[2]);

        // Verify this matches Horner reduction with arbitrary test data
        let rows: Vec<Vec<Felt>> = vec![
            vec![Felt::from_u64(10), Felt::from_u64(20), Felt::from_u64(30)],
            vec![
                Felt::from_u64(1),
                Felt::from_u64(2),
                Felt::from_u64(3),
                Felt::from_u64(4),
                Felt::from_u64(5),
            ],
            vec![Felt::from_u64(100), Felt::from_u64(200)],
        ];
        let padded = RowList::from_rows_aligned(&rows, alignment);

        let explicit: QuadFelt =
            dot_product(coeffs.iter().flatten().copied(), padded.iter_values());
        let horner: QuadFelt = horner(c, padded.iter_values());

        assert_eq!(explicit, QuadFelt::NEG_ONE * horner);
    }
}
