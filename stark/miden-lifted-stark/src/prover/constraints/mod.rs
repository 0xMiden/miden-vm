//! Constraint evaluation for the prover.
//!
//! - `evaluate_constraints_into`: SIMD-parallel constraint evaluation on the quotient domain
//! - `folder`: SIMD-optimized constraint folder and finalization
//! - `layout`: Constraint layout discovery (base vs extension) and alpha decomposition

mod folder;
pub(crate) mod layout;
mod packed_row_bitrev;

use alloc::vec::Vec;
use core::marker::PhantomData;

use folder::ProverConstraintFolder;
use miden_lifted_air::{LiftedAir, RowWindow, symbolic::ConstraintLayout};
use p3_field::{
    Algebra, BasedVectorSpace, ExtensionField, Field, PackedFieldExtension, PackedValue,
    TwoAdicField,
};
use p3_matrix::{Matrix, bitrev::BitReversedMatrixView, dense::RowMajorMatrixView};
#[cfg(feature = "concurrent")]
use p3_maybe_rayon::prelude::*;
use packed_row_bitrev::collect_vertically_packed_row_pair_bitrev_into;

use crate::{
    domain::{Coset, EvaluationDomain},
    prover::periodic::PeriodicLde,
};

/// Row-blocks (`i_start = r * packing_width`) processed per rayon task.
const ROW_BLOCKS_PER_PARALLEL_TASK: usize = 32;

/// Type alias for packed base field from F.
type PackedVal<F> = <F as Field>::Packing;

/// Type alias for packed extension field from EF.
type PackedExt<F, EF> = <EF as ExtensionField<F>>::ExtensionPacking;

/// Evaluate an AIR's constraints on its native quotient coset and write the
/// per-AIR quotient evaluations (constraint numerator divided by `Z_{H_j}`)
/// into `output`.
///
/// `coset` is the AIR's native quotient evaluation coset `gJ_j` of size `n_j * D_j`,
/// where `n_j` is the AIR's trace height and `D_j = 2^log_quotient_degree` is its
/// per-AIR constraint-degree bound. For each point on `gJ_j` we evaluate every
/// constraint, fold with powers of `alpha`, multiply by the precomputed `1 / Z_H`
/// value, and write the result:
///
/// `output[i] = folded_constraints(x_i) / Z_{H_j}(x_i)`.
///
/// `inv_z_h` is a length-`D_j` slice: `Z_{H_j}(x)` takes only `D_j` distinct
/// values over `gJ_j` by periodicity, so batch-inverting them once suffices
/// (use [`crate::domain::EvaluationDomain::inv_vanishing_evals`]). Fusing the
/// divide into the write loop saves a second pass over the `n_j · D_j`-point
/// output buffer.
///
/// `output` must be a fresh zero-initialized buffer of length `n_j * D_j`; each
/// point is written once. Upsampling to the batch-wide target and beta-accumulation
/// into the shared quotient accumulator happen in the caller.
///
/// Trace views must be [`BitReversedMatrixView`] over dense row-major storage (as
/// returned by [`crate::prover::commit::Committed::evals_on_quotient_domain`]), in
/// natural order on `gJ_j`.
///
/// Uses SIMD-packed parallel iteration via rayon for optimal performance:
/// - Processes `WIDTH` points simultaneously using packed field types
/// - Main trace stays in base field, only aux trace uses extension field
/// - Constraints are collected then finalized in batches via decomposed alpha powers
///
/// Why we fold with `alpha`: the prover does not want to carry K separate constraint
/// polynomials through the rest of the protocol. A random linear combination
///
/// `C_fold(x) = Σₖ α^{K−1−k}·Cₖ(x)`
///
/// collapses them into one numerator polynomial while preserving soundness (a non-zero
/// constraint survives with high probability).
///
/// Why we evaluate on the native coset: the quotient `Q_j = C_j / Z_{H_j}` has degree
/// `< n_j * D_j` by construction, so `n_j * D_j` evaluation points suffice to determine
/// it. The committed LDE coset (size `n_j * B`, with `B >= D_j`) contains `gJ_j` as a
/// subset, so the truncated view the caller passes in is zero-copy.
#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_constraints_into<F, EF, A>(
    output: &mut [EF],
    air: &A,
    main_on_gj: &BitReversedMatrixView<RowMajorMatrixView<'_, F>>,
    preprocessed_on_gj: Option<&BitReversedMatrixView<RowMajorMatrixView<'_, F>>>,
    aux_on_gj: &BitReversedMatrixView<RowMajorMatrixView<'_, F>>,
    eval_domain: &EvaluationDomain<F>,
    alpha: EF,
    randomness: &[EF],
    public_values: &[F],
    periodic_lde: &PeriodicLde<F>,
    layout: &ConstraintLayout,
    permutation_values: &[EF],
    inv_z_h: &[F],
) where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    PackedExt<F, EF>: Algebra<EF> + Algebra<PackedVal<F>> + BasedVectorSpace<PackedVal<F>>,
    A: LiftedAir<F, EF>,
{
    type P<F> = PackedVal<F>;
    type PE<F, EF> = PackedExt<F, EF>;

    let quotient_degree = eval_domain.quotient_degree();
    let gj_height = eval_domain.size();
    assert_eq!(output.len(), gj_height);
    let width = P::<F>::WIDTH;

    assert_eq!(gj_height % width, 0, "quotient height must be divisible by packing width");
    assert_eq!(inv_z_h.len(), quotient_degree, "inv_z_h length must equal D_j");
    // Bitmask for `i % inv_z_h.len()`; len is `2^log_blowup` by construction.
    let inv_z_h_mask: usize = inv_z_h.len() - 1;

    // Precompute selectors over the quotient evaluation coset.
    let sels = eval_domain.selectors();

    // ─── Decompose alpha powers by constraint layout ───
    let aux_ef_width = air.aux_width();
    let constraint_count = layout.total_constraints();
    let base_count = layout.base_indices.len();
    let ext_count = layout.ext_indices.len();
    let (base_alpha_powers, ext_alpha_powers) = layout.decompose_alpha(alpha);

    // Main trace width
    let main_width = main_on_gj.width();
    // Preprocessed trace view, constructed only when the AIR declares one.
    let preproc_trace_view = preprocessed_on_gj.map(|m| {
        let w = m.width();
        RowMajorMatrixView::new(m.inner.values, w)
    });
    let preprocessed_width = preproc_trace_view.as_ref().map_or(0, Matrix::width);

    // Pack randomness for aux trace
    let packed_randomness: Vec<PE<F, EF>> = randomness.iter().copied().map(Into::into).collect();

    // Pack permutation values
    let packed_perm_values: Vec<PE<F, EF>> =
        permutation_values.iter().copied().map(Into::into).collect();

    let main_vals = main_on_gj.inner.values;
    let aux_vals = aux_on_gj.inner.values;
    let aux_scalar_width = aux_on_gj.width();
    let main_trace_view = RowMajorMatrixView::new(main_vals, main_width);
    let aux_trace_view = RowMajorMatrixView::new(aux_vals, aux_scalar_width);

    let points_per_task = width * ROW_BLOCKS_PER_PARALLEL_TASK;

    let eval_big_slice = |main_buf: &mut Vec<P<F>>,
                          preproc_buf: &mut Vec<P<F>>,
                          aux_base_buf: &mut Vec<P<F>>,
                          aux_pe_buf: &mut Vec<PE<F, EF>>,
                          g: usize,
                          big_slice: &mut [EF]| {
        for (sub_r, chunk) in big_slice.chunks_exact_mut(width).enumerate() {
            let r = g * ROW_BLOCKS_PER_PARALLEL_TASK + sub_r;
            let i_start = r * width;

            // Extract packed selectors from precomputed vectors
            let selectors = sels.packed_at::<P<F>>(i_start);

            // Get main trace as packed row pair (stays in base field)
            collect_vertically_packed_row_pair_bitrev_into::<F, P<F>>(
                &main_trace_view,
                i_start,
                quotient_degree,
                main_buf,
            );
            let main_mat = RowMajorMatrixView::new(main_buf.as_slice(), main_width);

            // Get preprocessed trace as packed row pair (when present). For AIRs
            // without preprocessed columns, the window is empty and the AIR must
            // not call `builder.preprocessed()`.
            let preprocessed = if let Some(view) = preproc_trace_view.as_ref() {
                collect_vertically_packed_row_pair_bitrev_into::<F, P<F>>(
                    view,
                    i_start,
                    quotient_degree,
                    preproc_buf,
                );
                let m = RowMajorMatrixView::new(preproc_buf.as_slice(), preprocessed_width);
                RowWindow::from_view(&m)
            } else {
                let empty: &[P<F>] = &[];
                RowWindow::from_two_rows(empty, empty)
            };

            // Get aux trace as packed row pair and convert to packed extension field
            collect_vertically_packed_row_pair_bitrev_into::<F, P<F>>(
                &aux_trace_view,
                i_start,
                quotient_degree,
                aux_base_buf,
            );

            // Convert from packed base field to packed extension field
            // Each EF element is formed from DIMENSION consecutive base field elements
            aux_pe_buf.clear();
            aux_pe_buf.reserve(aux_ef_width * 2);
            for i in 0..aux_ef_width * 2 {
                aux_pe_buf.push(PE::<F, EF>::from_basis_coefficients_fn(|j| {
                    aux_base_buf[i * EF::DIMENSION + j]
                }));
            }
            let aux_mat = RowMajorMatrixView::new(aux_pe_buf.as_slice(), aux_ef_width);

            // Get packed periodic values
            let periodic_values: Vec<P<F>> = periodic_lde.packed_values_at(i_start).collect();

            // Build packed folder and evaluate constraints
            let mut folder: ProverConstraintFolder<'_, F, EF, P<F>, PE<F, EF>> =
                ProverConstraintFolder {
                    main: RowWindow::from_view(&main_mat),
                    preprocessed,
                    aux: RowWindow::from_view(&aux_mat),
                    packed_randomness: &packed_randomness,
                    public_values,
                    periodic_values: &periodic_values,
                    permutation_values: &packed_perm_values,
                    selectors,
                    base_alpha_powers: &base_alpha_powers,
                    ext_alpha_powers: &ext_alpha_powers,
                    constraint_index: 0,
                    constraint_count,
                    base_constraints: Vec::with_capacity(base_count),
                    ext_constraints: Vec::with_capacity(ext_count),
                    _phantom: PhantomData,
                };

            #[cfg(debug_assertions)]
            miden_lifted_air::debug::check_builder_shape(air, &folder);
            air.eval(&mut folder);
            let folded = folder.finalize_constraints();

            // Unpack the folded result, multiply by 1/Z_H (modular indexing since Z_H
            // takes only D_j distinct values on gJ_j), and write into the output chunk.
            for (k, (slot, val)) in
                chunk.iter_mut().zip(PE::<F, EF>::to_ext_iter([folded])).enumerate()
            {
                *slot = val * inv_z_h[(i_start + k) & inv_z_h_mask];
            }
        }
    };

    #[cfg(feature = "concurrent")]
    output.par_chunks_mut(points_per_task).enumerate().for_each_init(
        || {
            (
                Vec::<P<F>>::new(),
                Vec::<P<F>>::new(),
                Vec::<P<F>>::new(),
                Vec::<PE<F, EF>>::new(),
            )
        },
        |(main_buf, preproc_buf, aux_base_buf, aux_pe_buf), (g, big_slice)| {
            eval_big_slice(main_buf, preproc_buf, aux_base_buf, aux_pe_buf, g, big_slice);
        },
    );

    #[cfg(not(feature = "concurrent"))]
    {
        let mut main_buf = Vec::<P<F>>::new();
        let mut preproc_buf = Vec::<P<F>>::new();
        let mut aux_base_buf = Vec::<P<F>>::new();
        let mut aux_pe_buf = Vec::<PE<F, EF>>::new();
        output.chunks_mut(points_per_task).enumerate().for_each(|(g, big_slice)| {
            eval_big_slice(
                &mut main_buf,
                &mut preproc_buf,
                &mut aux_base_buf,
                &mut aux_pe_buf,
                g,
                big_slice,
            );
        });
    }
}
