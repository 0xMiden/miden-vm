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
#[cfg(feature = "parallel")]
use p3_maybe_rayon::prelude::*;
use packed_row_bitrev::RowMajorMatrixBitrevPackedExt;

use crate::{coset::LiftedCoset, prover::periodic::PeriodicLde};

/// Row-blocks (`i_start = r * packing_width`) processed per rayon task.
const ROW_BLOCKS_PER_PARALLEL_TASK: usize = 32;

/// Type alias for packed base field from F.
type PackedVal<F> = <F as Field>::Packing;

/// Type alias for packed extension field from EF.
type PackedExt<F, EF> = <EF as ExtensionField<F>>::ExtensionPacking;

/// Evaluate constraints on the quotient domain, adding results into `output`.
///
/// Here `gJ` is the quotient evaluation coset of size `N * D`, the subset of the
/// committed LDE coset `gK` (size `N * B`) that contains just enough points to
/// evaluate the quotient point-wise. For each point on `gJ`, we evaluate all AIR
/// constraints, fold them with powers of `alpha`, and add the resulting numerator value:
///
/// `output[i] += folded_constraints(xᵢ)`.
///
/// The caller is responsible for preparing `output` before calling this function
/// (e.g. cyclically extending and scaling by beta for multi-trace accumulation).
/// Trace views must be [`BitReversedMatrixView`] over dense row-major storage (as returned by
/// [`crate::prover::commit::Committed::evals_on_quotient_domain`]), in natural order on gJ.
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
/// Why we only evaluate on `gJ`: `gJ` (size `N * D`) is a subset of the committed LDE
/// coset `gK` (size `N * B`). For `B >= D`, these `N * D` points are sufficient for
/// the quotient-degree bounds used by the protocol; division by the vanishing polynomial
/// happens later.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_constraints_into<F, EF, A>(
    output: &mut [EF],
    air: &A,
    main_on_gj: &BitReversedMatrixView<RowMajorMatrixView<'_, F>>,
    aux_on_gj: &BitReversedMatrixView<RowMajorMatrixView<'_, F>>,
    coset: &LiftedCoset,
    alpha: EF,
    randomness: &[EF],
    public_values: &[F],
    periodic_lde: &PeriodicLde<F>,
    layout: &ConstraintLayout,
    permutation_values: &[EF],
) where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    PackedExt<F, EF>: Algebra<EF> + Algebra<PackedVal<F>> + BasedVectorSpace<PackedVal<F>>,
    A: LiftedAir<F, EF>,
{
    type P<F> = PackedVal<F>;
    type PE<F, EF> = PackedExt<F, EF>;

    let gj_height = coset.lde_height();
    assert_eq!(output.len(), gj_height);
    let constraint_degree = coset.blowup();
    let width = P::<F>::WIDTH;

    assert_eq!(gj_height % width, 0, "quotient height must be divisible by packing width");

    // Precompute selectors via coset method
    let sels = coset.selectors::<F>();

    // ─── Decompose alpha powers by constraint layout ───
    let aux_ef_width = air.aux_width();
    let constraint_count = layout.total_constraints();
    let base_count = layout.base_indices.len();
    let ext_count = layout.ext_indices.len();
    let (base_alpha_powers, ext_alpha_powers) = layout.decompose_alpha(alpha);

    // Main trace width
    let main_width = main_on_gj.width();

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
            main_trace_view.collect_vertically_packed_row_pair_bitrev_into(
                i_start,
                constraint_degree,
                main_buf,
            );
            let main_mat = RowMajorMatrixView::new(main_buf.as_slice(), main_width);

            // Get aux trace as packed row pair and convert to packed extension field
            aux_trace_view.collect_vertically_packed_row_pair_bitrev_into(
                i_start,
                constraint_degree,
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
            air.is_valid_builder(&folder).expect("builder dimensions must match AIR");
            air.eval(&mut folder);
            let folded = folder.finalize_constraints();

            // Unpack folded result and add scalars directly into the output chunk.
            for (slot, val) in chunk.iter_mut().zip(PE::<F, EF>::to_ext_iter([folded])) {
                *slot += val;
            }
        }
    };

    #[cfg(feature = "parallel")]
    output.par_chunks_mut(points_per_task).enumerate().for_each_init(
        || (Vec::<P<F>>::new(), Vec::<P<F>>::new(), Vec::<PE<F, EF>>::new()),
        |(main_buf, aux_base_buf, aux_pe_buf), (g, big_slice)| {
            eval_big_slice(main_buf, aux_base_buf, aux_pe_buf, g, big_slice);
        },
    );

    #[cfg(not(feature = "parallel"))]
    {
        let mut main_buf = Vec::<P<F>>::new();
        let mut aux_base_buf = Vec::<P<F>>::new();
        let mut aux_pe_buf = Vec::<PE<F, EF>>::new();
        output.chunks_mut(points_per_task).enumerate().for_each(|(g, big_slice)| {
            eval_big_slice(&mut main_buf, &mut aux_base_buf, &mut aux_pe_buf, g, big_slice);
        });
    }
}
