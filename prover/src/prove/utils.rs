// Common helper functions for the prover will live here

use std::{vec, vec::Vec};

use miden_air::{
    Air, Felt,
    trace::{AUX_TRACE_WIDTH, ColMatrix, TRACE_WIDTH},
};
use miden_processor::{ExecutionTrace, ZERO};
use p3_commit::PolynomialSpace;
use p3_field::{BasedVectorSpace, ExtensionField, PackedValue, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_maybe_rayon::prelude::*;
use p3_uni_stark::{Domain, PackedChallenge, PackedVal, StarkGenericConfig, Val};
use p3_util::log2_strict_usize;
use tracing::{debug_span, instrument};

use crate::prove::ProverConstraintFolder;

#[instrument("naive transposition", skip_all)]
pub fn to_row_major(trace: &ExecutionTrace) -> RowMajorMatrix<Felt> {
    let mut result: RowMajorMatrix<Felt> =
        RowMajorMatrix::new(vec![ZERO; TRACE_WIDTH * trace.get_trace_len()], TRACE_WIDTH);
    result.rows_mut().enumerate().for_each(|(row_idx, row)| {
        for col_idx in 0..TRACE_WIDTH {
            row[col_idx] = trace.main_trace.get(col_idx, row_idx)
        }
    });

    result
}

#[instrument("naive transposition", skip_all)]
pub fn to_row_major_aux<E>(trace: &ColMatrix<E>) -> RowMajorMatrix<E>
where
    E: ExtensionField<Felt>,
{
    let mut result: RowMajorMatrix<E> =
        RowMajorMatrix::new(vec![E::ZERO; AUX_TRACE_WIDTH * trace.num_rows()], AUX_TRACE_WIDTH);
    result.rows_mut().enumerate().for_each(|(row_idx, row)| {
        for col_idx in 0..AUX_TRACE_WIDTH {
            row[col_idx] = trace.get(col_idx, row_idx)
        }
    });

    result
}

#[instrument(name = "compute quotient polynomial", skip_all)]
pub fn quotient_values<SC, A, Mat>(
    air: &A,
    public_values: &Vec<Val<SC>>,
    trace_domain: Domain<SC>,
    quotient_domain: Domain<SC>,
    trace_on_quotient_domain: Mat,
    alpha: SC::Challenge,
    constraint_count: usize,
) -> Vec<SC::Challenge>
where
    SC: StarkGenericConfig,
    A: for<'a> Air<ProverConstraintFolder<'a, SC>>,
    Mat: Matrix<Val<SC>> + Sync,
{
    let quotient_size = quotient_domain.size();
    let width = trace_on_quotient_domain.width();
    let mut sels = debug_span!("Compute Selectors")
        .in_scope(|| trace_domain.selectors_on_coset(quotient_domain));

    let qdb = log2_strict_usize(quotient_domain.size()) - log2_strict_usize(trace_domain.size());
    let next_step = 1 << qdb;

    for _ in quotient_size..PackedVal::<SC>::WIDTH {
        sels.is_first_row.push(Val::<SC>::default());
        sels.is_last_row.push(Val::<SC>::default());
        sels.is_transition.push(Val::<SC>::default());
        sels.inv_vanishing.push(Val::<SC>::default());
    }

    let mut alpha_powers: Vec<_> = alpha.powers().take(constraint_count).collect();
    alpha_powers.reverse();
    let decomposed_alpha_powers: Vec<_> = (0..SC::Challenge::WIDTH)
        .map(|i| alpha_powers.iter().map(|x| x.as_basis_coefficients_slice()[i]).collect())
        .collect();

    (0..quotient_size)
        .into_par_iter()
        .step_by(PackedVal::<SC>::WIDTH)
        .flat_map_iter(|i_start| {
            let i_range = i_start..i_start + PackedVal::<SC>::WIDTH;

            let is_first_row = *PackedVal::<SC>::from_slice(&sels.is_first_row[i_range.clone()]);
            let is_last_row = *PackedVal::<SC>::from_slice(&sels.is_last_row[i_range.clone()]);
            let is_transition = *PackedVal::<SC>::from_slice(&sels.is_transition[i_range.clone()]);
            let inv_vanishing = *PackedVal::<SC>::from_slice(&sels.inv_vanishing[i_range]);

            let main = RowMajorMatrix::new(
                trace_on_quotient_domain.vertically_packed_row_pair(i_start, next_step),
                width,
            );

            let accumulator = PackedChallenge::<SC>::ZERO;
            let mut folder = ProverConstraintFolder {
                main: main.as_view(),
                public_values,
                is_first_row,
                is_last_row,
                is_transition,
                alpha_powers: &alpha_powers,
                decomposed_alpha_powers: &decomposed_alpha_powers,
                accumulator,
                constraint_index: 0,
            };
            air.eval(&mut folder);

            let quotient = folder.accumulator * inv_vanishing;

            (0..core::cmp::min(quotient_size, PackedVal::<SC>::WIDTH)).map(move |idx_in_packing| {
                SC::Challenge::from_basis_coefficients_fn(|coeff_idx| {
                    quotient.as_basis_coefficients_slice()[coeff_idx].as_slice()[idx_in_packing]
                })
            })
        })
        .collect()
}
