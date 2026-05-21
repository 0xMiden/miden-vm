//! Prover-side periodic column handling.
//!
//! Periodic columns are stored as LDE values in a row-major matrix for efficient
//! constraint evaluation on the LDE domain. The key optimization is that a periodic
//! column with period `p` only needs `p * blowup` LDE values (not `trace_height * blowup`),
//! which are accessed via modular indexing.
//!
//! Uses NaiveDft since periodic column periods are typically small.

use miden_lifted_air::log2_strict_u8;
use p3_dft::{NaiveDft, TwoAdicSubgroupDft};
use p3_field::{PackedValue, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::domain::{Coset, EvaluationDomain};

/// Prover-side periodic LDE values for constraint evaluation.
///
/// Stores precomputed LDE values as a row-major matrix in natural order. The key insight
/// is that by repeating each column's values to the maximum period, we can use batch DFT
/// methods and store only `max_period * blowup` rows instead of `trace_height * blowup`.
///
/// A periodic column of period `p` repeats every `p` rows on the trace domain, so its LDE
/// repeats every `p * blowup` rows on the quotient/LDE domains. We therefore only need to
/// store `p * blowup` rows for that column. To share one buffer across many periodic columns,
/// we repeat each column up to `max_period` and LDE-extend once; columns with smaller periods
/// are accessed via modular indexing.
#[derive(Clone, Debug)]
pub(super) struct PeriodicLde<F: TwoAdicField> {
    /// LDE values in natural order (height = max_period * blowup).
    /// `None` when there are no periodic columns.
    ldes: Option<RowMajorMatrix<F>>,
}

impl<F: TwoAdicField> PeriodicLde<F> {
    /// Build periodic LDEs from a periodic column matrix.
    ///
    /// Takes the output of [`crate::air::LiftedAir::periodic_columns_matrix`], where
    /// columns with smaller periods have been repeated cyclically to the maximum period.
    /// Uses NaiveDft since periodic column periods are typically small.
    ///
    /// # Arguments
    /// - `domain`: The evaluation domain (trace + LDE + constraint degree)
    /// - `repeated_matrix`: Periodic columns extended to a common height (max period), or `None` if
    ///   there are no periodic columns
    ///
    /// # Panics
    /// Panics if the matrix height exceeds the trace height or is not a power of two.
    pub fn build(domain: &EvaluationDomain<F>, repeated_matrix: Option<RowMajorMatrix<F>>) -> Self {
        let Some(repeated_matrix) = repeated_matrix else {
            return Self { ldes: None };
        };

        let max_period = repeated_matrix.height();
        let log_max_period = log2_strict_u8(max_period);
        assert!(
            domain.log_trace_height() >= log_max_period,
            "periodic column period ({max_period}) exceeds trace height ({})",
            1 << domain.log_trace_height() as usize,
        );
        let log_blowup = domain.log_quotient_degree() as usize;

        // Compute the coset shift for the max-period subgroup.
        //
        // Periodic polynomials are naturally defined on a subgroup of order `max_period`.
        // The quotient evaluation coset shares the LDE coset's shift; map it down
        // from trace height to `max_period` via a power-of-two ratio.
        let log_ratio = domain.log_trace_height() - log_max_period;
        let period_shift: F = domain.shift().exp_power_of_2(log_ratio as usize);

        // Compute LDE using NaiveDft (periods are small)
        let ldes = NaiveDft
            .coset_lde_batch(repeated_matrix, log_blowup, period_shift)
            .to_row_major_matrix();

        Self { ldes: Some(ldes) }
    }

    /// Get packed values for consecutive natural indices [i, i+1, ..., i+WIDTH-1].
    ///
    /// Returns an empty iterator when there are no periodic columns.
    #[inline]
    pub fn packed_values_at<P: PackedValue<Value = F>>(
        &self,
        i: usize,
    ) -> impl Iterator<Item = P> + '_ {
        self.ldes.iter().flat_map(move |ldes| {
            let height = ldes.height();
            (0..ldes.width()).map(move |col| {
                P::from_fn(|k| {
                    let row = (i + k) % height;
                    // SAFETY: `row < height` is guaranteed by the modulo operation,
                    // and `col < width` is guaranteed by the iterator bounds (0..ldes.width()).
                    unsafe { ldes.get_unchecked(row, col) }
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{vec, vec::Vec};

    use p3_dft::TwoAdicSubgroupDft;
    use p3_field::{PackedValue, PrimeCharacteristicRing};

    use super::*;
    use crate::{
        domain::LiftedDomain,
        testing::{canonical_domain, configs::goldilocks_poseidon2 as gl},
    };

    /// Verify that periodic LDE values match the full LDE computation.
    fn assert_periodic_lde_matches_full(
        columns: &[Vec<gl::Felt>],
        log_trace_height: u8,
        log_blowup: u8,
    ) {
        let trace_height = 1 << log_trace_height as usize;
        let lde_height = trace_height << log_blowup as usize;

        // Create an evaluation domain at max height (no lifting), with constraint
        // degree = log_blowup (the max-degree case for this test).
        let lifted: LiftedDomain<gl::Felt> = canonical_domain(log_trace_height, log_blowup);
        let domain = lifted.evaluation_domain(log_blowup);

        // Build the repeated matrix (same logic as periodic_columns_matrix)
        let max_period = columns.iter().map(Vec::len).max().unwrap();
        let num_cols = columns.len();
        let mut values = Vec::with_capacity(max_period * num_cols);
        for row in 0..max_period {
            for col in columns {
                values.push(col[row % col.len()]);
            }
        }
        let repeated_matrix = RowMajorMatrix::new(values, num_cols);

        let periodic_lde = PeriodicLde::build(&domain, Some(repeated_matrix));

        // Compute expected LDE for each column via full expansion (natural order).
        // The PeriodicLde uses `domain.lde_shift()` internally — match it here.
        let expected_shift = domain.shift();
        let expected: Vec<Vec<gl::Felt>> = columns
            .iter()
            .map(|col| {
                let full: Vec<gl::Felt> = (0..trace_height).map(|i| col[i % col.len()]).collect();
                let matrix = RowMajorMatrix::new(full, 1);
                NaiveDft
                    .coset_lde_batch(matrix, log_blowup.into(), expected_shift)
                    .to_row_major_matrix()
                    .values
            })
            .collect();

        // Verify all LDE rows match (natural indices)
        let ldes = periodic_lde.ldes.as_ref().expect("expected Some for non-empty columns");
        let height = ldes.height();
        for i in 0..lde_height {
            let row = i % height;
            let actual: Vec<gl::Felt> = ldes.row_slice(row).unwrap().to_vec();
            for (col_idx, (&actual_val, expected_col)) in actual.iter().zip(&expected).enumerate() {
                assert_eq!(actual_val, expected_col[i], "col {col_idx} mismatch at row {i}");
            }
        }

        // Verify packed_values_at returns correct packed values
        type P = gl::PackedFelt;
        let pack_width = P::WIDTH;
        for start in (0..lde_height).step_by(pack_width) {
            let packed: Vec<P> = periodic_lde.packed_values_at(start).collect();
            assert_eq!(packed.len(), columns.len());

            // Verify each lane matches scalar access
            for k in 0..pack_width {
                let idx = start + k;
                let row = idx % height;
                let scalar: Vec<gl::Felt> = ldes.row_slice(row).unwrap().to_vec();
                for (col_idx, (&packed_val, &scalar_val)) in packed.iter().zip(&scalar).enumerate()
                {
                    assert_eq!(
                        packed_val.as_slice()[k],
                        scalar_val,
                        "packed mismatch col {col_idx} row {idx} lane {k}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_periodic_lde_matches_full_lde() {
        // Period 2, blowup 2
        assert_periodic_lde_matches_full(&[vec![gl::Felt::ZERO, gl::Felt::ONE]], 3, 1);

        // Period 4, blowup 2
        let col4: Vec<gl::Felt> = [1, 2, 3, 4].into_iter().map(gl::Felt::from_u64).collect();
        assert_periodic_lde_matches_full(&[col4], 3, 1);

        // Period 2, blowup 8 (higher blowup)
        let col2: Vec<gl::Felt> = [5, 7].into_iter().map(gl::Felt::from_u64).collect();
        assert_periodic_lde_matches_full(&[col2], 4, 3);

        // Multiple columns with different periods
        let col_p2: Vec<gl::Felt> = [1, 2].into_iter().map(gl::Felt::from_u64).collect();
        let col_p4: Vec<gl::Felt> = [10, 20, 30, 40].into_iter().map(gl::Felt::from_u64).collect();
        assert_periodic_lde_matches_full(&[col_p2, col_p4], 3, 2);
    }
}
