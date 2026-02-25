//! Utilities for converting between row-major and column-major matrix formats.

use alloc::vec::Vec;

use miden_air::trace::MainTrace;
use tracing::instrument;

use crate::{
    Felt,
    field::{ExtensionField, PrimeCharacteristicRing},
    utils::{ColMatrix, Matrix, RowMajorMatrix},
};

/// Converts a row-major Felt matrix to column-major MainTrace format.
///
/// This extracts columns from the row-major matrix and packages them as a MainTrace
/// which is needed by the auxiliary trace builders in the processor crate.
///
/// Uses cache-blocked transposition to improve memory layout for better cache behavior
/// in downstream operations.
#[instrument(skip_all, fields(rows = matrix.height(), cols = matrix.width()))]
pub fn row_major_to_main_trace(matrix: &RowMajorMatrix<Felt>) -> MainTrace {
    let num_cols = matrix.width();
    let num_rows = matrix.height();

    // Use optimized cache-blocked transposition: row-major -> column-major
    let col_major_matrix = matrix.transpose();

    // Split the column-major data into individual column vectors
    let mut columns = Vec::with_capacity(num_cols);
    for col in col_major_matrix.values.chunks_exact(num_rows) {
        columns.push(col.to_vec())
    }

    let col_matrix = ColMatrix::new(columns);

    // Find the last program row by detecting where the clock stops incrementing
    let last_program_row = find_last_program_row(matrix);

    MainTrace::new(col_matrix, last_program_row.into())
}

/// Finds the last program row by detecting where the clock stops incrementing.
fn find_last_program_row(matrix: &RowMajorMatrix<Felt>) -> usize {
    let num_rows = matrix.height();

    // Clock is in column 0
    for row_idx in 1..num_rows {
        let prev_clk = matrix.get(row_idx - 1, 0).expect("valid indices");
        let curr_clk = matrix.get(row_idx, 0).expect("valid indices");

        // If clock didn't increment, we've found the end of the program
        if curr_clk != prev_clk + Felt::ONE {
            return row_idx - 1;
        }
    }

    // If we got here, the whole trace is program execution
    num_rows - 1
}

/// Converts auxiliary columns from column-major `Vec<Vec<EF>>` to a row-major
/// `RowMajorMatrix<EF>`.
#[instrument(skip_all, fields(num_cols = aux_columns.len(), trace_len))]
pub fn aux_columns_to_row_major<EF: ExtensionField<Felt>>(
    aux_columns: Vec<Vec<EF>>,
    trace_len: usize,
) -> RowMajorMatrix<EF> {
    if aux_columns.is_empty() {
        return RowMajorMatrix::new(Vec::new(), 0);
    }

    let num_ef_cols = aux_columns.len();

    // Flatten column-major data into a contiguous buffer for efficient transposition
    let mut col_major_ef_data = Vec::with_capacity(trace_len * num_ef_cols);
    for col in aux_columns {
        col_major_ef_data.extend_from_slice(&col);
    }

    // Use optimized cache-blocked transposition: column-major EF -> row-major EF
    RowMajorMatrix::new(col_major_ef_data, trace_len).transpose()
}
