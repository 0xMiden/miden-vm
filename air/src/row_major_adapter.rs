//! Utilities for converting between row-major and column-major matrix formats.

use alloc::vec::Vec;
use miden_core::{Felt, ExtensionField, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use crate::trace::{ColMatrix, main_trace::MainTrace};

/// Converts a row-major Felt matrix to column-major MainTrace format.
///
/// This extracts columns from the row-major matrix and packages them as a MainTrace
/// which is needed by the auxiliary trace builders in the processor crate.
pub fn row_major_to_main_trace(matrix: &RowMajorMatrix<Felt>) -> MainTrace {
    let num_cols = matrix.width();
    let num_rows = matrix.height();

    let mut columns = Vec::with_capacity(num_cols);
    for col_idx in 0..num_cols {
        let mut column = Vec::with_capacity(num_rows);
        for row_idx in 0..num_rows {
            column.push(matrix.get(row_idx, col_idx).expect("valid indices"));
        }
        columns.push(column);
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

/// Converts column-major extension field columns to row-major base field matrix.
///
/// This function performs two operations:
/// 1. Transposes from column-major to row-major layout
/// 2. Flattens extension field elements to base field representation
///
/// The input is a vector of EF columns (each column is a Vec<EF>).
/// The output is a row-major matrix where each EF element is expanded to its base field coefficients.
///
/// For example, with 2 EF columns and 3 rows:
/// - Input: [[A0, A1, A2], [B0, B1, B2]] where Ai, Bi are EF elements
/// - Output: Row-major matrix with rows [A0_coeffs..., B0_coeffs...], [A1_coeffs..., B1_coeffs...], etc.
pub fn aux_columns_to_row_major<EF: ExtensionField<Felt>>(
    aux_columns: Vec<Vec<EF>>,
    trace_len: usize,
) -> RowMajorMatrix<Felt> {
    use p3_util::flatten_to_base;

    if aux_columns.is_empty() {
        return RowMajorMatrix::new(Vec::new(), 0);
    }

    let num_ef_cols = aux_columns.len();

    // Convert column-major EF to row-major EF
    // For each row, concatenate all EF values from that row across columns
    let mut row_major_ef_data = Vec::with_capacity(trace_len * num_ef_cols);
    for row_idx in 0..trace_len {
        for col in &aux_columns {
            row_major_ef_data.push(col[row_idx]);
        }
    }

    // Flatten row-major EF to row-major base field
    // flatten_to_base expands each EF element into its base field coefficients
    let row_major_felt_data: Vec<Felt> = unsafe { flatten_to_base(row_major_ef_data) };

    // Calculate extension degree and number of base field columns
    let total_ef_elements = trace_len * num_ef_cols;
    let extension_degree = row_major_felt_data.len() / total_ef_elements;
    let num_base_cols = num_ef_cols * extension_degree;

    RowMajorMatrix::new(row_major_felt_data, num_base_cols)
}
