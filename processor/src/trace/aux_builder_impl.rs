//! Implementation of AuxTraceBuilder trait for processor's AuxTraceBuilders.

use alloc::vec::Vec;
use miden_air::{AuxTraceBuilder, trace::{ColMatrix, main_trace::MainTrace}};
use miden_core::{ExtensionField, Felt, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use super::AuxTraceBuilders;

impl<EF: ExtensionField<Felt>> AuxTraceBuilder<EF> for AuxTraceBuilders {
    fn build_aux_trace(
        &self,
        main_trace: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> RowMajorMatrix<Felt> {
        // Convert row-major to column-major MainTrace format
        let main_trace_cols = row_major_to_col_major(main_trace);
        let last_program_row = find_last_program_row(main_trace);
        let main_trace_structured = MainTrace::new(main_trace_cols, last_program_row.into());

        // Build individual auxiliary columns using existing builders
        let decoder_cols = self.decoder.build_aux_columns(&main_trace_structured, challenges);
        let stack_cols = self.stack.build_aux_columns(&main_trace_structured, challenges);
        let range_cols = self.range.build_aux_columns(&main_trace_structured, challenges);
        let chiplets_cols = self.chiplets.build_aux_columns(&main_trace_structured, challenges);

        // Combine all columns in order
        let aux_columns: Vec<Vec<EF>> = decoder_cols
            .into_iter()
            .chain(stack_cols)
            .chain(range_cols)
            .chain(chiplets_cols)
            .collect();

        // Convert from column-major extension field to row-major base field
        col_major_ef_to_row_major_f(aux_columns, main_trace.height())
    }
}

/// Converts a row-major matrix to column-major format.
fn row_major_to_col_major(matrix: &RowMajorMatrix<Felt>) -> ColMatrix<Felt> {
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

    ColMatrix::new(columns)
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
fn col_major_ef_to_row_major_f<EF: ExtensionField<Felt>>(
    columns: Vec<Vec<EF>>,
    trace_len: usize,
) -> RowMajorMatrix<Felt> {
    use p3_util::flatten_to_base;

    if columns.is_empty() {
        return RowMajorMatrix::new(alloc::vec![], 0);
    }

    // Flatten each EF column to base field (extension degree expansion)
    let base_columns: Vec<Vec<Felt>> = columns
        .into_iter()
        .map(|col| unsafe { flatten_to_base(col) })
        .collect();

    // Determine extension degree
    let extension_degree = base_columns[0].len() / trace_len;
    let num_cols = base_columns.len();
    let num_base_cols = num_cols * extension_degree;

    // Reorganize from column-major to row-major
    let mut row_major_data = Vec::with_capacity(num_base_cols * trace_len);
    for row_idx in 0..trace_len {
        for base_col in &base_columns {
            // For each original EF column, output all D coefficients for this row
            for coeff_idx in 0..extension_degree {
                let idx = row_idx * extension_degree + coeff_idx;
                row_major_data.push(base_col[idx]);
            }
        }
    }

    RowMajorMatrix::new(row_major_data, num_base_cols)
}
