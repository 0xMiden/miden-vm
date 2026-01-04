//! Utilities for converting between row-major and column-major matrix formats.
//!
//! This module provides functions for:
//! - Converting between row-major (Plonky3) and column-major (Miden) matrix formats
//! - Building auxiliary trace columns from row-major main traces

use alloc::vec::Vec;

use miden_air::trace::MainTrace;
use miden_core::{
    Felt,
    field::{ExtensionField, PrimeCharacteristicRing},
    utils::ColMatrix,
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use tracing::instrument;

use crate::trace::AuxTraceBuilders;

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

/// Converts column-major extension field columns to row-major base field matrix.
///
/// This function performs two operations:
/// 1. Transposes from column-major to row-major layout (using cache-blocked transposition)
/// 2. Flattens extension field elements to base field representation
///
/// The input is a vector of EF columns (each column is a Vec<EF>).
/// The output is a row-major matrix where each EF element is expanded to its base field
/// coefficients.
///
/// For example, with 2 EF columns and 3 rows:
/// - Input: [[A0, A1, A2], [B0, B1, B2]] where Ai, Bi are EF elements
/// - Output: Row-major matrix with rows [A0_coeffs..., B0_coeffs...], [A1_coeffs..., B1_coeffs...],
///   etc.
///
/// Uses cache-blocked transposition to improve memory layout for better cache behavior
/// in downstream operations.
#[instrument(skip_all, fields(num_cols = aux_columns.len(), trace_len))]
pub fn aux_columns_to_row_major<EF: ExtensionField<Felt>>(
    aux_columns: Vec<Vec<EF>>,
    trace_len: usize,
) -> RowMajorMatrix<Felt> {
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
    let row_major_ef_matrix = RowMajorMatrix::new(col_major_ef_data, trace_len).transpose();
    row_major_ef_matrix.flatten_to_base()
}

/// Builds auxiliary trace columns from a row-major main trace.
///
/// This function handles the format conversion between Plonky3's row-major format and
/// Miden's internal column-major format:
/// 1. Converts the row-major main trace to column-major `MainTrace`
/// 2. Builds auxiliary columns using the provided builders
/// 3. Converts the result back to row-major format
///
/// This is the main entry point for auxiliary trace generation when using Plonky3.
#[allow(dead_code)]
#[instrument(skip_all, fields(rows = main_trace.height(), cols = main_trace.width()))]
pub fn build_aux_columns<EF: ExtensionField<Felt>>(
    aux_builders: &AuxTraceBuilders,
    main_trace: &RowMajorMatrix<Felt>,
    challenges: &[EF],
) -> RowMajorMatrix<Felt> {
    let _span = tracing::info_span!("build_aux_columns_row_major").entered();

    // Convert row-major to column-major MainTrace
    let main_trace_col_major = row_major_to_main_trace(main_trace);

    // Build auxiliary columns using column-major logic
    let aux_columns = aux_builders.build_aux_columns(&main_trace_col_major, challenges);

    // Convert column-major aux columns back to row-major
    aux_columns_to_row_major(aux_columns, main_trace.height())
}
