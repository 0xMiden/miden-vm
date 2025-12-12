//! Trace format conversion utilities.
//!
//! This module provides functions to convert between miden-processor's `ExecutionTrace`
//! format (column-major) and Plonky3's `RowMajorMatrix` format (row-major).

use alloc::vec::Vec;

use miden_air::{
    Felt,
    trace::{AUX_TRACE_WIDTH, ColMatrix, TRACE_WIDTH},
    transpose,
};
use miden_processor::ExecutionTrace;
use p3_field::ExtensionField;
use p3_matrix::dense::RowMajorMatrix;
use tracing::instrument;

/// Converts the main trace from column-major (ExecutionTrace) to row-major (Plonky3) format.
///
/// # Arguments
///
/// * `trace` - The execution trace in column-major format
///
/// # Returns
///
/// A `RowMajorMatrix` containing the same trace data in row-major format.
#[instrument(skip_all, fields(rows = trace.get_trace_len(), cols = TRACE_WIDTH))]
pub fn execution_trace_to_row_major(trace: &ExecutionTrace) -> RowMajorMatrix<Felt> {
    let trace_len = trace.get_trace_len();

    // Extract column-major data into a flat buffer
    let mut col_major_data = Vec::with_capacity(TRACE_WIDTH * trace_len);
    for col_idx in 0..TRACE_WIDTH {
        for row_idx in 0..trace_len {
            col_major_data.push(trace.main_trace.get(col_idx, row_idx));
        }
    }

    // Use optimized cache-blocked transposition: column-major -> row-major
    let row_major_data = transpose::col_major_to_row_major(&col_major_data, trace_len, TRACE_WIDTH);

    RowMajorMatrix::new(row_major_data, TRACE_WIDTH)
}

/// Converts an auxiliary trace from column-major to row-major format.
///
/// The auxiliary trace contains extension field elements, typically used for
/// permutation arguments (RAP) or other advanced proving techniques.
///
/// # Arguments
///
/// * `trace` - The auxiliary trace in column-major format over extension field `E`
///
/// # Returns
///
/// A `RowMajorMatrix` containing the auxiliary trace in row-major format.
///
/// # Type Parameters
///
/// * `E` - The extension field type (e.g., `BinomialExtensionField<Felt, 2>`)
#[instrument(skip_all, fields(rows = trace.num_rows(), cols = AUX_TRACE_WIDTH))]
pub fn aux_trace_to_row_major<E>(trace: &ColMatrix<E>) -> RowMajorMatrix<E>
where
    E: ExtensionField<Felt>,
{
    let trace_len = trace.num_rows();
    let mut result =
        RowMajorMatrix::new(alloc::vec![E::ZERO; AUX_TRACE_WIDTH * trace_len], AUX_TRACE_WIDTH);

    result.rows_mut().enumerate().for_each(|(row_idx, row)| {
        for (col_idx, elem) in row.iter_mut().enumerate() {
            *elem = trace.get(col_idx, row_idx);
        }
    });

    result
}
