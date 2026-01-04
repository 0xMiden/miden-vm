//! Trace format conversion utilities.
//!
//! This module provides functions to convert between miden-processor's `ExecutionTrace`
//! format (column-major) and Plonky3's `RowMajorMatrix` format (row-major).

use alloc::vec::Vec;

use miden_air::{
    Felt,
    trace::{AUX_TRACE_WIDTH, TRACE_WIDTH},
};
use miden_core::utils::ColMatrix;
use miden_crypto::field::ExtensionField;
use miden_processor::ExecutionTrace;
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

    // Extract column-major data into a flat buffer (columns are contiguous)
    let mut col_major_data = Vec::with_capacity(TRACE_WIDTH * trace_len);
    for col_idx in 0..TRACE_WIDTH {
        col_major_data.extend_from_slice(trace.main_trace().get_column(col_idx));
    }

    // Build a column-major matrix and transpose to row-major using Plonky3's optimized transpose
    let col_major_matrix = RowMajorMatrix::new(col_major_data, trace_len);
    col_major_matrix.transpose()
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
    E: ExtensionField<Felt> + Default,
{
    let trace_len = trace.num_rows();

    // Extract column-major data into a flat buffer (columns are contiguous)
    let mut col_major_data = Vec::with_capacity(AUX_TRACE_WIDTH * trace_len);
    for col_idx in 0..AUX_TRACE_WIDTH {
        col_major_data.extend_from_slice(trace.get_column(col_idx));
    }

    // Build a column-major matrix and transpose to row-major using Plonky3's optimized transpose
    let col_major_matrix = RowMajorMatrix::new(col_major_data, trace_len);
    col_major_matrix.transpose()
}
