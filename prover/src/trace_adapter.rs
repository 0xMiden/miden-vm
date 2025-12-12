//! Trace format conversion utilities.
//!
//! This module provides functions to convert between miden-processor's `ExecutionTrace`
//! format (column-major) and Plonky3's `RowMajorMatrix` format (row-major).

use alloc::vec;

use miden_air::trace::{AUX_TRACE_WIDTH, TRACE_WIDTH, ColMatrix};
use miden_air::Felt;
use miden_processor::ExecutionTrace;
use p3_field::{ExtensionField, PrimeCharacteristicRing};
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
///
/// # Performance
///
/// This performs a naive transposition which requires O(rows * cols) operations.
/// For large traces, this can be expensive. Future optimizations could include:
/// - Cache-oblivious transposition
/// - SIMD vectorization
/// - GPU acceleration
#[instrument("transpose main trace", skip_all)]
pub fn execution_trace_to_row_major(trace: &ExecutionTrace) -> RowMajorMatrix<Felt> {
    let trace_len = trace.get_trace_len();
    let mut result = RowMajorMatrix::new(vec![Felt::ZERO; TRACE_WIDTH * trace_len], TRACE_WIDTH);

    result.rows_mut().enumerate().for_each(|(row_idx, row)| {
        for col_idx in 0..TRACE_WIDTH {
            row[col_idx] = trace.main_trace.get(col_idx, row_idx);
        }
    });

    result
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
#[instrument("transpose aux trace", skip_all)]
pub fn aux_trace_to_row_major<E>(trace: &ColMatrix<E>) -> RowMajorMatrix<E>
where
    E: ExtensionField<Felt>,
{
    let trace_len = trace.num_rows();
    let mut result = RowMajorMatrix::new(vec![E::ZERO; AUX_TRACE_WIDTH * trace_len], AUX_TRACE_WIDTH);

    result.rows_mut().enumerate().for_each(|(row_idx, row)| {
        for col_idx in 0..AUX_TRACE_WIDTH {
            row[col_idx] = trace.get(col_idx, row_idx);
        }
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Add tests for trace conversion
    // - Test round-trip conversion
    // - Test with various trace sizes
    // - Test with empty traces
    // - Verify element-by-element correctness
}
