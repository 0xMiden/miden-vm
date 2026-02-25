//! Trace format conversion utilities.
//!
//! Converts miden-processor's column-major `ExecutionTrace` to Plonky3's
//! row-major `RowMajorMatrix` format.

use alloc::vec::Vec;

use miden_air::trace::TRACE_WIDTH;
use miden_core::{Felt, utils::RowMajorMatrix};
use miden_processor::trace::ExecutionTrace;
use tracing::instrument;

/// Converts the main trace from column-major (ExecutionTrace) to row-major (Plonky3) format.
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
