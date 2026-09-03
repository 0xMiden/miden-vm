//! Column-band access for AIRs composed into disjoint column bands.

use alloc::vec::Vec;
use core::ops::Range;

use miden_core::utils::RowMajorMatrix;

/// Extract one contiguous column band from every row of a matrix.
pub fn extract_band<T: Clone + Send + Sync>(
    matrix: &RowMajorMatrix<T>,
    columns: Range<usize>,
) -> RowMajorMatrix<T> {
    assert!(columns.start <= columns.end && columns.end <= matrix.width);
    let width = columns.len();
    let height = matrix.values.len() / matrix.width;
    let mut values = Vec::with_capacity(height * width);
    for row in matrix.values.chunks_exact(matrix.width) {
        values.extend_from_slice(&row[columns.clone()]);
    }
    RowMajorMatrix::new(values, width)
}
