//! Parallel matrix transposition routines.

use alloc::vec::Vec;

use p3_maybe_rayon::prelude::{IntoParallelIterator, ParallelIterator};

/// Transposes a matrix using parallel processing.
///
/// # Arguments
///
/// * `src` - Source matrix data in row-major format (rows × cols)
/// * `rows` - Number of rows in the source matrix
/// * `cols` - Number of columns in the source matrix
///
/// # Returns
///
/// Transposed matrix data in row-major format (cols × rows)
fn transpose<T: Copy + Send + Sync>(src: &[T], rows: usize, cols: usize) -> Vec<T> {
    debug_assert_eq!(src.len(), rows * cols, "Source data size mismatch");

    // Use parallel iterator to compute each output element
    // This approach is safe because each output element is computed independently
    (0..rows * cols)
        .into_par_iter()
        .map(|dst_idx| {
            // For output at position dst_idx, determine which source position to read from
            let dst_row = dst_idx / rows;
            let dst_col = dst_idx % rows;

            // The transposed element comes from src[dst_col][dst_row]
            let src_idx = dst_col * cols + dst_row;

            src[src_idx]
        })
        .collect()
}

/// Transposes from column-major to row-major format.
///
/// # Arguments
///
/// * `col_major` - Data in column-major format
/// * `rows` - Number of rows in the logical matrix
/// * `cols` - Number of columns in the logical matrix
///
/// # Returns
///
/// Data in row-major format
pub fn col_major_to_row_major<T: Copy + Send + Sync>(
    col_major: &[T],
    rows: usize,
    cols: usize,
) -> Vec<T> {
    // Column-major with rows×cols is equivalent to row-major with cols×rows, transposed
    transpose(col_major, cols, rows)
}

/// Transposes from row-major to column-major format.
///
/// # Arguments
///
/// * `row_major` - Data in row-major format
/// * `rows` - Number of rows in the matrix
/// * `cols` - Number of columns in the matrix
///
/// # Returns
///
/// Data in column-major format
pub fn row_major_to_col_major<T: Copy + Send + Sync>(
    row_major: &[T],
    rows: usize,
    cols: usize,
) -> Vec<T> {
    transpose(row_major, rows, cols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transpose_small() {
        // 2×3 matrix:
        // [1, 2, 3]
        // [4, 5, 6]
        let src = vec![1, 2, 3, 4, 5, 6];
        let result = transpose(&src, 2, 3);

        // Expected 3×2 matrix:
        // [1, 4]
        // [2, 5]
        // [3, 6]
        let expected = vec![1, 4, 2, 5, 3, 6];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_transpose_square() {
        // 3×3 matrix:
        // [1, 2, 3]
        // [4, 5, 6]
        // [7, 8, 9]
        let src = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let result = transpose(&src, 3, 3);

        // Expected:
        // [1, 4, 7]
        // [2, 5, 8]
        // [3, 6, 9]
        let expected = vec![1, 4, 7, 2, 5, 8, 3, 6, 9];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_transpose_large() {
        // Test a larger matrix
        let rows = 130;
        let cols = 70;
        let mut src = Vec::with_capacity(rows * cols);

        // Fill with values that encode their position: row * 1000 + col
        for i in 0..rows {
            for j in 0..cols {
                src.push(i * 1000 + j);
            }
        }

        let result = transpose(&src, rows, cols);

        // Verify transpose: result[j][i] should equal src[i][j]
        for i in 0..rows {
            for j in 0..cols {
                let src_val = src[i * cols + j];
                let dst_val = result[j * rows + i];
                assert_eq!(
                    dst_val, src_val,
                    "Mismatch at ({}, {}): src={}, dst={}",
                    i, j, src_val, dst_val
                );
            }
        }
    }

    #[test]
    fn test_col_major_to_row_major() {
        // Column-major representation of:
        // [1, 2, 3]
        // [4, 5, 6]
        // Stored as columns: [1, 4], [2, 5], [3, 6]
        let col_major = vec![1, 4, 2, 5, 3, 6];
        let result = col_major_to_row_major(&col_major, 2, 3);

        // Expected row-major: [1, 2, 3, 4, 5, 6]
        let expected = vec![1, 2, 3, 4, 5, 6];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_row_major_to_col_major() {
        // Row-major representation of:
        // [1, 2, 3]
        // [4, 5, 6]
        let row_major = vec![1, 2, 3, 4, 5, 6];
        let result = row_major_to_col_major(&row_major, 2, 3);

        // Expected column-major: [1, 4, 2, 5, 3, 6]
        let expected = vec![1, 4, 2, 5, 3, 6];
        assert_eq!(result, expected);
    }
}
