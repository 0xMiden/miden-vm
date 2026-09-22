use std::{ops::Range, vec::Vec};

use miden_core::{Felt, utils::RowMajorMatrix};

use crate::utils::split_u64;

/// Extract one contiguous column band from every row of a matrix.
pub(super) fn extract_band<T: Clone + Send + Sync>(
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

#[test]
fn split_u64_extracts_lo_hi_halves() {
    assert_eq!(split_u64(0), [Felt::ZERO, Felt::ZERO]);
    // 2^32 → lo = 0, hi = 1.
    assert_eq!(split_u64(0x1_0000_0000), [Felt::ZERO, Felt::new(1).unwrap()]);
    // Max u32 fits in lo.
    assert_eq!(split_u64(0xffff_ffff), [Felt::new(0xffff_ffff).unwrap(), Felt::ZERO],);
    assert_eq!(
        split_u64(0xdead_beef_cafe_babe),
        [Felt::new(0xcafe_babe).unwrap(), Felt::new(0xdead_beef).unwrap()],
    );
}
