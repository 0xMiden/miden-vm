//! Optional column materialization for trace tests and debugging.

use alloc::vec::Vec;
use core::ops::Range;

use miden_core::Felt;

use super::{CORE_STORAGE_WIDTH, MainTrace};
use crate::vm::{
    constraints::columns::{NUM_CHIPLETS_COLS, NUM_CORE_COLS},
    trace::TRACE_WIDTH,
};

impl MainTrace {
    /// Returns one column as a new vector.
    ///
    /// Returns a column of length [`Self::core_height`] for Core columns and
    /// [`Self::chiplets_height`] for Chiplets columns — there is no unified projection.
    // Test/debug-only, the proving path never materializes columns.
    pub fn get_column(&self, col_idx: usize) -> Vec<Felt> {
        if col_idx < CORE_STORAGE_WIDTH {
            let (rows, _) = self.storage.core_rm.values.as_chunks::<NUM_CORE_COLS>();
            rows.iter().map(|row| row[col_idx]).collect()
        } else {
            let chip_col = col_idx - CORE_STORAGE_WIDTH;
            let (rows, _) = self.storage.chiplets_rm.values.as_chunks::<NUM_CHIPLETS_COLS>();
            rows.iter().map(|row| row[chip_col]).collect()
        }
    }

    /// Iterates over all columns (materialises each one). Test/debug-only.
    pub fn columns(&self) -> impl Iterator<Item = Vec<Felt>> + '_ {
        (0..TRACE_WIDTH).map(|c| self.get_column(c))
    }

    pub fn get_column_range(&self, range: Range<usize>) -> Vec<Vec<Felt>> {
        range.fold(vec![], |mut acc, col_idx| {
            acc.push(self.get_column(col_idx));
            acc
        })
    }
}
