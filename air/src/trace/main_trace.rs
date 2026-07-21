use alloc::vec::Vec;
use core::borrow::{Borrow, BorrowMut};
#[cfg(any(test, feature = "testing"))]
use core::ops::Range;

use miden_core::{
    Felt, ONE, ZERO,
    utils::{Matrix, RowMajorMatrix},
};

use super::{
    CHIPLETS_WIDTH, RowIndex, TRACE_WIDTH, poseidon2_permutation::NUM_POSEIDON2_PERMUTATION_COLS,
};
use crate::constraints::{
    columns::{ChipletCols, CoreCols, NUM_CHIPLETS_COLS, NUM_CORE_COLS},
    decoder::columns::DecoderCols,
    range::columns::RangeCols,
    stack::columns::StackCols,
    system::columns::SystemCols,
};

// MAIN TRACE ROW
// ================================================================================================

/// Column layout of the main trace row.
#[derive(Debug)]
#[repr(C)]
pub struct MainTraceRow<T> {
    pub system: SystemCols<T>,
    pub decoder: DecoderCols<T>,
    pub stack: StackCols<T>,
    pub range: RangeCols<T>,
    pub chiplets: ChipletCols<T>,
}

impl<T> Borrow<MainTraceRow<T>> for [T] {
    fn borrow(&self) -> &MainTraceRow<T> {
        debug_assert_eq!(self.len(), TRACE_WIDTH);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MainTraceRow<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<MainTraceRow<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut MainTraceRow<T> {
        debug_assert_eq!(self.len(), TRACE_WIDTH);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<MainTraceRow<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

// MAIN TRACE MATRIX
// ================================================================================================

/// Storage backing [`MainTrace`]: per-segment row-major buffers produced by `build_trace`.
#[derive(Debug)]
struct TraceStorage {
    /// Core matrix (`CORE_STORAGE_WIDTH` cols), at its own per-AIR height.
    core_rm: RowMajorMatrix<Felt>,
    /// Chiplets matrix (`CHIPLETS_WIDTH` cols), at its own per-AIR height.
    chiplets_rm: RowMajorMatrix<Felt>,
    /// Poseidon2 permutation matrix, at its own per-AIR height.
    poseidon2_permutation_rm: RowMajorMatrix<Felt>,
}

#[derive(Debug)]
pub struct MainTrace {
    storage: TraceStorage,
    last_program_row: RowIndex,
}

/// Physical row width of `core_rm`: the full per-AIR Core matrix width (`NUM_CORE_COLS`),
/// i.e. system+decoder+stack columns plus the two trailing range-checker columns.
const CORE_STORAGE_WIDTH: usize = NUM_CORE_COLS;

impl MainTrace {
    pub fn from_parts(
        core_rm: Vec<Felt>,
        chiplets_rm: Vec<Felt>,
        poseidon2_permutation_rm: Vec<Felt>,
        last_program_row: RowIndex,
    ) -> Self {
        assert_eq!(
            core_rm.len() % CORE_STORAGE_WIDTH,
            0,
            "core buffer not a multiple of CORE_STORAGE_WIDTH"
        );
        assert_eq!(
            chiplets_rm.len() % CHIPLETS_WIDTH,
            0,
            "chiplets buffer not a multiple of CHIPLETS_WIDTH"
        );
        assert_eq!(
            poseidon2_permutation_rm.len() % NUM_POSEIDON2_PERMUTATION_COLS,
            0,
            "Poseidon2 buffer not a multiple of NUM_POSEIDON2_PERMUTATION_COLS"
        );
        let core_rows = core_rm.len() / CORE_STORAGE_WIDTH;
        let chiplets_rows = chiplets_rm.len() / CHIPLETS_WIDTH;
        let poseidon2_rows = poseidon2_permutation_rm.len() / NUM_POSEIDON2_PERMUTATION_COLS;
        assert!(core_rows.is_power_of_two(), "core height must be a power of two");
        assert!(chiplets_rows.is_power_of_two(), "chiplets height must be a power of two");
        assert!(
            poseidon2_rows.is_power_of_two(),
            "Poseidon2 permutation height must be a power of two"
        );
        Self {
            storage: TraceStorage {
                core_rm: RowMajorMatrix::new(core_rm, CORE_STORAGE_WIDTH),
                chiplets_rm: RowMajorMatrix::new(chiplets_rm, CHIPLETS_WIDTH),
                poseidon2_permutation_rm: RowMajorMatrix::new(
                    poseidon2_permutation_rm,
                    NUM_POSEIDON2_PERMUTATION_COLS,
                ),
            },
            last_program_row,
        }
    }

    /// Returns the stored core trace row at index `i`.
    ///
    /// # Panics
    /// Panics if `i` is past the core trace height — see [`Self::core_height`]. Callers
    /// iterating the unified trace must bound by [`Self::core_height`] for Core accessors.
    #[inline]
    pub fn core_row(&self, i: RowIndex) -> &CoreCols<Felt> {
        let (rows, _) = self.storage.core_rm.values.as_chunks::<NUM_CORE_COLS>();
        rows[i.as_usize()].as_slice().borrow()
    }

    /// Returns the stored chiplets trace row at index `i`.
    ///
    /// The returned [`ChipletCols`] is the raw column layout shared across all chiplets;
    /// use one of the per-chiplet overlays (`.controller()`, `.bitwise()`,
    /// `.memory()`, `.ace()`, `.kernel_rom()`) to name the physical columns according to
    /// the chiplet active on that row.
    ///
    /// # Panics
    /// Panics if `i` is past the chiplets trace height — see [`Self::chiplets_height`]. The
    /// `is_bitwise_row`/`is_memory_row` classifiers short-circuit past the chiplets height, so
    /// they can be used as bound-aware filters when iterating the unified trace.
    #[inline]
    pub fn chiplet_cols(&self, i: RowIndex) -> &ChipletCols<Felt> {
        let (rows, _) = self.storage.chiplets_rm.values.as_chunks::<NUM_CHIPLETS_COLS>();
        rows[i.as_usize()].as_slice().borrow()
    }

    /// Splits the trace into the per-AIR matrices used by the multi-AIR proving path.
    pub fn to_air_matrices(
        &self,
    ) -> (RowMajorMatrix<Felt>, RowMajorMatrix<Felt>, RowMajorMatrix<Felt>) {
        // Each buffer is already stored at exactly its per-AIR height.
        (
            self.storage.core_rm.clone(),
            self.storage.chiplets_rm.clone(),
            self.storage.poseidon2_permutation_rm.clone(),
        )
    }

    /// Like [`Self::to_air_matrices`], but consumes the trace and moves buffers.
    pub fn into_air_matrices(
        self,
    ) -> (RowMajorMatrix<Felt>, RowMajorMatrix<Felt>, RowMajorMatrix<Felt>) {
        (
            self.storage.core_rm,
            self.storage.chiplets_rm,
            self.storage.poseidon2_permutation_rm,
        )
    }

    /// Returns the larger of all per-AIR heights.
    pub fn num_rows(&self) -> usize {
        self.core_height()
            .max(self.chiplets_height())
            .max(self.poseidon2_permutation_height())
    }

    /// Returns the Core-AIR trace height.
    #[inline]
    pub fn core_height(&self) -> usize {
        self.storage.core_rm.height()
    }

    /// Returns the Chiplets-AIR trace height.
    #[inline]
    pub fn chiplets_height(&self) -> usize {
        self.storage.chiplets_rm.height()
    }

    /// Returns the Poseidon2-permutation AIR trace height.
    #[inline]
    pub fn poseidon2_permutation_height(&self) -> usize {
        self.storage.poseidon2_permutation_rm.height()
    }

    pub fn last_program_row(&self) -> RowIndex {
        self.last_program_row
    }

    /// Returns one column as a new vector.
    ///
    /// Returns a column of length [`Self::core_height`] for Core columns and
    /// [`Self::chiplets_height`] for Chiplets columns — there is no unified projection.
    // Test/debug-only, the proving path never materializes columns.
    #[cfg(any(test, feature = "testing"))]
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
    #[cfg(any(test, feature = "testing"))]
    pub fn columns(&self) -> impl Iterator<Item = Vec<Felt>> + '_ {
        (0..TRACE_WIDTH).map(|c| self.get_column(c))
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn get_column_range(&self, range: Range<usize>) -> Vec<Vec<Felt>> {
        range.fold(vec![], |mut acc, col_idx| {
            acc.push(self.get_column(col_idx));
            acc
        })
    }

    // CHIPLETS COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns `true` if a row is part of the bitwise chiplet.
    /// Active when `s0=1` and `s1=0`.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height so the classifier is safe to
    /// call on any row of the unified trace.
    pub fn is_bitwise_row(&self, i: RowIndex) -> bool {
        if i.as_usize() >= self.chiplets_height() {
            return false;
        }
        let s = self.chiplet_cols(i).chiplet_selectors();
        s[0] == ONE && s[1] == ZERO
    }

    /// Returns `true` if a row is part of the memory chiplet.
    /// Active when `s0=1`, `s1=1`, and `s2=0`.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; see [`Self::is_bitwise_row`].
    pub fn is_memory_row(&self, i: RowIndex) -> bool {
        if i.as_usize() >= self.chiplets_height() {
            return false;
        }
        let s = self.chiplet_cols(i).chiplet_selectors();
        s[0] == ONE && s[1] == ONE && s[2] == ZERO
    }
}

#[cfg(test)]
mod tests {
    use miden_core::utils::Matrix;

    use super::*;
    use crate::trace::TRACE_WIDTH;

    /// Builds a deterministic Parts-form `MainTrace` with `num_rows` rows where each cell
    /// holds `Felt::from_u32(row * TRACE_WIDTH + col)` for col positions matching the
    /// equivalent unified-trace column index.
    fn deterministic_parts_trace(num_rows: usize) -> MainTrace {
        // `core_rm` is the full per-AIR Core matrix (range columns in trailing slots).
        let mut core_rm = Vec::with_capacity(num_rows * CORE_STORAGE_WIDTH);
        let mut chiplets_rm = Vec::with_capacity(num_rows * CHIPLETS_WIDTH);
        let mut poseidon2_rm = Vec::with_capacity(num_rows * NUM_POSEIDON2_PERMUTATION_COLS);

        for row in 0..num_rows {
            for col in 0..CORE_STORAGE_WIDTH {
                core_rm.push(Felt::from_u32((row * TRACE_WIDTH + col) as u32));
            }
            for c in 0..CHIPLETS_WIDTH {
                chiplets_rm
                    .push(Felt::from_u32((row * TRACE_WIDTH + CORE_STORAGE_WIDTH + c) as u32));
            }
            for c in 0..NUM_POSEIDON2_PERMUTATION_COLS {
                poseidon2_rm.push(Felt::from_u32((row * 100 + c) as u32));
            }
        }

        MainTrace::from_parts(core_rm, chiplets_rm, poseidon2_rm, RowIndex::from(0))
    }

    #[test]
    fn into_split_matches_borrowed_split() {
        const NUM_ROWS: usize = 8;
        let (ref_core, ref_chip, ref_poseidon2) =
            deterministic_parts_trace(NUM_ROWS).to_air_matrices();
        let (moved_core, moved_chip, moved_poseidon2) =
            deterministic_parts_trace(NUM_ROWS).into_air_matrices();

        assert_eq!(ref_core.width(), moved_core.width());
        assert_eq!(ref_chip.width(), moved_chip.width());
        assert_eq!(ref_poseidon2.width(), moved_poseidon2.width());
        assert_eq!(ref_core.values, moved_core.values);
        assert_eq!(ref_chip.values, moved_chip.values);
        assert_eq!(ref_poseidon2.values, moved_poseidon2.values);
    }
}
