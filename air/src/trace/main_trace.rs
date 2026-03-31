use alloc::{sync::Arc, vec::Vec};
use core::{
    borrow::{Borrow, BorrowMut},
    ops::Range,
};

use miden_core::{
    Felt, ONE, WORD_SIZE, Word, ZERO,
    field::PrimeCharacteristicRing,
    utils::{Matrix, RowMajorMatrix, range},
};

use super::{
    CHIPLETS_OFFSET, CHIPLETS_WIDTH, CLK_COL_IDX, CTX_COL_IDX, DECODER_TRACE_OFFSET,
    DECODER_TRACE_WIDTH, FN_HASH_OFFSET, PADDED_TRACE_WIDTH, RANGE_CHECK_TRACE_OFFSET,
    RANGE_CHECK_TRACE_WIDTH, RowIndex, STACK_TRACE_OFFSET, STACK_TRACE_WIDTH,
    chiplets::{
        BITWISE_A_COL_IDX, BITWISE_B_COL_IDX, BITWISE_OUTPUT_COL_IDX, HASHER_NODE_INDEX_COL_IDX,
        HASHER_STATE_COL_RANGE, MEMORY_CLK_COL_IDX, MEMORY_CTX_COL_IDX, MEMORY_IDX0_COL_IDX,
        MEMORY_IDX1_COL_IDX, MEMORY_V_COL_RANGE, MEMORY_WORD_COL_IDX, NUM_ACE_SELECTORS,
        ace::{
            CLK_IDX, CTX_IDX, EVAL_OP_IDX, ID_0_IDX, ID_1_IDX, ID_2_IDX, M_0_IDX, M_1_IDX, PTR_IDX,
            READ_NUM_EVAL_IDX, SELECTOR_BLOCK_IDX, SELECTOR_START_IDX, V_0_0_IDX, V_0_1_IDX,
            V_1_0_IDX, V_1_1_IDX, V_2_0_IDX, V_2_1_IDX,
        },
        hasher::{DIGEST_LEN, HASH_CYCLE_LEN, LAST_CYCLE_ROW, STATE_WIDTH},
    },
    decoder::{
        GROUP_COUNT_COL_IDX, HASHER_STATE_OFFSET, IN_SPAN_COL_IDX, IS_CALL_FLAG_COL_IDX,
        IS_LOOP_BODY_FLAG_COL_IDX, IS_LOOP_FLAG_COL_IDX, IS_SYSCALL_FLAG_COL_IDX,
        NUM_HASHER_COLUMNS, NUM_OP_BATCH_FLAGS, OP_BATCH_FLAGS_OFFSET, OP_BITS_EXTRA_COLS_OFFSET,
        USER_OP_HELPERS_OFFSET,
    },
    stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX},
};

// CONSTANTS
// ================================================================================================

const DECODER_HASHER_RANGE: Range<usize> =
    range(DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET, NUM_HASHER_COLUMNS);

// MAIN TRACE ROW
// ================================================================================================

/// Column layout of the main trace row.
#[derive(Debug)]
#[repr(C)]
pub struct MainTraceRow<T> {
    // System
    pub clk: T,
    pub ctx: T,
    pub fn_hash: [T; WORD_SIZE],

    // Decoder
    pub decoder: [T; DECODER_TRACE_WIDTH],

    // Stack
    pub stack: [T; STACK_TRACE_WIDTH],

    // Range checker
    pub range: [T; RANGE_CHECK_TRACE_WIDTH],

    // Chiplets
    pub chiplets: [T; CHIPLETS_WIDTH],
}

impl<T> Borrow<MainTraceRow<T>> for [T] {
    fn borrow(&self) -> &MainTraceRow<T> {
        debug_assert_eq!(self.len(), crate::TRACE_WIDTH);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MainTraceRow<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<MainTraceRow<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut MainTraceRow<T> {
        debug_assert_eq!(self.len(), crate::TRACE_WIDTH);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<MainTraceRow<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

// MAIN TRACE MATRIX
// ================================================================================================

/// Storage backing [`MainTrace`]: `Parts` from `build_trace`, `RowMajor` from the prover, or
/// `Transposed` (`W×N` row-major of an `N×W` trace) for aux trace construction.
#[derive(Debug)]
enum TraceStorage {
    /// Core and chiplets as row-major matrices; range checker as column vectors (same layout as
    /// `build_trace` output, moved in without repacking).
    Parts {
        core_rm: RowMajorMatrix<Felt>,
        chiplets_rm: RowMajorMatrix<Felt>,
        range_checker_cols: [Vec<Felt>; 2],
        num_rows: usize,
    },
    RowMajor(RowMajorMatrix<Felt>),
    Transposed {
        matrix: Arc<RowMajorMatrix<Felt>>,
        num_cols: usize,
        num_rows: usize,
    },
}

#[derive(Debug)]
pub struct MainTrace {
    storage: TraceStorage,
    last_program_row: RowIndex,
}

/// Number of columns in the core (row-major) part of [`TraceStorage::Parts`].
const CORE_WIDTH: usize = RANGE_CHECK_TRACE_OFFSET;

// TODO: Could be tailored more efficiently?
#[cfg(feature = "concurrent")]
const ROW_MAJOR_CHUNK_SIZE: usize = 512;

impl MainTrace {
    /// Creates a `MainTrace` from a [`RowMajorMatrix`].
    pub fn new(matrix: RowMajorMatrix<Felt>, last_program_row: RowIndex) -> Self {
        Self {
            storage: TraceStorage::RowMajor(matrix),
            last_program_row,
        }
    }

    /// Builds from `build_trace` outputs: core and chiplets as [`RowMajorMatrix`] traces
    /// and range checker column vectors.
    pub fn from_parts(
        core_rm: RowMajorMatrix<Felt>,
        chiplets_rm: RowMajorMatrix<Felt>,
        range_checker_cols: [Vec<Felt>; 2],
        num_rows: usize,
        last_program_row: RowIndex,
    ) -> Self {
        assert_eq!(core_rm.width(), CORE_WIDTH, "core trace width matches CORE_WIDTH");
        assert_eq!(core_rm.height(), num_rows, "core trace height matches num_rows");
        assert_eq!(
            chiplets_rm.width(),
            CHIPLETS_WIDTH,
            "chiplet trace width matches CHIPLETS_WIDTH"
        );
        assert_eq!(chiplets_rm.height(), num_rows, "chiplet trace height matches num_rows");
        assert_eq!(range_checker_cols[0].len(), num_rows);
        assert_eq!(range_checker_cols[1].len(), num_rows);
        Self {
            storage: TraceStorage::Parts {
                core_rm,
                chiplets_rm,
                range_checker_cols,
                num_rows,
            },
            last_program_row,
        }
    }

    /// `transposed` is `main.transpose()` where `main` was `num_rows × num_cols`.
    pub fn from_transposed(transposed: RowMajorMatrix<Felt>, last_program_row: RowIndex) -> Self {
        Self::from_transposed_arc(Arc::new(transposed), last_program_row)
    }

    /// Same as [`Self::from_transposed`], but reuses an existing `Arc` to skip cloning the matrix.
    pub fn from_transposed_arc(
        matrix: Arc<RowMajorMatrix<Felt>>,
        last_program_row: RowIndex,
    ) -> Self {
        let num_cols = matrix.height();
        let num_rows = matrix.width();

        Self {
            storage: TraceStorage::Transposed { matrix, num_cols, num_rows },
            last_program_row,
        }
    }

    /// Get matrix element at `(row, col)`.
    ///
    /// # Panics
    /// Panics if the row or column is out of bounds.
    #[inline]
    pub fn get(&self, row: RowIndex, col: usize) -> Felt {
        let r = row.as_usize();
        match &self.storage {
            TraceStorage::Parts {
                core_rm,
                chiplets_rm,
                range_checker_cols,
                num_rows,
            } => {
                assert!(r < *num_rows, "main trace row index in bounds");
                assert!(col < PADDED_TRACE_WIDTH, "main trace column index in bounds");

                if col < CORE_WIDTH {
                    core_rm.row_slice(r).expect("main trace row index in bounds")[col]
                } else {
                    let nc = col - CORE_WIDTH;
                    if nc < RANGE_CHECK_TRACE_WIDTH {
                        range_checker_cols[nc][r]
                    } else if nc < RANGE_CHECK_TRACE_WIDTH + CHIPLETS_WIDTH {
                        let cc = nc - RANGE_CHECK_TRACE_WIDTH;
                        chiplets_rm.row_slice(r).expect("main trace row index in bounds")[cc]
                    } else {
                        ZERO
                    }
                }
            },
            TraceStorage::RowMajor(matrix) => {
                let row_slice = matrix.row_slice(r).expect("main trace row index in bounds");
                assert!(col < row_slice.len(), "main trace column index in bounds");
                row_slice[col]
            },
            TraceStorage::Transposed { matrix, num_cols, .. } => {
                let col_slice = matrix.row_slice(col).expect("main trace column index in bounds");
                assert!(r < col_slice.len(), "main trace row index in bounds");
                debug_assert_eq!(col_slice.len(), matrix.width());
                debug_assert_eq!(matrix.height(), *num_cols);
                col_slice[r]
            },
        }
    }

    /// Returns the stored width (number of columns).
    #[inline]
    pub fn width(&self) -> usize {
        match &self.storage {
            TraceStorage::Parts { .. } => PADDED_TRACE_WIDTH,
            TraceStorage::RowMajor(matrix) => matrix.width(),
            TraceStorage::Transposed { num_cols, .. } => *num_cols,
        }
    }

    /// Row-major matrix of this trace.
    pub fn to_row_major(&self) -> RowMajorMatrix<Felt> {
        match &self.storage {
            TraceStorage::RowMajor(matrix) => matrix.clone(),
            TraceStorage::Transposed { matrix, .. } => matrix.transpose(),
            TraceStorage::Parts {
                core_rm,
                chiplets_rm,
                range_checker_cols,
                num_rows,
            } => {
                let h = *num_rows;
                let w = PADDED_TRACE_WIDTH;
                let cw = CHIPLETS_WIDTH;
                let num_pad = PADDED_TRACE_WIDTH - CORE_WIDTH - 2 - cw;

                let total = h * w;
                let mut data = Vec::with_capacity(total);
                // SAFETY: the loop below writes exactly `h * w` elements.
                #[allow(clippy::uninit_vec)]
                unsafe {
                    data.set_len(total);
                }

                let fill_rows = |chunk: &mut [Felt], start_row: usize| {
                    let chunk_rows = chunk.len() / w;
                    for i in 0..chunk_rows {
                        let row = start_row + i;
                        let dst = &mut chunk[i * w..(i + 1) * w];
                        dst[..CORE_WIDTH].copy_from_slice(
                            &core_rm.row_slice(row).expect("main trace row index in bounds"),
                        );
                        dst[CORE_WIDTH] = range_checker_cols[0][row];
                        dst[CORE_WIDTH + 1] = range_checker_cols[1][row];
                        dst[CORE_WIDTH + 2..CORE_WIDTH + 2 + cw].copy_from_slice(
                            &chiplets_rm.row_slice(row).expect("main trace row index in bounds"),
                        );
                        for p in 0..num_pad {
                            dst[CORE_WIDTH + 2 + cw + p] = ZERO;
                        }
                    }
                };

                #[cfg(not(feature = "concurrent"))]
                fill_rows(&mut data, 0);

                #[cfg(feature = "concurrent")]
                {
                    use miden_crypto::parallel::*;
                    let rows_per_chunk = ROW_MAJOR_CHUNK_SIZE;
                    data.par_chunks_mut(rows_per_chunk * w).enumerate().for_each(
                        |(chunk_idx, chunk)| {
                            fill_rows(chunk, chunk_idx * rows_per_chunk);
                        },
                    );
                }

                RowMajorMatrix::new(data, w)
            },
        }
    }

    /// Like [`to_row_major`](Self::to_row_major) but only the first `target_width` columns.
    pub fn to_row_major_stripped(&self, target_width: usize) -> RowMajorMatrix<Felt> {
        match &self.storage {
            TraceStorage::RowMajor(matrix) => {
                let h = matrix.height();
                let w = matrix.width();
                debug_assert!(target_width <= w);
                if target_width == w {
                    return matrix.clone();
                }
                let total = h * target_width;
                let mut data = Vec::with_capacity(total);
                // SAFETY: the loop below writes exactly `h * target_width` elements.
                #[allow(clippy::uninit_vec)]
                unsafe {
                    data.set_len(total);
                }

                #[cfg(not(feature = "concurrent"))]
                for row in 0..h {
                    let src = matrix.row_slice(row).expect("row index in bounds");
                    data[row * target_width..(row + 1) * target_width]
                        .copy_from_slice(&src[..target_width]);
                }

                #[cfg(feature = "concurrent")]
                {
                    use miden_crypto::parallel::*;
                    let rows_per_chunk = ROW_MAJOR_CHUNK_SIZE;
                    data.par_chunks_mut(rows_per_chunk * target_width).enumerate().for_each(
                        |(chunk_idx, chunk)| {
                            let chunk_rows = chunk.len() / target_width;
                            for i in 0..chunk_rows {
                                let row = chunk_idx * rows_per_chunk + i;
                                let src = matrix.row_slice(row).expect("row index in bounds");
                                chunk[i * target_width..(i + 1) * target_width]
                                    .copy_from_slice(&src[..target_width]);
                            }
                        },
                    );
                }

                RowMajorMatrix::new(data, target_width)
            },
            TraceStorage::Transposed { .. } => {
                let full = self.to_row_major();
                if target_width == full.width() {
                    return full;
                }
                let h = full.height();
                let total = h * target_width;
                let mut data = Vec::with_capacity(total);
                // SAFETY: the loop below writes exactly `h * target_width` elements.
                #[allow(clippy::uninit_vec)]
                unsafe {
                    data.set_len(total);
                }
                for row in 0..h {
                    let src = full.row_slice(row).expect("row index in bounds");
                    data[row * target_width..(row + 1) * target_width]
                        .copy_from_slice(&src[..target_width]);
                }
                RowMajorMatrix::new(data, target_width)
            },
            TraceStorage::Parts {
                core_rm,
                chiplets_rm,
                range_checker_cols,
                num_rows,
            } => {
                let h = *num_rows;
                let cw = CHIPLETS_WIDTH;
                debug_assert!(target_width >= CORE_WIDTH);
                let nc_needed = target_width - CORE_WIDTH;

                let total = h * target_width;
                let mut data = Vec::with_capacity(total);
                // SAFETY: the loop below writes exactly `h * target_width` elements.
                #[allow(clippy::uninit_vec)]
                unsafe {
                    data.set_len(total);
                }

                let fill_rows = |chunk: &mut [Felt], start_row: usize| {
                    let chunk_rows = chunk.len() / target_width;
                    for i in 0..chunk_rows {
                        let row = start_row + i;
                        let core_row =
                            core_rm.row_slice(row).expect("main trace row index in bounds");
                        let chip_row =
                            chiplets_rm.row_slice(row).expect("main trace row index in bounds");
                        let dst = &mut chunk[i * target_width..(i + 1) * target_width];
                        dst[..CORE_WIDTH].copy_from_slice(&core_row);
                        let nc_dst = &mut dst[CORE_WIDTH..];
                        let mut nc_pos = 0;
                        if nc_needed > 0 {
                            let range_cols = RANGE_CHECK_TRACE_WIDTH.min(nc_needed);
                            for c in 0..range_cols {
                                nc_dst[c] = range_checker_cols[c][row];
                            }
                            nc_pos = range_cols;
                        }
                        if nc_pos < nc_needed {
                            let chip_cols = (nc_needed - nc_pos).min(cw);
                            nc_dst[nc_pos..nc_pos + chip_cols]
                                .copy_from_slice(&chip_row.as_ref()[..chip_cols]);
                            nc_pos += chip_cols;
                        }
                        for dst in &mut nc_dst[nc_pos..nc_needed] {
                            *dst = ZERO;
                        }
                    }
                };

                #[cfg(not(feature = "concurrent"))]
                fill_rows(&mut data, 0);

                #[cfg(feature = "concurrent")]
                {
                    use miden_crypto::parallel::*;
                    let rows_per_chunk = ROW_MAJOR_CHUNK_SIZE;
                    data.par_chunks_mut(rows_per_chunk * target_width).enumerate().for_each(
                        |(chunk_idx, chunk)| {
                            fill_rows(chunk, chunk_idx * rows_per_chunk);
                        },
                    );
                }

                RowMajorMatrix::new(data, target_width)
            },
        }
    }

    pub fn num_rows(&self) -> usize {
        match &self.storage {
            TraceStorage::Parts { num_rows, .. } => *num_rows,
            TraceStorage::RowMajor(matrix) => matrix.height(),
            TraceStorage::Transposed { num_rows, .. } => *num_rows,
        }
    }

    pub fn last_program_row(&self) -> RowIndex {
        self.last_program_row
    }

    /// Copies one logical row into `row` (must be at least as long as the stored width).
    pub fn read_row_into(&self, row_idx: usize, row: &mut [Felt]) {
        let w = self.width();
        assert!(row.len() >= w, "row buffer too small for main trace");
        match &self.storage {
            TraceStorage::RowMajor(matrix) => {
                let slice = matrix.row_slice(row_idx).expect("row index in bounds");
                row[..w].copy_from_slice(&slice);
            },
            TraceStorage::Parts {
                core_rm,
                chiplets_rm,
                range_checker_cols,
                num_rows,
            } => {
                assert!(row_idx < *num_rows, "row index in bounds");
                row[..CORE_WIDTH].copy_from_slice(
                    &core_rm.row_slice(row_idx).expect("main trace row index in bounds"),
                );
                row[CORE_WIDTH] = range_checker_cols[0][row_idx];
                row[CORE_WIDTH + 1] = range_checker_cols[1][row_idx];
                row[CORE_WIDTH + 2..CORE_WIDTH + 2 + CHIPLETS_WIDTH].copy_from_slice(
                    &chiplets_rm.row_slice(row_idx).expect("main trace row index in bounds"),
                );
                for dst in &mut row[CORE_WIDTH + 2 + CHIPLETS_WIDTH..w] {
                    *dst = ZERO;
                }
            },
            TraceStorage::Transposed { matrix, num_cols, .. } => {
                for (col_idx, cell) in row[..*num_cols].iter_mut().enumerate() {
                    *cell = unsafe { matrix.get_unchecked(col_idx, row_idx) };
                }
            },
        }
    }

    /// Returns one column as a new vector.
    pub fn get_column(&self, col_idx: usize) -> Vec<Felt> {
        let h = self.num_rows();
        match &self.storage {
            TraceStorage::Parts {
                core_rm,
                chiplets_rm,
                range_checker_cols,
                num_rows,
            } => {
                if col_idx < CORE_WIDTH {
                    (0..*num_rows)
                        .map(|r| {
                            core_rm.row_slice(r).expect("main trace row index in bounds")[col_idx]
                        })
                        .collect()
                } else {
                    let nc = col_idx - CORE_WIDTH;
                    if nc < RANGE_CHECK_TRACE_WIDTH {
                        (0..*num_rows).map(|r| range_checker_cols[nc][r]).collect()
                    } else if nc < RANGE_CHECK_TRACE_WIDTH + CHIPLETS_WIDTH {
                        let cc = nc - RANGE_CHECK_TRACE_WIDTH;
                        (0..*num_rows)
                            .map(|r| {
                                chiplets_rm.row_slice(r).expect("main trace row index in bounds")
                                    [cc]
                            })
                            .collect()
                    } else {
                        vec![ZERO; h]
                    }
                }
            },
            TraceStorage::RowMajor(_) => {
                (0..h).map(|r| self.get(RowIndex::from(r), col_idx)).collect()
            },
            TraceStorage::Transposed { matrix, .. } => {
                let row_slice = matrix.row_slice(col_idx).expect("column index in bounds");
                row_slice[..h].to_vec()
            },
        }
    }

    /// Iterates over all columns (materialises each one).
    pub fn columns(&self) -> impl Iterator<Item = Vec<Felt>> + '_ {
        (0..self.width()).map(|c| self.get_column(c))
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn get_column_range(&self, range: Range<usize>) -> Vec<Vec<Felt>> {
        range.fold(vec![], |mut acc, col_idx| {
            acc.push(self.get_column(col_idx));
            acc
        })
    }

    // SYSTEM COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns the value of the clk column at row i.
    pub fn clk(&self, i: RowIndex) -> Felt {
        self.get(i, CLK_COL_IDX)
    }

    /// Returns the value of the ctx column at row i.
    pub fn ctx(&self, i: RowIndex) -> Felt {
        self.get(i, CTX_COL_IDX)
    }

    // DECODER COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns the value in the block address column at the row i.
    pub fn addr(&self, i: RowIndex) -> Felt {
        self.get(i, DECODER_TRACE_OFFSET)
    }

    /// Helper method to detect change of address.
    pub fn is_addr_change(&self, i: RowIndex) -> bool {
        self.addr(i) != self.addr(i + 1)
    }

    /// The i-th decoder helper register at `row`.
    pub fn helper_register(&self, i: usize, row: RowIndex) -> Felt {
        self.get(row, DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + i)
    }

    /// Returns the hasher state at row i.
    pub fn decoder_hasher_state(&self, i: RowIndex) -> [Felt; NUM_HASHER_COLUMNS] {
        let mut state = [ZERO; NUM_HASHER_COLUMNS];
        for (idx, col_idx) in DECODER_HASHER_RANGE.enumerate() {
            state[idx] = self.get(i, col_idx);
        }
        state
    }

    /// Returns the first half of the hasher state at row i.
    pub fn decoder_hasher_state_first_half(&self, i: RowIndex) -> Word {
        let mut state = [ZERO; DIGEST_LEN];
        for (col, s) in state.iter_mut().enumerate() {
            *s = self.get(i, DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + col);
        }
        state.into()
    }

    /// Returns the second half of the hasher state at row i.
    pub fn decoder_hasher_state_second_half(&self, i: RowIndex) -> Word {
        const SECOND_WORD_OFFSET: usize = 4;
        let mut state = [ZERO; DIGEST_LEN];
        for (col, s) in state.iter_mut().enumerate() {
            *s = self.get(i, DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + SECOND_WORD_OFFSET + col);
        }
        state.into()
    }

    /// Returns a specific element from the hasher state at row i.
    pub fn decoder_hasher_state_element(&self, element: usize, i: RowIndex) -> Felt {
        self.get(i, DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + element)
    }

    /// Returns the current function hash (i.e., root) at row i.
    pub fn fn_hash(&self, i: RowIndex) -> [Felt; DIGEST_LEN] {
        let mut state = [ZERO; DIGEST_LEN];
        for (col, s) in state.iter_mut().enumerate() {
            *s = self.get(i, FN_HASH_OFFSET + col);
        }
        state
    }

    /// Returns the `is_loop_body` flag at row i.
    pub fn is_loop_body_flag(&self, i: RowIndex) -> Felt {
        self.get(i, DECODER_TRACE_OFFSET + IS_LOOP_BODY_FLAG_COL_IDX)
    }

    /// Returns the `is_loop` flag at row i.
    pub fn is_loop_flag(&self, i: RowIndex) -> Felt {
        self.get(i, DECODER_TRACE_OFFSET + IS_LOOP_FLAG_COL_IDX)
    }

    /// Returns the `is_call` flag at row i.
    pub fn is_call_flag(&self, i: RowIndex) -> Felt {
        self.get(i, DECODER_TRACE_OFFSET + IS_CALL_FLAG_COL_IDX)
    }

    /// Returns the `is_syscall` flag at row i.
    pub fn is_syscall_flag(&self, i: RowIndex) -> Felt {
        self.get(i, DECODER_TRACE_OFFSET + IS_SYSCALL_FLAG_COL_IDX)
    }

    /// Returns the operation batch flags at row i. This indicates the number of op groups in
    /// the current batch that is being processed.
    pub fn op_batch_flag(&self, i: RowIndex) -> [Felt; NUM_OP_BATCH_FLAGS] {
        [
            self.get(i, DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET),
            self.get(i, DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET + 1),
            self.get(i, DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET + 2),
        ]
    }

    /// Returns the operation group count. This indicates the number of operation that remain
    /// to be executed in the current span block.
    pub fn group_count(&self, i: RowIndex) -> Felt {
        self.get(i, DECODER_TRACE_OFFSET + GROUP_COUNT_COL_IDX)
    }

    /// Returns the delta between the current and next group counts.
    pub fn delta_group_count(&self, i: RowIndex) -> Felt {
        self.group_count(i) - self.group_count(i + 1)
    }

    /// Returns the `in_span` flag at row i.
    pub fn is_in_span(&self, i: RowIndex) -> Felt {
        self.get(i, DECODER_TRACE_OFFSET + IN_SPAN_COL_IDX)
    }

    /// Constructs the i-th op code value from its individual bits.
    pub fn get_op_code(&self, i: RowIndex) -> Felt {
        let b0 = self.get(i, DECODER_TRACE_OFFSET + 1);
        let b1 = self.get(i, DECODER_TRACE_OFFSET + 2);
        let b2 = self.get(i, DECODER_TRACE_OFFSET + 3);
        let b3 = self.get(i, DECODER_TRACE_OFFSET + 4);
        let b4 = self.get(i, DECODER_TRACE_OFFSET + 5);
        let b5 = self.get(i, DECODER_TRACE_OFFSET + 6);
        let b6 = self.get(i, DECODER_TRACE_OFFSET + 7);
        b0 + b1 * Felt::from_u64(2)
            + b2 * Felt::from_u64(4)
            + b3 * Felt::from_u64(8)
            + b4 * Felt::from_u64(16)
            + b5 * Felt::from_u64(32)
            + b6 * Felt::from_u64(64)
    }

    /// Returns an iterator of [`RowIndex`] values over the row indices of this trace.
    pub fn row_iter(&self) -> impl Iterator<Item = RowIndex> {
        (0..self.num_rows()).map(RowIndex::from)
    }

    /// Returns a flag indicating whether the current operation induces a left shift of the operand
    /// stack.
    pub fn is_left_shift(&self, i: RowIndex) -> bool {
        let b0 = self.get(i, DECODER_TRACE_OFFSET + 1);
        let b1 = self.get(i, DECODER_TRACE_OFFSET + 2);
        let b2 = self.get(i, DECODER_TRACE_OFFSET + 3);
        let b3 = self.get(i, DECODER_TRACE_OFFSET + 4);
        let b4 = self.get(i, DECODER_TRACE_OFFSET + 5);
        let b5 = self.get(i, DECODER_TRACE_OFFSET + 6);
        let b6 = self.get(i, DECODER_TRACE_OFFSET + 7);
        let e0 = self.get(i, DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET);
        let h5 = self.get(i, DECODER_TRACE_OFFSET + IS_LOOP_FLAG_COL_IDX);

        // group with left shift effect grouped by a common prefix
        ([b6, b5, b4] == [ZERO, ONE, ZERO])||
        // U32ADD3 or U32MADD
        ([b6, b5, b4, b3, b2] == [ONE, ZERO, ZERO, ONE, ONE]) ||
        // SPLIT or LOOP block
        ([e0, b3, b2, b1] == [ONE, ZERO, ONE, ZERO]) ||
        // REPEAT
        ([b6, b5, b4, b3, b2, b1, b0] == [ONE, ONE, ONE, ZERO, ONE, ZERO, ZERO]) ||
        // DYN
        ([b6, b5, b4, b3, b2, b1, b0] == [ONE, ZERO, ONE, ONE, ZERO, ZERO, ZERO]) ||
        // END of a loop
        ([b6, b5, b4, b3, b2, b1, b0] == [ONE, ONE, ONE, ZERO, ZERO, ZERO, ZERO] && h5 == ONE)
    }

    /// Returns a flag indicating whether the current operation induces a right shift of the operand
    /// stack.
    pub fn is_right_shift(&self, i: RowIndex) -> bool {
        let b0 = self.get(i, DECODER_TRACE_OFFSET + 1);
        let b1 = self.get(i, DECODER_TRACE_OFFSET + 2);
        let b2 = self.get(i, DECODER_TRACE_OFFSET + 3);
        let b3 = self.get(i, DECODER_TRACE_OFFSET + 4);
        let b4 = self.get(i, DECODER_TRACE_OFFSET + 5);
        let b5 = self.get(i, DECODER_TRACE_OFFSET + 6);
        let b6 = self.get(i, DECODER_TRACE_OFFSET + 7);

        // group with right shift effect grouped by a common prefix
        [b6, b5, b4] == [ZERO, ONE, ONE]||
        // u32SPLIT 100_1000
        ([b6, b5, b4, b3, b2, b1, b0] == [ONE, ZERO, ZERO, ONE, ZERO, ZERO, ZERO]) ||
        // PUSH i.e., 101_1011
        ([b6, b5, b4, b3, b2, b1, b0] == [ONE, ZERO, ONE, ONE, ZERO, ONE, ONE])
    }

    // STACK COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns the value of the stack depth column at row i.
    pub fn stack_depth(&self, i: RowIndex) -> Felt {
        self.get(i, STACK_TRACE_OFFSET + B0_COL_IDX)
    }

    /// Returns the element at row i in a given stack trace column.
    pub fn stack_element(&self, column: usize, i: RowIndex) -> Felt {
        self.get(i, STACK_TRACE_OFFSET + column)
    }

    /// Returns a word from the stack starting at `start` index at row i, in LE order.
    ///
    /// The word is read such that `word[0]` comes from stack position `start` (top),
    /// `word[1]` from `start + 1`, etc.
    pub fn stack_word(&self, start: usize, i: RowIndex) -> Word {
        Word::from([
            self.stack_element(start, i),
            self.stack_element(start + 1, i),
            self.stack_element(start + 2, i),
            self.stack_element(start + 3, i),
        ])
    }

    /// Returns the address of the top element in the stack overflow table at row i.
    pub fn parent_overflow_address(&self, i: RowIndex) -> Felt {
        self.get(i, STACK_TRACE_OFFSET + B1_COL_IDX)
    }

    /// Returns a flag indicating whether the overflow stack is non-empty.
    pub fn is_non_empty_overflow(&self, i: RowIndex) -> bool {
        let b0 = self.get(i, STACK_TRACE_OFFSET + B0_COL_IDX);
        let h0 = self.get(i, STACK_TRACE_OFFSET + H0_COL_IDX);
        (b0 - Felt::from_u64(16)) * h0 == ONE
    }

    // CHIPLETS COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns chiplet column number 0 at row i.
    pub fn chiplet_selector_0(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET)
    }

    /// Returns chiplet column number 1 at row i.
    pub fn chiplet_selector_1(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + 1)
    }

    /// Returns chiplet column number 2 at row i.
    pub fn chiplet_selector_2(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + 2)
    }

    /// Returns chiplet column number 3 at row i.
    pub fn chiplet_selector_3(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + 3)
    }

    /// Returns chiplet column number 4 at row i.
    pub fn chiplet_selector_4(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + 4)
    }

    /// Returns chiplet column number 5 at row i.
    pub fn chiplet_selector_5(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + 5)
    }

    /// Returns `true` if a row is part of the hash chiplet.
    pub fn is_hash_row(&self, i: RowIndex) -> bool {
        self.chiplet_selector_0(i) == ZERO
    }

    /// Returns the (full) state of the hasher chiplet at row i.
    pub fn chiplet_hasher_state(&self, i: RowIndex) -> [Felt; STATE_WIDTH] {
        let mut state = [ZERO; STATE_WIDTH];
        for (idx, col_idx) in HASHER_STATE_COL_RANGE.enumerate() {
            state[idx] = self.get(i, col_idx);
        }
        state
    }

    /// Returns the hasher's node index column at row i
    pub fn chiplet_node_index(&self, i: RowIndex) -> Felt {
        self.get(i, HASHER_NODE_INDEX_COL_IDX)
    }

    /// Returns `true` if a row is part of the bitwise chiplet.
    pub fn is_bitwise_row(&self, i: RowIndex) -> bool {
        self.chiplet_selector_0(i) == ONE && self.chiplet_selector_1(i) == ZERO
    }

    /// Returns the bitwise column holding the aggregated value of input `a` at row i.
    pub fn chiplet_bitwise_a(&self, i: RowIndex) -> Felt {
        self.get(i, BITWISE_A_COL_IDX)
    }

    /// Returns the bitwise column holding the aggregated value of input `b` at row i.
    pub fn chiplet_bitwise_b(&self, i: RowIndex) -> Felt {
        self.get(i, BITWISE_B_COL_IDX)
    }

    /// Returns the bitwise column holding the aggregated value of the output at row i.
    pub fn chiplet_bitwise_z(&self, i: RowIndex) -> Felt {
        self.get(i, BITWISE_OUTPUT_COL_IDX)
    }

    /// Returns `true` if a row is part of the memory chiplet.
    pub fn is_memory_row(&self, i: RowIndex) -> bool {
        self.chiplet_selector_0(i) == ONE
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ZERO
    }

    /// Returns the i-th row of the chiplet column containing memory context.
    pub fn chiplet_memory_ctx(&self, i: RowIndex) -> Felt {
        self.get(i, MEMORY_CTX_COL_IDX)
    }

    /// Returns the i-th row of the chiplet column containing memory address.
    pub fn chiplet_memory_word(&self, i: RowIndex) -> Felt {
        self.get(i, MEMORY_WORD_COL_IDX)
    }

    /// Returns the i-th row of the chiplet column containing 0th bit of the word index.
    pub fn chiplet_memory_idx0(&self, i: RowIndex) -> Felt {
        self.get(i, MEMORY_IDX0_COL_IDX)
    }

    /// Returns the i-th row of the chiplet column containing 1st bit of the word index.
    pub fn chiplet_memory_idx1(&self, i: RowIndex) -> Felt {
        self.get(i, MEMORY_IDX1_COL_IDX)
    }

    /// Returns the i-th row of the chiplet column containing clock cycle.
    pub fn chiplet_memory_clk(&self, i: RowIndex) -> Felt {
        self.get(i, MEMORY_CLK_COL_IDX)
    }

    /// Returns the i-th row of the chiplet column containing the zeroth memory value element.
    pub fn chiplet_memory_value_0(&self, i: RowIndex) -> Felt {
        self.get(i, MEMORY_V_COL_RANGE.start)
    }

    /// Returns the i-th row of the chiplet column containing the first memory value element.
    pub fn chiplet_memory_value_1(&self, i: RowIndex) -> Felt {
        self.get(i, MEMORY_V_COL_RANGE.start + 1)
    }

    /// Returns the i-th row of the chiplet column containing the second memory value element.
    pub fn chiplet_memory_value_2(&self, i: RowIndex) -> Felt {
        self.get(i, MEMORY_V_COL_RANGE.start + 2)
    }

    /// Returns the i-th row of the chiplet column containing the third memory value element.
    pub fn chiplet_memory_value_3(&self, i: RowIndex) -> Felt {
        self.get(i, MEMORY_V_COL_RANGE.start + 3)
    }

    /// Returns `true` if a row is part of the ACE chiplet.
    pub fn is_ace_row(&self, i: RowIndex) -> bool {
        self.chiplet_selector_0(i) == ONE
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ONE
            && self.chiplet_selector_3(i) == ZERO
    }

    pub fn chiplet_ace_start_selector(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + SELECTOR_START_IDX)
    }

    pub fn chiplet_ace_block_selector(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + SELECTOR_BLOCK_IDX)
    }

    pub fn chiplet_ace_ctx(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + CTX_IDX)
    }

    pub fn chiplet_ace_ptr(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + PTR_IDX)
    }

    pub fn chiplet_ace_clk(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + CLK_IDX)
    }

    pub fn chiplet_ace_eval_op(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + EVAL_OP_IDX)
    }

    pub fn chiplet_ace_num_eval_rows(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + READ_NUM_EVAL_IDX)
    }

    pub fn chiplet_ace_id_0(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + ID_0_IDX)
    }

    pub fn chiplet_ace_v_0_0(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_0_0_IDX)
    }

    pub fn chiplet_ace_v_0_1(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_0_1_IDX)
    }

    pub fn chiplet_ace_wire_0(&self, i: RowIndex) -> [Felt; 3] {
        let id_0 = self.chiplet_ace_id_0(i);
        let v_0_0 = self.chiplet_ace_v_0_0(i);
        let v_0_1 = self.chiplet_ace_v_0_1(i);

        [id_0, v_0_0, v_0_1]
    }

    pub fn chiplet_ace_id_1(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + ID_1_IDX)
    }

    pub fn chiplet_ace_v_1_0(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_1_0_IDX)
    }

    pub fn chiplet_ace_v_1_1(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_1_1_IDX)
    }

    pub fn chiplet_ace_wire_1(&self, i: RowIndex) -> [Felt; 3] {
        let id_1 = self.chiplet_ace_id_1(i);
        let v_1_0 = self.chiplet_ace_v_1_0(i);
        let v_1_1 = self.chiplet_ace_v_1_1(i);

        [id_1, v_1_0, v_1_1]
    }

    pub fn chiplet_ace_id_2(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + ID_2_IDX)
    }

    pub fn chiplet_ace_v_2_0(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_2_0_IDX)
    }

    pub fn chiplet_ace_v_2_1(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_2_1_IDX)
    }

    pub fn chiplet_ace_wire_2(&self, i: RowIndex) -> [Felt; 3] {
        let id_2 = self.chiplet_ace_id_2(i);
        let v_2_0 = self.chiplet_ace_v_2_0(i);
        let v_2_1 = self.chiplet_ace_v_2_1(i);

        [id_2, v_2_0, v_2_1]
    }

    pub fn chiplet_ace_m_1(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + M_1_IDX)
    }

    pub fn chiplet_ace_m_0(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + NUM_ACE_SELECTORS + M_0_IDX)
    }

    pub fn chiplet_ace_is_read_row(&self, i: RowIndex) -> bool {
        self.is_ace_row(i) && self.chiplet_ace_block_selector(i) == ZERO
    }

    pub fn chiplet_ace_is_eval_row(&self, i: RowIndex) -> bool {
        self.is_ace_row(i) && self.chiplet_ace_block_selector(i) == ONE
    }

    /// Returns `true` if a row is part of the kernel chiplet.
    pub fn is_kernel_row(&self, i: RowIndex) -> bool {
        self.chiplet_selector_0(i) == ONE
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ONE
            && self.chiplet_selector_3(i) == ONE
            && self.chiplet_selector_4(i) == ZERO
    }

    /// Returns true when the i-th row of the `s_first` column in the kernel chiplet is one, i.e.,
    /// when this is the first row in a range of rows containing the same kernel proc hash.
    pub fn chiplet_kernel_is_first_hash_row(&self, i: RowIndex) -> bool {
        self.get(i, CHIPLETS_OFFSET + 5) == ONE
    }

    /// Returns the i-th row of the chiplet column containing the zeroth element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_0(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + 6)
    }

    /// Returns the i-th row of the chiplet column containing the first element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_1(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + 7)
    }

    /// Returns the i-th row of the chiplet column containing the second element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_2(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + 8)
    }

    /// Returns the i-th row of the chiplet column containing the third element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_3(&self, i: RowIndex) -> Felt {
        self.get(i, CHIPLETS_OFFSET + 9)
    }

    //  MERKLE PATH HASHING SELECTORS
    // --------------------------------------------------------------------------------------------

    /// Returns `true` if the hasher chiplet flags indicate the initialization of verifying
    /// a Merkle path to an old node during Merkle root update procedure (MRUPDATE).
    pub fn f_mv(&self, i: RowIndex) -> bool {
        i.as_usize().is_multiple_of(HASH_CYCLE_LEN)
            && self.chiplet_selector_0(i) == ZERO
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ONE
            && self.chiplet_selector_3(i) == ZERO
    }

    /// Returns `true` if the hasher chiplet flags indicate the continuation of verifying
    /// a Merkle path to an old node during Merkle root update procedure (MRUPDATE).
    pub fn f_mva(&self, i: RowIndex) -> bool {
        (i.as_usize() % HASH_CYCLE_LEN == LAST_CYCLE_ROW)
            && self.chiplet_selector_0(i) == ZERO
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ONE
            && self.chiplet_selector_3(i) == ZERO
    }

    /// Returns `true` if the hasher chiplet flags indicate the initialization of verifying
    /// a Merkle path to a new node during Merkle root update procedure (MRUPDATE).
    pub fn f_mu(&self, i: RowIndex) -> bool {
        i.as_usize().is_multiple_of(HASH_CYCLE_LEN)
            && self.chiplet_selector_0(i) == ZERO
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ONE
            && self.chiplet_selector_3(i) == ONE
    }

    /// Returns `true` if the hasher chiplet flags indicate the continuation of verifying
    /// a Merkle path to a new node during Merkle root update procedure (MRUPDATE).
    pub fn f_mua(&self, i: RowIndex) -> bool {
        (i.as_usize() % HASH_CYCLE_LEN == LAST_CYCLE_ROW)
            && self.chiplet_selector_0(i) == ZERO
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ONE
            && self.chiplet_selector_3(i) == ONE
    }
}
