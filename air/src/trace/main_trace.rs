use alloc::vec::Vec;
use core::borrow::{Borrow, BorrowMut};
#[cfg(any(test, feature = "testing"))]
use core::ops::Range;

use miden_core::{
    Felt, ONE, Word, ZERO,
    field::PrimeCharacteristicRing,
    utils::{Matrix, RowMajorMatrix},
};

use super::{
    CHIPLETS_WIDTH, RowIndex, TRACE_WIDTH,
    chiplets::hasher::{DIGEST_LEN, STATE_WIDTH},
    decoder::{NUM_HASHER_COLUMNS, NUM_OP_BATCH_FLAGS},
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
        let core_rows = core_rm.len() / CORE_STORAGE_WIDTH;
        let chiplets_rows = chiplets_rm.len() / CHIPLETS_WIDTH;
        assert!(core_rows.is_power_of_two(), "core height must be a power of two");
        assert!(chiplets_rows.is_power_of_two(), "chiplets height must be a power of two");
        Self {
            storage: TraceStorage {
                core_rm: RowMajorMatrix::new(core_rm, CORE_STORAGE_WIDTH),
                chiplets_rm: RowMajorMatrix::new(chiplets_rm, CHIPLETS_WIDTH),
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
    /// use one of the per-chiplet overlays (`.controller()`, `.permutation()`, `.bitwise()`,
    /// `.memory()`, `.ace()`, `.kernel_rom()`) to name the physical columns according to
    /// the chiplet active on that row.
    ///
    /// # Panics
    /// Panics if `i` is past the chiplets trace height — see [`Self::chiplets_height`]. The
    /// four `is_*_row` classifiers short-circuit past the chiplets height, so they can be
    /// used as bound-aware filters when iterating the unified trace.
    #[inline]
    pub fn chiplet_cols(&self, i: RowIndex) -> &ChipletCols<Felt> {
        let (rows, _) = self.storage.chiplets_rm.values.as_chunks::<NUM_CHIPLETS_COLS>();
        rows[i.as_usize()].as_slice().borrow()
    }

    /// Splits the trace into the per-AIR `(Core, Chiplets)` matrix pair used by the multi-AIR
    /// proving path.
    pub fn to_core_chiplets_matrices(&self) -> (RowMajorMatrix<Felt>, RowMajorMatrix<Felt>) {
        // Each buffer is already stored at exactly its per-AIR height.
        (self.storage.core_rm.clone(), self.storage.chiplets_rm.clone())
    }

    /// Like [`Self::to_core_chiplets_matrices`], but consumes the trace and moves buffers.
    pub fn into_core_chiplets_matrices(self) -> (RowMajorMatrix<Felt>, RowMajorMatrix<Felt>) {
        (self.storage.core_rm, self.storage.chiplets_rm)
    }

    /// Returns the larger of the two per-AIR heights.
    pub fn num_rows(&self) -> usize {
        self.core_height().max(self.chiplets_height())
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

    // SYSTEM COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns the value of the clk column at row i.
    pub fn clk(&self, i: RowIndex) -> Felt {
        self.core_row(i).system.clk
    }

    /// Returns the value of the ctx column at row i.
    pub fn ctx(&self, i: RowIndex) -> Felt {
        self.core_row(i).system.ctx
    }

    // DECODER COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns the value in the block address column at the row i.
    pub fn addr(&self, i: RowIndex) -> Felt {
        self.core_row(i).decoder.addr
    }

    /// Helper method to detect change of address.
    pub fn is_addr_change(&self, i: RowIndex) -> bool {
        self.addr(i) != self.addr(i + 1)
    }

    /// The i-th decoder helper register at `row`.
    pub fn helper_register(&self, i: usize, row: RowIndex) -> Felt {
        self.core_row(row).decoder.user_op_helpers()[i]
    }

    /// Returns the hasher state at row i.
    pub fn decoder_hasher_state(&self, i: RowIndex) -> [Felt; NUM_HASHER_COLUMNS] {
        self.core_row(i).decoder.hasher_state
    }

    /// Returns the first half of the hasher state at row i.
    pub fn decoder_hasher_state_first_half(&self, i: RowIndex) -> Word {
        let hs = &self.core_row(i).decoder.hasher_state;
        Word::from([hs[0], hs[1], hs[2], hs[3]])
    }

    /// Returns the second half of the hasher state at row i.
    pub fn decoder_hasher_state_second_half(&self, i: RowIndex) -> Word {
        let hs = &self.core_row(i).decoder.hasher_state;
        Word::from([hs[4], hs[5], hs[6], hs[7]])
    }

    /// Returns a specific element from the hasher state at row i.
    pub fn decoder_hasher_state_element(&self, element: usize, i: RowIndex) -> Felt {
        self.core_row(i).decoder.hasher_state[element]
    }

    /// Returns the current function hash (i.e., root) at row i.
    pub fn fn_hash(&self, i: RowIndex) -> [Felt; DIGEST_LEN] {
        self.core_row(i).system.fn_hash
    }

    /// Returns the `is_loop_body` flag at row i.
    pub fn is_loop_body_flag(&self, i: RowIndex) -> Felt {
        self.core_row(i).decoder.end_block_flags().is_loop_body
    }

    /// Returns the `is_loop` flag at row i.
    pub fn is_loop_flag(&self, i: RowIndex) -> Felt {
        self.core_row(i).decoder.end_block_flags().is_loop
    }

    /// Returns the `is_call` flag at row i.
    pub fn is_call_flag(&self, i: RowIndex) -> Felt {
        self.core_row(i).decoder.end_block_flags().is_call
    }

    /// Returns the `is_syscall` flag at row i.
    pub fn is_syscall_flag(&self, i: RowIndex) -> Felt {
        self.core_row(i).decoder.end_block_flags().is_syscall
    }

    /// Returns the operation batch flags at row i. This indicates the number of op groups in
    /// the current batch that is being processed.
    pub fn op_batch_flag(&self, i: RowIndex) -> [Felt; NUM_OP_BATCH_FLAGS] {
        self.core_row(i).decoder.batch_flags
    }

    /// Returns the operation group count. This indicates the number of operation that remain
    /// to be executed in the current span block.
    pub fn group_count(&self, i: RowIndex) -> Felt {
        self.core_row(i).decoder.group_count
    }

    /// Returns the delta between the current and next group counts.
    pub fn delta_group_count(&self, i: RowIndex) -> Felt {
        self.group_count(i) - self.group_count(i + 1)
    }

    /// Returns the `in_span` flag at row i.
    pub fn is_in_span(&self, i: RowIndex) -> Felt {
        self.core_row(i).decoder.in_span
    }

    /// Constructs the i-th op code value from its individual bits.
    pub fn get_op_code(&self, i: RowIndex) -> Felt {
        let bits = &self.core_row(i).decoder.op_bits;
        bits[0]
            + bits[1] * Felt::from_u64(2)
            + bits[2] * Felt::from_u64(4)
            + bits[3] * Felt::from_u64(8)
            + bits[4] * Felt::from_u64(16)
            + bits[5] * Felt::from_u64(32)
            + bits[6] * Felt::from_u64(64)
    }

    /// Returns a flag indicating whether the current operation induces a left shift of the operand
    /// stack.
    pub fn is_left_shift(&self, i: RowIndex) -> bool {
        let decoder = &self.core_row(i).decoder;
        let bits = &decoder.op_bits;
        let b0 = bits[0];
        let b1 = bits[1];
        let b2 = bits[2];
        let b3 = bits[3];
        let b4 = bits[4];
        let b5 = bits[5];
        let b6 = bits[6];
        let e0 = decoder.extra[0];
        let h5 = decoder.end_block_flags().is_loop;

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
        let bits = &self.core_row(i).decoder.op_bits;
        let b0 = bits[0];
        let b1 = bits[1];
        let b2 = bits[2];
        let b3 = bits[3];
        let b4 = bits[4];
        let b5 = bits[5];
        let b6 = bits[6];

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
        self.core_row(i).stack.b0
    }

    /// Returns the element at row i in a given stack trace column.
    pub fn stack_element(&self, column: usize, i: RowIndex) -> Felt {
        self.core_row(i).stack.get(column)
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
        self.core_row(i).stack.b1
    }

    /// Returns a flag indicating whether the overflow stack is non-empty.
    pub fn is_non_empty_overflow(&self, i: RowIndex) -> bool {
        let stack = &self.core_row(i).stack;
        (stack.b0 - Felt::from_u64(16)) * stack.h0 == ONE
    }

    // CHIPLETS COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns chiplet column number 0 at row i.
    ///
    /// # Panics
    /// Panics if `i` is past the chiplets-AIR height. Callers iterating the unified trace
    /// must guard via [`Self::chiplets_height`] or filter via [`Self::is_hash_row`] /
    /// [`Self::is_bitwise_row`] / [`Self::is_memory_row`] / [`Self::is_ace_row`], which
    /// short-circuit past the chiplets height.
    pub fn chiplet_selector_0(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).s_01
    }

    /// Returns chiplet column number 1 at row i. See [`Self::chiplet_selector_0`] for bounds.
    pub fn chiplet_selector_1(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).chiplets[0]
    }

    /// Returns chiplet column number 2 at row i. See [`Self::chiplet_selector_0`] for bounds.
    pub fn chiplet_selector_2(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).chiplets[1]
    }

    /// Returns chiplet column number 3 at row i. See [`Self::chiplet_selector_0`] for bounds.
    pub fn chiplet_selector_3(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).chiplets[2]
    }

    /// Returns chiplet column number 4 at row i. See [`Self::chiplet_selector_0`] for bounds.
    pub fn chiplet_selector_4(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).chiplets[3]
    }

    /// Returns chiplet column number 5 at row i. See [`Self::chiplet_selector_0`] for bounds.
    pub fn chiplet_selector_5(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).chiplets[4]
    }

    /// Returns `true` if a row is part of the hash chiplet (controller or permutation).
    ///
    /// Short-circuits to `false` past the chiplets-AIR height — rows past `chiplets_height()`
    /// are not part of any chiplet by definition in the split-trace model.
    pub fn is_hash_row(&self, i: RowIndex) -> bool {
        if i.as_usize() >= self.chiplets_height() {
            return false;
        }
        self.chiplet_selector_0(i) == ONE || self.chiplet_s_perm(i) == ONE
    }

    /// Returns the (full) state of the hasher chiplet at row i.
    pub fn chiplet_hasher_state(&self, i: RowIndex) -> [Felt; STATE_WIDTH] {
        self.chiplet_cols(i).controller().state
    }

    /// Returns the hasher's node index column at row i
    pub fn chiplet_node_index(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).controller().node_index
    }

    /// Returns the hasher's mrupdate_id column at row i (domain separator for sibling table).
    pub fn chiplet_mrupdate_id(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).controller().mrupdate_id
    }

    /// Returns the hasher's is_boundary column at row i (1 on boundary rows: first input or last
    /// output of an operation).
    pub fn chiplet_is_boundary(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).controller().is_boundary
    }

    /// Returns the hasher's direction_bit column at row i. On Merkle controller rows this holds
    /// the direction bit extracted from the node index; zero on non-Merkle and perm segment rows.
    pub fn chiplet_direction_bit(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).controller().direction_bit
    }

    /// Returns the hasher's s_00 column at row i (0=controller, 1=permutation segment).
    ///
    /// # Panics
    /// Panics if `i` is past the chiplets-AIR height. See [`Self::chiplet_selector_0`] for
    /// the contract that the four `is_*_row` classifiers short-circuit past the chiplets
    /// height, so they can be used as bound-aware filters.
    pub fn chiplet_s_perm(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).s_00
    }

    /// Returns the memory's word address low 16-bit limb at row i.
    pub fn chiplet_memory_word_addr_lo(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).memory_word_addr_lo()
    }

    /// Returns the memory's word address high 16-bit limb at row i.
    pub fn chiplet_memory_word_addr_hi(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).memory_word_addr_hi()
    }

    /// Returns `true` if a row is part of the bitwise chiplet.
    /// Active when virtual s0=1 (s_ctrl=0, s_perm=0) and s1=0.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height so the classifier is safe to
    /// call on any row of the unified trace.
    pub fn is_bitwise_row(&self, i: RowIndex) -> bool {
        if i.as_usize() >= self.chiplets_height() {
            return false;
        }
        self.chiplet_selector_0(i) == ZERO
            && self.chiplet_s_perm(i) == ZERO
            && self.chiplet_selector_1(i) == ZERO
    }

    /// Returns the bitwise column holding the aggregated value of input `a` at row i.
    pub fn chiplet_bitwise_a(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).bitwise().a
    }

    /// Returns the bitwise column holding the aggregated value of input `b` at row i.
    pub fn chiplet_bitwise_b(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).bitwise().b
    }

    /// Returns the bitwise column holding the aggregated value of the output at row i.
    pub fn chiplet_bitwise_z(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).bitwise().output
    }

    /// Returns `true` if a row is part of the memory chiplet.
    /// Active when virtual s0=1 (s_ctrl=0, s_perm=0) and s1=1, s2=0.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; see [`Self::is_bitwise_row`].
    pub fn is_memory_row(&self, i: RowIndex) -> bool {
        if i.as_usize() >= self.chiplets_height() {
            return false;
        }
        self.chiplet_selector_0(i) == ZERO
            && self.chiplet_s_perm(i) == ZERO
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ZERO
    }

    /// Returns the i-th row of the chiplet column containing memory context.
    pub fn chiplet_memory_ctx(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).memory().ctx
    }

    /// Returns the i-th row of the chiplet column containing memory address.
    pub fn chiplet_memory_word(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).memory().word_addr
    }

    /// Returns the i-th row of the chiplet column containing 0th bit of the word index.
    pub fn chiplet_memory_idx0(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).memory().idx0
    }

    /// Returns the i-th row of the chiplet column containing 1st bit of the word index.
    pub fn chiplet_memory_idx1(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).memory().idx1
    }

    /// Returns the i-th row of the chiplet column containing clock cycle.
    pub fn chiplet_memory_clk(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).memory().clk
    }

    /// Returns the i-th row of the chiplet column containing the zeroth memory value element.
    pub fn chiplet_memory_value_0(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).memory().values[0]
    }

    /// Returns the i-th row of the chiplet column containing the first memory value element.
    pub fn chiplet_memory_value_1(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).memory().values[1]
    }

    /// Returns the i-th row of the chiplet column containing the second memory value element.
    pub fn chiplet_memory_value_2(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).memory().values[2]
    }

    /// Returns the i-th row of the chiplet column containing the third memory value element.
    pub fn chiplet_memory_value_3(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).memory().values[3]
    }

    /// Returns `true` if a row is part of the ACE chiplet.
    /// Active when virtual s0=1 (s_ctrl=0, s_perm=0) and s1=1, s2=1, s3=0.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; see [`Self::is_bitwise_row`].
    pub fn is_ace_row(&self, i: RowIndex) -> bool {
        if i.as_usize() >= self.chiplets_height() {
            return false;
        }
        self.chiplet_selector_0(i) == ZERO
            && self.chiplet_s_perm(i) == ZERO
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ONE
            && self.chiplet_selector_3(i) == ZERO
    }

    pub fn chiplet_ace_start_selector(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().s_start
    }

    pub fn chiplet_ace_block_selector(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().s_block
    }

    pub fn chiplet_ace_ctx(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().ctx
    }

    pub fn chiplet_ace_ptr(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().ptr
    }

    pub fn chiplet_ace_clk(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().clk
    }

    pub fn chiplet_ace_eval_op(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().eval_op
    }

    pub fn chiplet_ace_num_eval_rows(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().read().num_eval
    }

    pub fn chiplet_ace_id_0(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().id_0
    }

    pub fn chiplet_ace_v_0_0(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().v_0.0
    }

    pub fn chiplet_ace_v_0_1(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().v_0.1
    }

    pub fn chiplet_ace_wire_0(&self, i: RowIndex) -> [Felt; 3] {
        let id_0 = self.chiplet_ace_id_0(i);
        let v_0_0 = self.chiplet_ace_v_0_0(i);
        let v_0_1 = self.chiplet_ace_v_0_1(i);

        [id_0, v_0_0, v_0_1]
    }

    pub fn chiplet_ace_id_1(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().id_1
    }

    pub fn chiplet_ace_v_1_0(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().v_1.0
    }

    pub fn chiplet_ace_v_1_1(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().v_1.1
    }

    pub fn chiplet_ace_wire_1(&self, i: RowIndex) -> [Felt; 3] {
        let id_1 = self.chiplet_ace_id_1(i);
        let v_1_0 = self.chiplet_ace_v_1_0(i);
        let v_1_1 = self.chiplet_ace_v_1_1(i);

        [id_1, v_1_0, v_1_1]
    }

    pub fn chiplet_ace_id_2(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().eval().id_2
    }

    pub fn chiplet_ace_v_2_0(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().eval().v_2.0
    }

    pub fn chiplet_ace_v_2_1(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().eval().v_2.1
    }

    pub fn chiplet_ace_wire_2(&self, i: RowIndex) -> [Felt; 3] {
        let id_2 = self.chiplet_ace_id_2(i);
        let v_2_0 = self.chiplet_ace_v_2_0(i);
        let v_2_1 = self.chiplet_ace_v_2_1(i);

        [id_2, v_2_0, v_2_1]
    }

    pub fn chiplet_ace_m_1(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().read().m_1
    }

    pub fn chiplet_ace_m_0(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).ace().read().m_0
    }

    pub fn chiplet_ace_is_read_row(&self, i: RowIndex) -> bool {
        self.is_ace_row(i) && self.chiplet_ace_block_selector(i) == ZERO
    }

    pub fn chiplet_ace_is_eval_row(&self, i: RowIndex) -> bool {
        self.is_ace_row(i) && self.chiplet_ace_block_selector(i) == ONE
    }

    /// Returns `true` if a row is part of the kernel chiplet.
    /// Active when virtual s0=1 (s_ctrl=0, s_perm=0) and s1=1, s2=1, s3=1, s4=0.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; see [`Self::is_bitwise_row`].
    pub fn is_kernel_row(&self, i: RowIndex) -> bool {
        if i.as_usize() >= self.chiplets_height() {
            return false;
        }
        self.chiplet_selector_0(i) == ZERO
            && self.chiplet_s_perm(i) == ZERO
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ONE
            && self.chiplet_selector_3(i) == ONE
            && self.chiplet_selector_4(i) == ZERO
    }

    /// Returns true when the i-th row of the `s_first` column in the kernel chiplet is one, i.e.,
    /// when this is the first row in a range of rows containing the same kernel proc hash.
    pub fn chiplet_kernel_is_first_hash_row(&self, i: RowIndex) -> bool {
        self.chiplet_cols(i).kernel_rom().multiplicity == ONE
    }

    /// Returns the i-th row of the chiplet column containing the zeroth element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_0(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).kernel_rom().root[0]
    }

    /// Returns the i-th row of the chiplet column containing the first element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_1(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).kernel_rom().root[1]
    }

    /// Returns the i-th row of the chiplet column containing the second element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_2(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).kernel_rom().root[2]
    }

    /// Returns the i-th row of the chiplet column containing the third element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_3(&self, i: RowIndex) -> Felt {
        self.chiplet_cols(i).kernel_rom().root[3]
    }

    // MERKLE ROOT UPDATE SELECTORS
    // --------------------------------------------------------------------------------------------
    //
    // The MRUPDATE operation has two legs, each traversing the same Merkle path:
    //   - MV (Merkle Verify old path): inserts siblings into the sibling table
    //   - MU (Merkle Update new path): removes siblings from the sibling table
    //
    // MPVERIFY (read-only path verification) does not interact with the sibling table.

    /// Returns `true` if row `i` is an MR_UPDATE_OLD (Merkle Verify) hasher controller input row.
    ///
    /// These rows appear during the old-path leg of a Merkle root update (MRUPDATE). Each
    /// MV input row inserts a sibling into the virtual sibling table via the hash_kernel bus.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; see [`Self::is_bitwise_row`].
    pub fn f_mv(&self, i: RowIndex) -> bool {
        if i.as_usize() >= self.chiplets_height() {
            return false;
        }
        self.chiplet_selector_0(i) == ONE         // s_ctrl=1 (controller row)
            && self.chiplet_s_perm(i) == ZERO   // controller region
            && self.chiplet_selector_1(i) == ONE  // s0=1 (input row)
            && self.chiplet_selector_2(i) == ONE  // s1=1 (MR_UPDATE_OLD)
            && self.chiplet_selector_3(i) == ZERO // s2=0
    }

    /// Returns `true` if row `i` is an MR_UPDATE_NEW (Merkle Update) hasher controller input row.
    ///
    /// These rows appear during the new-path leg of a Merkle root update (MRUPDATE). Each
    /// MU input row removes a sibling from the virtual sibling table via the hash_kernel bus.
    /// The sibling table balance ensures the old and new paths use the same siblings.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; see [`Self::is_bitwise_row`].
    pub fn f_mu(&self, i: RowIndex) -> bool {
        if i.as_usize() >= self.chiplets_height() {
            return false;
        }
        self.chiplet_selector_0(i) == ONE         // s_ctrl=1 (controller row)
            && self.chiplet_s_perm(i) == ZERO   // controller region
            && self.chiplet_selector_1(i) == ONE  // s0=1 (input row)
            && self.chiplet_selector_2(i) == ONE  // s1=1 (MR_UPDATE_NEW)
            && self.chiplet_selector_3(i) == ONE // s2=1
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

        for row in 0..num_rows {
            for col in 0..CORE_STORAGE_WIDTH {
                core_rm.push(Felt::from_u32((row * TRACE_WIDTH + col) as u32));
            }
            for c in 0..CHIPLETS_WIDTH {
                chiplets_rm
                    .push(Felt::from_u32((row * TRACE_WIDTH + CORE_STORAGE_WIDTH + c) as u32));
            }
        }

        MainTrace::from_parts(core_rm, chiplets_rm, RowIndex::from(0))
    }

    #[test]
    fn into_split_matches_borrowed_split() {
        const NUM_ROWS: usize = 8;
        let (ref_core, ref_chip) = deterministic_parts_trace(NUM_ROWS).to_core_chiplets_matrices();
        let (moved_core, moved_chip) =
            deterministic_parts_trace(NUM_ROWS).into_core_chiplets_matrices();

        assert_eq!(ref_core.width(), moved_core.width());
        assert_eq!(ref_chip.width(), moved_chip.width());
        assert_eq!(ref_core.values, moved_core.values);
        assert_eq!(ref_chip.values, moved_chip.values);
    }
}
