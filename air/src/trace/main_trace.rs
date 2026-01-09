#[cfg(any(test, feature = "testing"))]
use alloc::vec::Vec;
use core::{
    borrow::{Borrow, BorrowMut},
    ops::{Deref, Range},
};

use miden_core::{
    Felt, ONE, WORD_SIZE, Word, ZERO,
    field::PrimeCharacteristicRing,
    utils::{ColMatrix, range},
};

use super::{
    CHIPLETS_OFFSET, CHIPLETS_WIDTH, CLK_COL_IDX, CTX_COL_IDX, DECODER_TRACE_OFFSET,
    DECODER_TRACE_WIDTH, FN_HASH_OFFSET, RANGE_CHECK_TRACE_WIDTH, RowIndex, STACK_TRACE_OFFSET,
    STACK_TRACE_WIDTH,
    chiplets::{
        BITWISE_A_COL_IDX, BITWISE_B_COL_IDX, BITWISE_OUTPUT_COL_IDX, HASHER_NODE_INDEX_COL_IDX,
        HASHER_STATE_COL_RANGE, MEMORY_CLK_COL_IDX, MEMORY_CTX_COL_IDX, MEMORY_IDX0_COL_IDX,
        MEMORY_IDX1_COL_IDX, MEMORY_V_COL_RANGE, MEMORY_WORD_COL_IDX, NUM_ACE_SELECTORS,
        ace::{
            CLK_IDX, CTX_IDX, EVAL_OP_IDX, ID_0_IDX, ID_1_IDX, ID_2_IDX, M_0_IDX, M_1_IDX, PTR_IDX,
            READ_NUM_EVAL_IDX, SELECTOR_BLOCK_IDX, SELECTOR_START_IDX, V_0_0_IDX, V_0_1_IDX,
            V_1_0_IDX, V_1_1_IDX, V_2_0_IDX, V_2_1_IDX,
        },
        hasher::{DIGEST_LEN, HASH_CYCLE_LEN, STATE_WIDTH},
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

#[derive(Debug)]
pub struct MainTrace {
    columns: ColMatrix<Felt>,
    last_program_row: RowIndex,
}

impl Deref for MainTrace {
    type Target = ColMatrix<Felt>;

    fn deref(&self) -> &Self::Target {
        &self.columns
    }
}

impl MainTrace {
    pub fn new(main_trace: ColMatrix<Felt>, last_program_row: RowIndex) -> Self {
        Self { columns: main_trace, last_program_row }
    }

    pub fn num_rows(&self) -> usize {
        self.columns.num_rows()
    }

    pub fn last_program_row(&self) -> RowIndex {
        self.last_program_row
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn get_column_range(&self, range: Range<usize>) -> Vec<Vec<Felt>> {
        range.fold(vec![], |mut acc, col_idx| {
            acc.push(self.get_column(col_idx).to_vec());
            acc
        })
    }

    // SYSTEM COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns the value of the clk column at row i.
    pub fn clk(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CLK_COL_IDX)[i]
    }

    /// Returns the value of the ctx column at row i.
    pub fn ctx(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CTX_COL_IDX)[i]
    }

    // DECODER COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns the value in the block address column at the row i.
    pub fn addr(&self, i: RowIndex) -> Felt {
        self.columns.get_column(DECODER_TRACE_OFFSET)[i]
    }

    /// Helper method to detect change of address.
    pub fn is_addr_change(&self, i: RowIndex) -> bool {
        self.addr(i) != self.addr(i + 1)
    }

    /// The i-th decoder helper register at `row`.
    pub fn helper_register(&self, i: usize, row: RowIndex) -> Felt {
        self.columns.get_column(DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + i)[row]
    }

    /// Returns the hasher state at row i.
    pub fn decoder_hasher_state(&self, i: RowIndex) -> [Felt; NUM_HASHER_COLUMNS] {
        let mut state = [ZERO; NUM_HASHER_COLUMNS];
        for (idx, col_idx) in DECODER_HASHER_RANGE.enumerate() {
            let column = self.columns.get_column(col_idx);
            state[idx] = column[i];
        }
        state
    }

    /// Returns the first half of the hasher state at row i.
    pub fn decoder_hasher_state_first_half(&self, i: RowIndex) -> Word {
        let mut state = [ZERO; DIGEST_LEN];
        for (col, s) in state.iter_mut().enumerate() {
            *s = self.columns.get_column(DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + col)[i];
        }
        state.into()
    }

    /// Returns the second half of the hasher state at row i.
    pub fn decoder_hasher_state_second_half(&self, i: RowIndex) -> Word {
        const SECOND_WORD_OFFSET: usize = 4;
        let mut state = [ZERO; DIGEST_LEN];
        for (col, s) in state.iter_mut().enumerate() {
            *s = self
                .columns
                .get_column(DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + SECOND_WORD_OFFSET + col)
                [i];
        }
        state.into()
    }

    /// Returns a specific element from the hasher state at row i.
    pub fn decoder_hasher_state_element(&self, element: usize, i: RowIndex) -> Felt {
        self.columns.get_column(DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + element)[i]
    }

    /// Returns the current function hash (i.e., root) at row i.
    pub fn fn_hash(&self, i: RowIndex) -> [Felt; DIGEST_LEN] {
        let mut state = [ZERO; DIGEST_LEN];
        for (col, s) in state.iter_mut().enumerate() {
            *s = self.columns.get_column(FN_HASH_OFFSET + col)[i];
        }
        state
    }

    /// Returns the `is_loop_body` flag at row i.
    pub fn is_loop_body_flag(&self, i: RowIndex) -> Felt {
        self.columns.get_column(DECODER_TRACE_OFFSET + IS_LOOP_BODY_FLAG_COL_IDX)[i]
    }

    /// Returns the `is_loop` flag at row i.
    pub fn is_loop_flag(&self, i: RowIndex) -> Felt {
        self.columns.get_column(DECODER_TRACE_OFFSET + IS_LOOP_FLAG_COL_IDX)[i]
    }

    /// Returns the `is_call` flag at row i.
    pub fn is_call_flag(&self, i: RowIndex) -> Felt {
        self.columns.get_column(DECODER_TRACE_OFFSET + IS_CALL_FLAG_COL_IDX)[i]
    }

    /// Returns the `is_syscall` flag at row i.
    pub fn is_syscall_flag(&self, i: RowIndex) -> Felt {
        self.columns.get_column(DECODER_TRACE_OFFSET + IS_SYSCALL_FLAG_COL_IDX)[i]
    }

    /// Returns the operation batch flags at row i. This indicates the number of op groups in
    /// the current batch that is being processed.
    pub fn op_batch_flag(&self, i: RowIndex) -> [Felt; NUM_OP_BATCH_FLAGS] {
        [
            self.columns.get(DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET, i.into()),
            self.columns.get(DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET + 1, i.into()),
            self.columns.get(DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET + 2, i.into()),
        ]
    }

    /// Returns the operation group count. This indicates the number of operation that remain
    /// to be executed in the current span block.
    pub fn group_count(&self, i: RowIndex) -> Felt {
        self.columns.get_column(DECODER_TRACE_OFFSET + GROUP_COUNT_COL_IDX)[i]
    }

    /// Returns the delta between the current and next group counts.
    pub fn delta_group_count(&self, i: RowIndex) -> Felt {
        self.group_count(i) - self.group_count(i + 1)
    }

    /// Returns the `in_span` flag at row i.
    pub fn is_in_span(&self, i: RowIndex) -> Felt {
        self.columns.get_column(DECODER_TRACE_OFFSET + IN_SPAN_COL_IDX)[i]
    }

    /// Constructs the i-th op code value from its individual bits.
    pub fn get_op_code(&self, i: RowIndex) -> Felt {
        let col_b0 = self.columns.get_column(DECODER_TRACE_OFFSET + 1);
        let col_b1 = self.columns.get_column(DECODER_TRACE_OFFSET + 2);
        let col_b2 = self.columns.get_column(DECODER_TRACE_OFFSET + 3);
        let col_b3 = self.columns.get_column(DECODER_TRACE_OFFSET + 4);
        let col_b4 = self.columns.get_column(DECODER_TRACE_OFFSET + 5);
        let col_b5 = self.columns.get_column(DECODER_TRACE_OFFSET + 6);
        let col_b6 = self.columns.get_column(DECODER_TRACE_OFFSET + 7);
        let [b0, b1, b2, b3, b4, b5, b6] =
            [col_b0[i], col_b1[i], col_b2[i], col_b3[i], col_b4[i], col_b5[i], col_b6[i]];
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
        let b0 = self.columns.get(DECODER_TRACE_OFFSET + 1, i.into());
        let b1 = self.columns.get(DECODER_TRACE_OFFSET + 2, i.into());
        let b2 = self.columns.get(DECODER_TRACE_OFFSET + 3, i.into());
        let b3 = self.columns.get(DECODER_TRACE_OFFSET + 4, i.into());
        let b4 = self.columns.get(DECODER_TRACE_OFFSET + 5, i.into());
        let b5 = self.columns.get(DECODER_TRACE_OFFSET + 6, i.into());
        let b6 = self.columns.get(DECODER_TRACE_OFFSET + 7, i.into());
        let e0 = self.columns.get(DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET, i.into());
        let h5 = self.columns.get(DECODER_TRACE_OFFSET + IS_LOOP_FLAG_COL_IDX, i.into());

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
        let b0 = self.columns.get(DECODER_TRACE_OFFSET + 1, i.into());
        let b1 = self.columns.get(DECODER_TRACE_OFFSET + 2, i.into());
        let b2 = self.columns.get(DECODER_TRACE_OFFSET + 3, i.into());
        let b3 = self.columns.get(DECODER_TRACE_OFFSET + 4, i.into());
        let b4 = self.columns.get(DECODER_TRACE_OFFSET + 5, i.into());
        let b5 = self.columns.get(DECODER_TRACE_OFFSET + 6, i.into());
        let b6 = self.columns.get(DECODER_TRACE_OFFSET + 7, i.into());

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
        self.columns.get_column(STACK_TRACE_OFFSET + B0_COL_IDX)[i]
    }

    /// Returns the element at row i in a given stack trace column.
    pub fn stack_element(&self, column: usize, i: RowIndex) -> Felt {
        self.columns.get_column(STACK_TRACE_OFFSET + column)[i]
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
        self.columns.get_column(STACK_TRACE_OFFSET + B1_COL_IDX)[i]
    }

    /// Returns a flag indicating whether the overflow stack is non-empty.
    pub fn is_non_empty_overflow(&self, i: RowIndex) -> bool {
        let b0 = self.columns.get_column(STACK_TRACE_OFFSET + B0_COL_IDX)[i];
        let h0 = self.columns.get_column(STACK_TRACE_OFFSET + H0_COL_IDX)[i];
        (b0 - Felt::from_u64(16)) * h0 == ONE
    }

    // CHIPLETS COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns chiplet column number 0 at row i.
    pub fn chiplet_selector_0(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET)[i]
    }

    /// Returns chiplet column number 1 at row i.
    pub fn chiplet_selector_1(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + 1)[i]
    }

    /// Returns chiplet column number 2 at row i.
    pub fn chiplet_selector_2(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + 2)[i]
    }

    /// Returns chiplet column number 3 at row i.
    pub fn chiplet_selector_3(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + 3)[i]
    }

    /// Returns chiplet column number 4 at row i.
    pub fn chiplet_selector_4(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + 4)[i]
    }

    /// Returns chiplet column number 5 at row i.
    pub fn chiplet_selector_5(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + 5)[i]
    }

    /// Returns `true` if a row is part of the hash chiplet.
    pub fn is_hash_row(&self, i: RowIndex) -> bool {
        self.chiplet_selector_0(i) == ZERO
    }

    /// Returns the (full) state of the hasher chiplet at row i.
    pub fn chiplet_hasher_state(&self, i: RowIndex) -> [Felt; STATE_WIDTH] {
        let mut state = [ZERO; STATE_WIDTH];
        for (idx, col_idx) in HASHER_STATE_COL_RANGE.enumerate() {
            let column = self.columns.get_column(col_idx);
            state[idx] = column[i];
        }
        state
    }

    /// Returns the hasher's node index column at row i
    pub fn chiplet_node_index(&self, i: RowIndex) -> Felt {
        self.columns.get(HASHER_NODE_INDEX_COL_IDX, i.into())
    }

    /// Returns `true` if a row is part of the bitwise chiplet.
    pub fn is_bitwise_row(&self, i: RowIndex) -> bool {
        self.chiplet_selector_0(i) == ONE && self.chiplet_selector_1(i) == ZERO
    }

    /// Returns the bitwise column holding the aggregated value of input `a` at row i.
    pub fn chiplet_bitwise_a(&self, i: RowIndex) -> Felt {
        self.columns.get_column(BITWISE_A_COL_IDX)[i]
    }

    /// Returns the bitwise column holding the aggregated value of input `b` at row i.
    pub fn chiplet_bitwise_b(&self, i: RowIndex) -> Felt {
        self.columns.get_column(BITWISE_B_COL_IDX)[i]
    }

    /// Returns the bitwise column holding the aggregated value of the output at row i.
    pub fn chiplet_bitwise_z(&self, i: RowIndex) -> Felt {
        self.columns.get_column(BITWISE_OUTPUT_COL_IDX)[i]
    }

    /// Returns `true` if a row is part of the memory chiplet.
    pub fn is_memory_row(&self, i: RowIndex) -> bool {
        self.chiplet_selector_0(i) == ONE
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ZERO
    }

    /// Returns the i-th row of the chiplet column containing memory context.
    pub fn chiplet_memory_ctx(&self, i: RowIndex) -> Felt {
        self.columns.get_column(MEMORY_CTX_COL_IDX)[i]
    }

    /// Returns the i-th row of the chiplet column containing memory address.
    pub fn chiplet_memory_word(&self, i: RowIndex) -> Felt {
        self.columns.get_column(MEMORY_WORD_COL_IDX)[i]
    }

    /// Returns the i-th row of the chiplet column containing 0th bit of the word index.
    pub fn chiplet_memory_idx0(&self, i: RowIndex) -> Felt {
        self.columns.get_column(MEMORY_IDX0_COL_IDX)[i]
    }

    /// Returns the i-th row of the chiplet column containing 1st bit of the word index.
    pub fn chiplet_memory_idx1(&self, i: RowIndex) -> Felt {
        self.columns.get_column(MEMORY_IDX1_COL_IDX)[i]
    }

    /// Returns the i-th row of the chiplet column containing clock cycle.
    pub fn chiplet_memory_clk(&self, i: RowIndex) -> Felt {
        self.columns.get_column(MEMORY_CLK_COL_IDX)[i]
    }

    /// Returns the i-th row of the chiplet column containing the zeroth memory value element.
    pub fn chiplet_memory_value_0(&self, i: RowIndex) -> Felt {
        self.columns.get_column(MEMORY_V_COL_RANGE.start)[i]
    }

    /// Returns the i-th row of the chiplet column containing the first memory value element.
    pub fn chiplet_memory_value_1(&self, i: RowIndex) -> Felt {
        self.columns.get_column(MEMORY_V_COL_RANGE.start + 1)[i]
    }

    /// Returns the i-th row of the chiplet column containing the second memory value element.
    pub fn chiplet_memory_value_2(&self, i: RowIndex) -> Felt {
        self.columns.get_column(MEMORY_V_COL_RANGE.start + 2)[i]
    }

    /// Returns the i-th row of the chiplet column containing the third memory value element.
    pub fn chiplet_memory_value_3(&self, i: RowIndex) -> Felt {
        self.columns.get_column(MEMORY_V_COL_RANGE.start + 3)[i]
    }

    /// Returns `true` if a row is part of the ACE chiplet.
    pub fn is_ace_row(&self, i: RowIndex) -> bool {
        self.chiplet_selector_0(i) == ONE
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ONE
            && self.chiplet_selector_3(i) == ZERO
    }

    pub fn chiplet_ace_start_selector(&self, i: RowIndex) -> Felt {
        self.columns
            .get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + SELECTOR_START_IDX)[i]
    }

    pub fn chiplet_ace_block_selector(&self, i: RowIndex) -> Felt {
        self.columns
            .get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + SELECTOR_BLOCK_IDX)[i]
    }

    pub fn chiplet_ace_ctx(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + CTX_IDX)[i]
    }

    pub fn chiplet_ace_ptr(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + PTR_IDX)[i]
    }

    pub fn chiplet_ace_clk(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + CLK_IDX)[i]
    }

    pub fn chiplet_ace_eval_op(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + EVAL_OP_IDX)[i]
    }

    pub fn chiplet_ace_num_eval_rows(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + READ_NUM_EVAL_IDX)[i]
    }

    pub fn chiplet_ace_id_0(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + ID_0_IDX)[i]
    }

    pub fn chiplet_ace_v_0_0(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_0_0_IDX)[i]
    }

    pub fn chiplet_ace_v_0_1(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_0_1_IDX)[i]
    }

    pub fn chiplet_ace_wire_0(&self, i: RowIndex) -> [Felt; 3] {
        let id_0 = self.chiplet_ace_id_0(i);
        let v_0_0 = self.chiplet_ace_v_0_0(i);
        let v_0_1 = self.chiplet_ace_v_0_1(i);

        [id_0, v_0_0, v_0_1]
    }

    pub fn chiplet_ace_id_1(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + ID_1_IDX)[i]
    }

    pub fn chiplet_ace_v_1_0(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_1_0_IDX)[i]
    }

    pub fn chiplet_ace_v_1_1(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_1_1_IDX)[i]
    }

    pub fn chiplet_ace_wire_1(&self, i: RowIndex) -> [Felt; 3] {
        let id_1 = self.chiplet_ace_id_1(i);
        let v_1_0 = self.chiplet_ace_v_1_0(i);
        let v_1_1 = self.chiplet_ace_v_1_1(i);

        [id_1, v_1_0, v_1_1]
    }

    pub fn chiplet_ace_id_2(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + ID_2_IDX)[i]
    }

    pub fn chiplet_ace_v_2_0(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_2_0_IDX)[i]
    }

    pub fn chiplet_ace_v_2_1(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + V_2_1_IDX)[i]
    }

    pub fn chiplet_ace_wire_2(&self, i: RowIndex) -> [Felt; 3] {
        let id_2 = self.chiplet_ace_id_2(i);
        let v_2_0 = self.chiplet_ace_v_2_0(i);
        let v_2_1 = self.chiplet_ace_v_2_1(i);

        [id_2, v_2_0, v_2_1]
    }

    pub fn chiplet_ace_m_1(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + M_1_IDX)[i]
    }

    pub fn chiplet_ace_m_0(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + NUM_ACE_SELECTORS + M_0_IDX)[i]
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
        self.columns.get_column(CHIPLETS_OFFSET + 5)[i] == ONE
    }

    /// Returns the i-th row of the chiplet column containing the zeroth element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_0(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + 6)[i]
    }

    /// Returns the i-th row of the chiplet column containing the first element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_1(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + 7)[i]
    }

    /// Returns the i-th row of the chiplet column containing the second element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_2(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + 8)[i]
    }

    /// Returns the i-th row of the chiplet column containing the third element of the kernel
    /// procedure root.
    pub fn chiplet_kernel_root_3(&self, i: RowIndex) -> Felt {
        self.columns.get_column(CHIPLETS_OFFSET + 9)[i]
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
        (i.as_usize() % HASH_CYCLE_LEN == HASH_CYCLE_LEN - 1)
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
        (i.as_usize() % HASH_CYCLE_LEN == HASH_CYCLE_LEN - 1)
            && self.chiplet_selector_0(i) == ZERO
            && self.chiplet_selector_1(i) == ONE
            && self.chiplet_selector_2(i) == ONE
            && self.chiplet_selector_3(i) == ONE
    }
}
