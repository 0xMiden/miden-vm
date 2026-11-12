use alloc::vec::Vec;
use core::borrow::{Borrow, BorrowMut};

use miden_core::{
    Felt, ONE, Word, ZERO,
    field::PrimeCharacteristicRing,
    utils::{Matrix, RowMajorMatrix},
};

use super::{
    CHIPLETS_WIDTH, RowIndex, TRACE_WIDTH,
    and8_lookup::NUM_AND8_LOOKUP_COLS,
    chiplets::hasher::DIGEST_LEN,
    decoder::{NUM_HASHER_COLUMNS, NUM_OP_BATCH_ENCODING_COLS},
    eidos_compression::NUM_EIDOS_COMPRESSION_COLS,
};
use crate::vm::constraints::{
    chiplets::selectors::ChipletActiveFlags,
    columns::{ChipletCols, CoreCols, NUM_CHIPLETS_COLS, NUM_CORE_COLS},
    decoder::columns::DecoderCols,
    stack::columns::StackCols,
    system::columns::SystemCols,
};

#[cfg(any(test, feature = "testing"))]
mod testing;

// MAIN TRACE ROW
// ================================================================================================

/// Column layout of the main trace row.
#[derive(Debug)]
#[repr(C)]
pub struct MainTraceRow<T> {
    pub system: SystemCols<T>,
    pub decoder: DecoderCols<T>,
    pub stack: StackCols<T>,
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
#[derive(Clone, Debug)]
struct TraceStorage {
    /// Core matrix (`CORE_STORAGE_WIDTH` cols), at its own per-AIR height.
    core_rm: RowMajorMatrix<Felt>,
    /// Chiplets matrix (`CHIPLETS_WIDTH` cols), at its own per-AIR height.
    chiplets_rm: RowMajorMatrix<Felt>,
    /// Eidos compression matrix, at its own per-AIR height.
    eidos_compression_rm: RowMajorMatrix<Felt>,
    /// Byte-pair lookup matrix, at its fixed table height.
    and8_lookup_rm: RowMajorMatrix<Felt>,
}

#[derive(Clone, Debug)]
pub struct MainTrace {
    storage: TraceStorage,
    last_program_row: RowIndex,
}

/// Physical row width of `core_rm`: the full per-AIR Core matrix width (`NUM_CORE_COLS`).
const CORE_STORAGE_WIDTH: usize = NUM_CORE_COLS;

impl MainTrace {
    pub fn from_parts(
        core_rm: Vec<Felt>,
        chiplets_rm: Vec<Felt>,
        eidos_compression_rm: Vec<Felt>,
        and8_lookup_rm: Vec<Felt>,
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
            eidos_compression_rm.len() % NUM_EIDOS_COMPRESSION_COLS,
            0,
            "Eidos compression buffer not a multiple of NUM_EIDOS_COMPRESSION_COLS"
        );
        assert_eq!(
            and8_lookup_rm.len() % NUM_AND8_LOOKUP_COLS,
            0,
            "AND8 lookup buffer not a multiple of NUM_AND8_LOOKUP_COLS"
        );
        let core_rows = core_rm.len() / CORE_STORAGE_WIDTH;
        let chiplets_rows = chiplets_rm.len() / CHIPLETS_WIDTH;
        let eidos_compression_rows = eidos_compression_rm.len() / NUM_EIDOS_COMPRESSION_COLS;
        let and8_rows = and8_lookup_rm.len() / NUM_AND8_LOOKUP_COLS;
        assert!(core_rows.is_power_of_two(), "core height must be a power of two");
        assert!(chiplets_rows.is_power_of_two(), "chiplets height must be a power of two");
        assert!(
            eidos_compression_rows.is_power_of_two(),
            "Eidos compression height must be a power of two"
        );
        assert!(and8_rows.is_power_of_two(), "AND8 lookup height must be a power of two");
        Self {
            storage: TraceStorage {
                core_rm: RowMajorMatrix::new(core_rm, CORE_STORAGE_WIDTH),
                chiplets_rm: RowMajorMatrix::new(chiplets_rm, CHIPLETS_WIDTH),
                eidos_compression_rm: RowMajorMatrix::new(
                    eidos_compression_rm,
                    NUM_EIDOS_COMPRESSION_COLS,
                ),
                and8_lookup_rm: RowMajorMatrix::new(and8_lookup_rm, NUM_AND8_LOOKUP_COLS),
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
    /// use a typed projection such as [`ChipletCols::controller_cols`] or
    /// [`ChipletCols::memory_cols`] to name the physical columns according to the chiplet
    /// active on that row.
    ///
    /// # Panics
    /// Panics if `i` is past the chiplets trace height — see [`Self::chiplets_height`]. The
    /// `is_*_row` classifiers short-circuit past the chiplets height, so they can be
    /// used as bound-aware filters when iterating the unified trace.
    #[inline]
    pub fn chiplet_cols(&self, i: RowIndex) -> &ChipletCols<Felt> {
        let (rows, _) = self.storage.chiplets_rm.values.as_chunks::<NUM_CHIPLETS_COLS>();
        rows[i.as_usize()].as_slice().borrow()
    }

    pub fn into_air_matrices(
        self,
    ) -> (
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
    ) {
        (
            self.storage.core_rm,
            self.storage.chiplets_rm,
            self.storage.eidos_compression_rm,
            self.storage.and8_lookup_rm,
        )
    }

    /// Returns the larger of all per-AIR heights.
    pub fn num_rows(&self) -> usize {
        self.core_height()
            .max(self.chiplets_height())
            .max(self.eidos_compression_height())
            .max(self.byte_pair_lookup_height())
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

    /// Returns the Eidos compression AIR trace height.
    #[inline]
    pub fn eidos_compression_height(&self) -> usize {
        self.storage.eidos_compression_rm.height()
    }

    /// Returns the byte-pair lookup AIR trace height.
    #[inline]
    pub fn byte_pair_lookup_height(&self) -> usize {
        self.storage.and8_lookup_rm.height()
    }

    pub fn last_program_row(&self) -> RowIndex {
        self.last_program_row
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

    /// Returns whether the END at row i restores a caller frame.
    pub fn restores_caller_frame_flag(&self, i: RowIndex) -> Felt {
        self.core_row(i).decoder.end_block_flags().restores_caller_frame
    }

    /// Returns the operation-batch encoding at row i.
    pub fn op_batch_encoding(&self, i: RowIndex) -> [Felt; NUM_OP_BATCH_ENCODING_COLS] {
        let decoder = &self.core_row(i).decoder;
        [decoder.full_batch, decoder.batch_size_code]
    }

    /// Returns the decoder's `group_count` value at row i.
    ///
    /// On SPAN, RESPAN, and in-span rows, this tracks the operation groups remaining in the
    /// current basic block. On LOOP rows, it counts body executions and supplies the block-hash
    /// lookup multiplicity.
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

    fn chiplet_active(&self, i: RowIndex) -> Option<ChipletActiveFlags<bool>> {
        (i.as_usize() < self.chiplets_height())
            .then(|| ChipletActiveFlags::from_trace_row(self.chiplet_cols(i)))
    }

    /// Returns `true` if a row is part of the hasher-controller chiplet.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; rows past `chiplets_height()`
    /// are not part of any chiplet by definition in the split-trace model.
    pub fn is_controller_row(&self, i: RowIndex) -> bool {
        self.chiplet_active(i).is_some_and(|active| active.controller)
    }

    /// Returns `true` if a row is part of the bitwise chiplet.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; see [`Self::is_controller_row`].
    pub fn is_bitwise_row(&self, i: RowIndex) -> bool {
        self.chiplet_active(i).is_some_and(|active| active.bitwise)
    }

    /// Returns `true` if a row is part of the AEAD stream chiplet.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; see [`Self::is_controller_row`].
    pub fn is_aead_stream_row(&self, i: RowIndex) -> bool {
        self.chiplet_active(i).is_some_and(|active| active.aead_stream)
    }

    /// Returns `true` if a row is part of the memory chiplet.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; see [`Self::is_controller_row`].
    pub fn is_memory_row(&self, i: RowIndex) -> bool {
        self.chiplet_active(i).is_some_and(|active| active.memory)
    }

    /// Returns `true` if a row is part of the ACE chiplet.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; see [`Self::is_controller_row`].
    pub fn is_ace_row(&self, i: RowIndex) -> bool {
        self.chiplet_active(i).is_some_and(|active| active.ace)
    }

    /// Returns `true` if a row is part of the kernel chiplet.
    ///
    /// Short-circuits to `false` past the chiplets-AIR height; see [`Self::is_controller_row`].
    pub fn is_kernel_row(&self, i: RowIndex) -> bool {
        self.chiplet_active(i).is_some_and(|active| active.kernel_rom)
    }
}
