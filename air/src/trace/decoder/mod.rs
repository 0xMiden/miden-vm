use core::ops::{Index, IndexMut, Range};

use miden_core::{Felt, ONE, ZERO, operations::Operation, utils::range};

use super::{DECODER_AUX_TRACE_OFFSET, DECODER_TRACE_WIDTH};

// COLUMN STRUCTS
// ================================================================================================

/// Decoder columns in the main execution trace (24 columns).
#[repr(C)]
pub struct DecoderCols<T> {
    /// Block address (hasher table row pointer).
    pub addr: T,
    /// Opcode bits b0-b6.
    pub op_bits: [T; NUM_OP_BITS],
    /// Hasher state h0-h7 (shared between decoding and MAST node hashing).
    pub hasher_state: [T; NUM_HASHER_COLUMNS],
    /// In-span flag (1 inside a basic block).
    pub in_span: T,
    /// Remaining operation group count.
    pub group_count: T,
    /// Position within operation group (0-8).
    pub op_index: T,
    /// Operation batch flags c0, c1, c2.
    pub batch_flags: [T; NUM_OP_BATCH_FLAGS],
    /// Degree-reduction extra columns e0, e1.
    pub extra: [T; NUM_OP_BITS_EXTRA_COLS],
}

impl<T: Copy> DecoderCols<T> {
    /// Returns the 6 user-op helper registers (hasher_state[2..8]).
    pub fn user_op_helpers(&self) -> [T; NUM_USER_OP_HELPERS] {
        [
            self.hasher_state[2],
            self.hasher_state[3],
            self.hasher_state[4],
            self.hasher_state[5],
            self.hasher_state[6],
            self.hasher_state[7],
        ]
    }

    /// Returns the 4 end-block flags (hasher_state[4..8]).
    pub fn end_block_flags(&self) -> EndBlockFlags<T> {
        EndBlockFlags {
            is_loop_body: self.hasher_state[4],
            is_loop: self.hasher_state[5],
            is_call: self.hasher_state[6],
            is_syscall: self.hasher_state[7],
        }
    }
}

/// Named end-block flag overlay for `hasher_state[4..8]`.
#[repr(C)]
pub struct EndBlockFlags<T> {
    pub is_loop_body: T,
    pub is_loop: T,
    pub is_call: T,
    pub is_syscall: T,
}

/// Flat index access for backwards compatibility during migration.
impl<T> Index<usize> for DecoderCols<T> {
    type Output = T;
    fn index(&self, idx: usize) -> &T {
        assert!(idx < DECODER_TRACE_WIDTH, "decoder column index {idx} out of bounds");
        // Safety: DecoderCols is #[repr(C)] with all T-sized fields, so it is layout-
        // compatible with [T; DECODER_TRACE_WIDTH].
        unsafe { &*(self as *const Self as *const T).add(idx) }
    }
}

impl<T> IndexMut<usize> for DecoderCols<T> {
    fn index_mut(&mut self, idx: usize) -> &mut T {
        assert!(idx < DECODER_TRACE_WIDTH, "decoder column index {idx} out of bounds");
        unsafe { &mut *(self as *mut Self as *mut T).add(idx) }
    }
}

// CONSTANTS
// ================================================================================================

/// Index of the column holding code block IDs (which are row addresses from the hasher table).
pub const ADDR_COL_IDX: usize = 0;

/// Index at which operation bit columns start in the decoder trace.
pub const OP_BITS_OFFSET: usize = ADDR_COL_IDX + 1;

/// Number of columns needed to hold a binary representation of opcodes.
pub const NUM_OP_BITS: usize = Operation::OP_BITS;

/// Location of operation bits columns in the decoder trace.
pub const OP_BITS_RANGE: Range<usize> = range(OP_BITS_OFFSET, NUM_OP_BITS);

// Note: "hasher state" columns are shared between decoding operations and holding
// the hasher state during MAST node hashing.

/// Index at which hasher state columns start in the decoder trace.
pub const HASHER_STATE_OFFSET: usize = OP_BITS_RANGE.end;

/// Number of hasher columns in the decoder trace.
pub const NUM_HASHER_COLUMNS: usize = 8;

/// Number of helper registers available to user ops.
pub const NUM_USER_OP_HELPERS: usize = 6;

/// Index at which helper registers available to user ops start.
/// The first two helper registers are used by the decoder itself.
pub const USER_OP_HELPERS_OFFSET: usize = HASHER_STATE_OFFSET + 2;

/// Location of hasher columns in the decoder trace.
pub const HASHER_STATE_RANGE: Range<usize> = range(HASHER_STATE_OFFSET, NUM_HASHER_COLUMNS);

/// Index of the in_span column in the decoder trace.
pub const IN_SPAN_COL_IDX: usize = HASHER_STATE_RANGE.end;

/// Index of the operation group count column in the decoder trace.
pub const GROUP_COUNT_COL_IDX: usize = IN_SPAN_COL_IDX + 1;

/// Index of the operation index column in the decoder trace.
pub const OP_INDEX_COL_IDX: usize = GROUP_COUNT_COL_IDX + 1;

/// Index at which operation batch flag columns start in the decoder trace.
pub const OP_BATCH_FLAGS_OFFSET: usize = OP_INDEX_COL_IDX + 1;

/// Number of operation batch flag columns.
pub const NUM_OP_BATCH_FLAGS: usize = 3;

/// Location of operation batch flag columns in the decoder trace.
pub const OP_BATCH_FLAGS_RANGE: Range<usize> = range(OP_BATCH_FLAGS_OFFSET, NUM_OP_BATCH_FLAGS);

/// Operation batch consists of 8 operation groups.
pub const OP_BATCH_8_GROUPS: [Felt; NUM_OP_BATCH_FLAGS] = [ONE, ZERO, ZERO];

/// Operation batch consists of 4 operation groups.
pub const OP_BATCH_4_GROUPS: [Felt; NUM_OP_BATCH_FLAGS] = [ZERO, ONE, ZERO];

/// Operation batch consists of 2 operation groups.
pub const OP_BATCH_2_GROUPS: [Felt; NUM_OP_BATCH_FLAGS] = [ZERO, ZERO, ONE];

/// Operation batch consists of 1 operation group.
pub const OP_BATCH_1_GROUPS: [Felt; NUM_OP_BATCH_FLAGS] = [ZERO, ONE, ONE];

/// Index at which the op bits extra columns start in the decoder trace.
pub const OP_BITS_EXTRA_COLS_OFFSET: usize = OP_BATCH_FLAGS_RANGE.end;

/// Number of columns needed for degree reduction of the operation flags.
pub const NUM_OP_BITS_EXTRA_COLS: usize = 2;

/// Location of the operation bits extra columns (for degree reduction) in the decoder trace.
pub const OP_BITS_EXTRA_COLS_RANGE: Range<usize> =
    range(OP_BITS_EXTRA_COLS_OFFSET, NUM_OP_BITS_EXTRA_COLS);

/// Index of a flag column which indicates whether an ending block is a body of a loop.
pub const IS_LOOP_BODY_FLAG_COL_IDX: usize = HASHER_STATE_RANGE.start + 4;

/// Index of a flag column which indicates whether an ending block is a LOOP block.
pub const IS_LOOP_FLAG_COL_IDX: usize = HASHER_STATE_RANGE.start + 5;

/// Index of a flag column which indicates whether an ending block is a CALL or DYNCALL block.
pub const IS_CALL_FLAG_COL_IDX: usize = HASHER_STATE_RANGE.start + 6;

/// Index of a flag column which indicates whether an ending block is a SYSCALL block.
pub const IS_SYSCALL_FLAG_COL_IDX: usize = HASHER_STATE_RANGE.start + 7;

// --- Column accessors in the auxiliary columns --------------------------------------------------

/// Running product column representing block stack table.
pub const P1_COL_IDX: usize = DECODER_AUX_TRACE_OFFSET;

/// Running product column representing block hash table
pub const P2_COL_IDX: usize = DECODER_AUX_TRACE_OFFSET + 1;

/// Running product column representing op group table.
pub const P3_COL_IDX: usize = DECODER_AUX_TRACE_OFFSET + 2;

// --- GLOBALLY-INDEXED DECODER COLUMN ACCESSORS --------------------------------------------------
pub const DECODER_OP_BITS_OFFSET: usize = super::DECODER_TRACE_OFFSET + OP_BITS_OFFSET;
pub const DECODER_USER_OP_HELPERS_OFFSET: usize =
    super::DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET;
