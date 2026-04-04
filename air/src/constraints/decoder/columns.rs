use core::ops::{Index, IndexMut};

use crate::trace::{
    DECODER_TRACE_WIDTH,
    decoder::{
        NUM_HASHER_COLUMNS, NUM_OP_BATCH_FLAGS, NUM_OP_BITS, NUM_OP_BITS_EXTRA_COLS,
        NUM_USER_OP_HELPERS,
    },
};

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
