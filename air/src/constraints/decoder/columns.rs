use crate::trace::decoder::{
    NUM_HASHER_COLUMNS, NUM_OP_BATCH_FLAGS, NUM_OP_BITS, NUM_OP_BITS_EXTRA_COLS,
    NUM_USER_OP_HELPERS,
};

/// Decoder columns in the main execution trace (24 columns).
#[repr(C)]
#[derive(Debug, Clone, Default)]
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

    /// Returns the END flags stored in hasher state columns 4 through 6.
    /// Column 7 is constrained to zero on END rows.
    pub fn end_block_flags(&self) -> EndBlockFlags<T> {
        EndBlockFlags {
            is_loop_body: self.hasher_state[4],
            is_loop: self.hasher_state[5],
            restores_caller_frame: self.hasher_state[6],
        }
    }
}

/// Named overlay for the semantic END flags in `hasher_state[4..7]`.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct EndBlockFlags<T> {
    /// Whether the node that ended is the body of a LOOP node.
    pub is_loop_body: T,
    /// Whether this END closes a LOOP continuation.
    pub is_loop: T,
    /// Whether this END restores state from an authenticated caller-frame entry.
    pub restores_caller_frame: T,
}
