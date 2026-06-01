use miden_core::{Felt, ONE, ZERO, operations::Operation};

// CONSTANTS
// ================================================================================================

/// Number of columns needed to hold a binary representation of opcodes.
pub const NUM_OP_BITS: usize = Operation::OP_BITS;

// Note: "hasher state" columns are shared between decoding operations and holding
// the hasher state during MAST node hashing.

/// Number of hasher columns in the decoder trace.
pub const NUM_HASHER_COLUMNS: usize = 8;

/// Number of helper registers available to user ops.
pub const NUM_USER_OP_HELPERS: usize = 6;

/// Number of operation batch flag columns.
pub const NUM_OP_BATCH_FLAGS: usize = 3;

/// Operation batch consists of 8 operation groups.
pub const OP_BATCH_8_GROUPS: [Felt; NUM_OP_BATCH_FLAGS] = [ONE, ZERO, ZERO];

/// Operation batch consists of 4 operation groups.
pub const OP_BATCH_4_GROUPS: [Felt; NUM_OP_BATCH_FLAGS] = [ZERO, ONE, ZERO];

/// Operation batch consists of 2 operation groups.
pub const OP_BATCH_2_GROUPS: [Felt; NUM_OP_BATCH_FLAGS] = [ZERO, ZERO, ONE];

/// Operation batch consists of 1 operation group.
pub const OP_BATCH_1_GROUPS: [Felt; NUM_OP_BATCH_FLAGS] = [ZERO, ONE, ONE];

/// Number of columns needed for degree reduction of the operation flags.
pub const NUM_OP_BITS_EXTRA_COLS: usize = 2;
