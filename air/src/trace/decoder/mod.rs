use miden_core::{Felt, ONE, ZERO, field::PrimeCharacteristicRing, operations::Operation};

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

/// Number of columns in the operation-batch encoding.
pub const NUM_OP_BATCH_ENCODING_COLS: usize = 2;

/// Operation batch consists of 8 operation groups: `(full_batch, batch_size_code) = (1, 0)`.
pub const OP_BATCH_8_GROUPS: [Felt; NUM_OP_BATCH_ENCODING_COLS] = [ONE, ZERO];

/// Operation batch consists of 4 operation groups: `(full_batch, batch_size_code) = (0, 1)`.
pub const OP_BATCH_4_GROUPS: [Felt; NUM_OP_BATCH_ENCODING_COLS] = [ZERO, ONE];

/// Operation batch consists of 2 operation groups: `(full_batch, batch_size_code) = (0, -1)`.
pub const OP_BATCH_2_GROUPS: [Felt; NUM_OP_BATCH_ENCODING_COLS] = [ZERO, Felt::NEG_ONE];

/// Operation batch consists of 1 operation group: `(full_batch, batch_size_code) = (0, 0)`.
///
/// Inactive rows use the same pair and are distinguished by the constrained SPAN/RESPAN opcode.
pub const OP_BATCH_1_GROUPS: [Felt; NUM_OP_BATCH_ENCODING_COLS] = [ZERO, ZERO];

/// Number of columns needed for degree reduction of the operation flags.
pub const NUM_OP_BITS_EXTRA_COLS: usize = 2;
