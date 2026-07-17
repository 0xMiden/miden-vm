use super::{Felt, ONE, ZERO};

// CONSTANTS
// ================================================================================================

/// Number of selector columns in the trace.
pub const NUM_SELECTORS: usize = 1;

/// The number of bits decomposed per row per input parameter `a` or `b`.
pub const NUM_DECOMP_BITS: usize = 4;

/// Number of decomposition columns for the current 4-bit limbs of `a` and `b`.
pub const NUM_DECOMP_COLS: usize = 2 * NUM_DECOMP_BITS;

/// Number of non-selector accumulator columns: `a`, `b`, previous output, and output.
pub const NUM_ACCUMULATOR_COLS: usize = 4;

/// Number of columns needed to record an execution trace of the bitwise chiplet.
pub const TRACE_WIDTH: usize = NUM_SELECTORS + NUM_ACCUMULATOR_COLS + NUM_DECOMP_COLS;

/// The number of rows required to compute an operation in the Bitwise chiplet.
pub const OP_CYCLE_LEN: usize = 8;

// --- OPERATION SELECTORS ------------------------------------------------------------------------

/// Specifies a bitwise AND operation.
pub const BITWISE_AND: Felt = ZERO;

/// Specifies a bitwise XOR operation.
pub const BITWISE_XOR: Felt = ONE;

// TYPE ALIASES
// ================================================================================================

pub type Selectors = [Felt; NUM_SELECTORS];
