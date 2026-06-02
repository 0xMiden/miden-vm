use super::{Felt, ONE, ZERO};

// CONSTANTS
// ================================================================================================

/// Number of selector columns in the trace.
pub const NUM_SELECTORS: usize = 1;

/// Number of columns needed to record an execution trace of the bitwise chiplet.
pub const TRACE_WIDTH: usize = NUM_SELECTORS + 12;

/// The number of rows required to compute an operation in the Bitwise chiplet.
pub const OP_CYCLE_LEN: usize = 8;

// --- OPERATION SELECTORS ------------------------------------------------------------------------

/// Specifies a bitwise AND operation.
pub const BITWISE_AND: Felt = ZERO;

/// Specifies a bitwise XOR operation.
pub const BITWISE_XOR: Felt = ONE;

// --- INPUT DECOMPOSITION ------------------------------------------------------------------------

/// The number of bits decomposed per row per input parameter `a` or `b`.
pub const NUM_DECOMP_BITS: usize = 4;

// TYPE ALIASES
// ================================================================================================

pub type Selectors = [Felt; NUM_SELECTORS];
