use super::{Felt, ONE, ZERO};

// CONSTANTS
// ================================================================================================

/// Number of selector columns in the trace.
pub const NUM_SELECTORS: usize = 1;

/// Number of bytes in a u32 operand.
pub const NUM_U32_BYTES: usize = 4;

/// Number of columns in the ordinary bitwise operation payload.
pub const TRACE_WIDTH: usize = size_of::<crate::vm::BitwiseOpCols<u8>>();

/// The number of rows required to compute an operation in the Bitwise chiplet.
pub const OP_CYCLE_LEN: usize = 1;

// --- OPERATION SELECTORS ------------------------------------------------------------------------

/// Specifies a bitwise AND operation.
pub const BITWISE_AND: Felt = ZERO;

/// Specifies a bitwise XOR operation.
pub const BITWISE_XOR: Felt = ONE;

// TYPE ALIASES
// ================================================================================================

pub type Selectors = [Felt; NUM_SELECTORS];
