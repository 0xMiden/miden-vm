use super::{Felt, ONE, ZERO};

// CONSTANTS
// ================================================================================================

/// Number of columns needed to record an execution trace of the memory chiplet.
pub const TRACE_WIDTH: usize = 17;

// --- OPERATION SELECTORS ------------------------------------------------------------------------

/// Specifies the value of the `READ_WRITE` column when the operation is a write.
pub const MEMORY_WRITE: Felt = ZERO;
/// Specifies the value of the `READ_WRITE` column when the operation is a read.
pub const MEMORY_READ: Felt = ONE;
/// Specifies the value of the `ELEMENT_OR_WORD` column when the operation is over an element.
pub const MEMORY_ACCESS_ELEMENT: Felt = ZERO;
/// Specifies the value of the `ELEMENT_OR_WORD` column when the operation is over a word.
pub const MEMORY_ACCESS_WORD: Felt = ONE;
