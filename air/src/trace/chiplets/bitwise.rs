use super::{Felt, ONE, Range, ZERO, create_range};

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
/// Unique label computed as 1 plus the full chiplet selector with the bits reversed.
/// `selector = [1, 0 | 0]`, `flag = rev(selector) + 1 = [0 | 0, 1] + 1 = 2`
pub const BITWISE_AND_LABEL: Felt = Felt::new(0b001 + 1);

/// Specifies a bitwise XOR operation.
pub const BITWISE_XOR: Felt = ONE;
/// Unique label computed as 1 plus the full chiplet selector with the bits reversed.
/// `selector = [1, 0 | 1]`, `flag = rev(selector) + 1 = [1 | 0, 1] + 1 = 6`
pub const BITWISE_XOR_LABEL: Felt = Felt::new(0b101 + 1);

// --- INPUT DECOMPOSITION ------------------------------------------------------------------------

/// The number of bits decomposed per row per input parameter `a` or `b`.
pub const NUM_DECOMP_BITS: usize = 4;

// --- COLUMN ACCESSOR INDICES WITHIN THE CHIPLET -------------------------------------------------

/// The index of the column holding the aggregated value of input `a` within the bitwise chiplet
/// execution trace.
pub const A_COL_IDX: usize = NUM_SELECTORS;

/// The index of the column holding the aggregated value of input `b` within the bitwise chiplet
/// execution trace.
pub const B_COL_IDX: usize = A_COL_IDX + 1;

/// The index range for the bit decomposition of `a` within the bitwise chiplet's trace.
pub const A_COL_RANGE: Range<usize> = create_range(B_COL_IDX + 1, NUM_DECOMP_BITS);

/// The index range for the bit decomposition of `b` within the bitwise chiplet's trace.
pub const B_COL_RANGE: Range<usize> = create_range(A_COL_RANGE.end, NUM_DECOMP_BITS);

/// The index of the column containing the aggregated output value within the bitwise chiplet
/// execution trace.
pub const PREV_OUTPUT_COL_IDX: usize = B_COL_IDX + 1 + 2 * NUM_DECOMP_BITS;

/// The index of the column containing the aggregated output value within the bitwise chiplet
/// execution trace.
pub const OUTPUT_COL_IDX: usize = PREV_OUTPUT_COL_IDX + 1;

// TYPE ALIASES
// ================================================================================================

pub type Selectors = [Felt; NUM_SELECTORS];
