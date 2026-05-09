use super::RANGE_CHECK_TRACE_OFFSET;

// CONSTANTS
// ================================================================================================

// --- Column accessors in the main trace ---------------------------------------------------------

/// A column to hold the multiplicity of how many times the value is being range-checked.
pub const M_COL_IDX: usize = RANGE_CHECK_TRACE_OFFSET;
/// A column to hold the values being range-checked.
pub const V_COL_IDX: usize = RANGE_CHECK_TRACE_OFFSET + 1;
