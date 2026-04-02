use super::{RANGE_CHECK_AUX_TRACE_OFFSET, RANGE_CHECK_TRACE_OFFSET};

// COLUMN STRUCTS
// ================================================================================================

/// Range check columns in the main execution trace (2 columns).
#[repr(C)]
pub struct RangeCols<T> {
    /// Multiplicity: how many times this value is range-checked.
    pub multiplicity: T,
    /// The value being range-checked.
    pub value: T,
}

// CONSTANTS
// ================================================================================================

// --- Column accessors in the main trace ---------------------------------------------------------

/// A column to hold the multiplicity of how many times the value is being range-checked.
pub const M_COL_IDX: usize = RANGE_CHECK_TRACE_OFFSET;
/// A column to hold the values being range-checked.
pub const V_COL_IDX: usize = RANGE_CHECK_TRACE_OFFSET + 1;

// --- Column accessors in the auxiliary columns --------------------------------------------------

/// The running product column used for verifying that the range check lookups performed in the
/// Stack and the Memory chiplet match the values checked in the Range Checker.
pub const B_RANGE_COL_IDX: usize = RANGE_CHECK_AUX_TRACE_OFFSET;
