use miden_core::WORD_SIZE;

// SYSTEM COLUMNS
// ================================================================================================

/// System columns in the main execution trace (6 columns).
///
/// These columns track global execution state: clock cycle, execution context, and
/// the function hash (digest) of the currently executing function.
#[repr(C)]
pub struct SystemCols<T> {
    /// Clock cycle counter.
    pub clk: T,
    /// Context identifier.
    pub ctx: T,
    /// Function hash (digest) of the currently executing function.
    pub fn_hash: [T; WORD_SIZE],
}
