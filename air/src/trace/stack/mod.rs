use core::ops::{Index, Range};

use miden_core::{program::MIN_STACK_DEPTH, utils::range};

use super::STACK_TRACE_WIDTH;

// COLUMN STRUCTS
// ================================================================================================

/// Stack columns in the main execution trace (19 columns).
#[repr(C)]
pub struct StackCols<T> {
    /// Top 16 stack elements s0-s15.
    pub top: [T; MIN_STACK_DEPTH],
    /// Stack depth.
    pub b0: T,
    /// Overflow table parent address.
    pub b1: T,
    /// Helper: 1/(b0 - 16) when b0 != 16, else 0.
    pub h0: T,
}

/// Flat index access for backwards compatibility during migration.
impl<T> Index<usize> for StackCols<T> {
    type Output = T;
    fn index(&self, idx: usize) -> &T {
        assert!(idx < STACK_TRACE_WIDTH, "stack column index {idx} out of bounds");
        unsafe { &*(self as *const Self as *const T).add(idx) }
    }
}

// CONSTANTS
// ================================================================================================

/// Index at which stack item columns start in the stack trace.
pub const STACK_TOP_OFFSET: usize = 0;

/// Location of stack top items in the stack trace.
pub const STACK_TOP_RANGE: Range<usize> = range(STACK_TOP_OFFSET, MIN_STACK_DEPTH);

/// Number of bookkeeping and helper columns in the stack trace.
pub const NUM_STACK_HELPER_COLS: usize = 3;

/// Index of the b0 helper column in the stack trace. This column holds the current stack depth.
pub const B0_COL_IDX: usize = STACK_TOP_RANGE.end;

/// Index of the b1 helper column in the stack trace. This column holds the address of the top
/// item in the stack overflow table.
pub const B1_COL_IDX: usize = STACK_TOP_RANGE.end + 1;

/// Index of the h0 helper column in the stack trace. This column contains 1 / (b0 - 16) when
/// b0 != 16, and ZERO otherwise.
pub const H0_COL_IDX: usize = STACK_TOP_RANGE.end + 2;
