use core::ops::Index;

use miden_core::program::MIN_STACK_DEPTH;

use crate::trace::STACK_TRACE_WIDTH;

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
