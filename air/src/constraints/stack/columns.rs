use miden_core::program::MIN_STACK_DEPTH;

/// Stack columns in the main execution trace (19 columns).
#[repr(C)]
pub struct StackCols<T> {
    /// Top 16 stack elements s0-s15.
    pub(crate) top: [T; MIN_STACK_DEPTH],
    /// Stack depth.
    pub b0: T,
    /// Overflow table parent address.
    pub b1: T,
    /// Helper: 1/(b0 - 16) when b0 != 16, else 0.
    pub h0: T,
}

impl<T: Copy> StackCols<T> {
    /// Returns the stack element at position `idx` (0 = top of stack).
    pub fn get(&self, idx: usize) -> T {
        self.top[idx]
    }
}

impl<T> StackCols<T> {
    /// Returns a slice of stack elements for the given range.
    pub fn elements(&self, range: impl core::slice::SliceIndex<[T], Output = [T]>) -> &[T] {
        &self.top[range]
    }
}
