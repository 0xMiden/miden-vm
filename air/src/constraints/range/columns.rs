use core::ops::Index;

use crate::trace::RANGE_CHECK_TRACE_WIDTH;

/// Range check columns in the main execution trace (2 columns).
#[repr(C)]
pub struct RangeCols<T> {
    /// Multiplicity: how many times this value is range-checked.
    pub multiplicity: T,
    /// The value being range-checked.
    pub value: T,
}

/// Flat index access for backwards compatibility during migration.
impl<T> Index<usize> for RangeCols<T> {
    type Output = T;
    fn index(&self, idx: usize) -> &T {
        assert!(idx < RANGE_CHECK_TRACE_WIDTH, "range column index {idx} out of bounds");
        unsafe { &*(self as *const Self as *const T).add(idx) }
    }
}
