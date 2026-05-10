//! Width / length alignment helpers.

use alloc::vec::Vec;

/// Compute the aligned length for `len` given an alignment.
#[inline]
pub const fn aligned_len(len: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        len
    } else {
        len.next_multiple_of(alignment)
    }
}

/// Align each width in place, returning the same `Vec`.
pub fn aligned_widths(mut widths: Vec<usize>, alignment: usize) -> Vec<usize> {
    for w in &mut widths {
        *w = aligned_len(*w, alignment);
    }
    widths
}
