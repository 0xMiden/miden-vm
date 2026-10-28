//! Width / length alignment helpers.

use alloc::vec::Vec;

/// Compute the aligned length for `len` given an alignment.
#[inline]
pub(crate) const fn aligned_len(len: usize, alignment: usize) -> usize {
    assert!(alignment != 0, "alignment must be non-zero");

    if alignment == 1 {
        len
    } else {
        len.next_multiple_of(alignment)
    }
}

/// Sum independently aligned lengths.
pub(crate) fn aligned_len_sum(lengths: impl IntoIterator<Item = usize>, alignment: usize) -> usize {
    assert_ne!(alignment, 0, "alignment must be non-zero");

    lengths.into_iter().fold(0usize, |total, len| {
        let aligned = len
            .checked_add(alignment - 1)
            .map(|len| len / alignment * alignment)
            .expect("aligned input length exceeds usize");
        total.checked_add(aligned).expect("encoded input length exceeds usize")
    })
}

/// Align each width in place, returning the same `Vec`.
pub(crate) fn aligned_widths(mut widths: Vec<usize>, alignment: usize) -> Vec<usize> {
    for w in &mut widths {
        *w = aligned_len(*w, alignment);
    }
    widths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_independently_aligned_lengths() {
        assert_eq!(aligned_len_sum([0, 1, 8, 9], 8), 32);
        assert_eq!(aligned_len_sum([3, 9, 4], 8), 32);
        assert_eq!(aligned_len_sum([3, 9, 4], 1), 16);
    }

    #[test]
    #[should_panic(expected = "alignment must be non-zero")]
    fn aligned_len_rejects_zero_alignment() {
        aligned_len(3, 0);
    }

    #[test]
    #[should_panic(expected = "alignment must be non-zero")]
    fn aligned_len_sum_rejects_zero_alignment() {
        aligned_len_sum([3, 9, 4], 0);
    }
}
