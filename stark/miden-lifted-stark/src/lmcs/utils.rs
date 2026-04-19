//! Utility functions for LMCS operations.

use alloc::vec::Vec;
use core::array;

use p3_field::PackedValue;
use p3_util::log2_strict_usize;

/// Strict log₂ returning `u8`.
///
/// Panics if `n` is not a power of two.
#[inline]
pub fn log2_strict_u8(n: usize) -> u8 {
    log2_strict_usize(n) as u8
}

/// Extension trait for `PackedValue` providing columnar pack/unpack operations.
///
/// These methods perform transpose operations on packed data, useful for
/// SIMD-parallelized Merkle tree construction.
pub trait PackedValueExt: PackedValue {
    /// Pack columns from `WIDTH` rows of scalar values.
    ///
    /// Given `WIDTH` rows of `N` scalar values, extract each column and pack it
    /// into a single packed value. This performs a transpose operation.
    #[inline]
    #[must_use]
    fn pack_columns<const N: usize>(rows: &[[Self::Value; N]]) -> [Self; N] {
        assert_eq!(rows.len(), Self::WIDTH);
        array::from_fn(|col| Self::from_fn(|lane| rows[lane][col]))
    }
}

// Blanket implementation for all PackedValue types
impl<T: PackedValue> PackedValueExt for T {}

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
