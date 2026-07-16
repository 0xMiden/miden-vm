//! Small utility helpers shared across lifted-STARK crates.

use p3_util::{log2_ceil_usize, log2_strict_usize};

/// Strict log₂ returning `u8`.
///
/// Panics if `n` is not a power of two, or if the result exceeds `u8::MAX`
/// (i.e., `n >= 2^256` — impossible on any real platform).
#[inline]
pub fn log2_strict_u8(n: usize) -> u8 {
    log2_strict_usize(n) as u8
}

/// Ceiling log₂ returning `u8`.
///
/// Returns `0` for `n = 0` or `n = 1`; otherwise the smallest `k` such that
/// `2^k >= n`. Panics if the result exceeds `u8::MAX` (impossible in practice).
#[inline]
pub fn log2_ceil_u8(n: usize) -> u8 {
    log2_ceil_usize(n) as u8
}
