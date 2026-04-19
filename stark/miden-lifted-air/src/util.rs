//! Small utility helpers shared across lifted-STARK crates.

use p3_util::log2_strict_usize;

/// Strict log₂ returning `u8`.
///
/// Panics if `n` is not a power of two, or if the result exceeds `u8::MAX`
/// (i.e., `n >= 2^256` — impossible on any real platform).
#[inline]
pub fn log2_strict_u8(n: usize) -> u8 {
    log2_strict_usize(n) as u8
}
