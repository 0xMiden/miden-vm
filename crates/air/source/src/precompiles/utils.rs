//! Helpers shared across chiplets.
//!
//! **Field-element packing** ([`pack_le`], [`halves_le`]) — LSB-first base-`base` digit
//! reconstruction. Generic over the expression type `E` and the variable type `V`, so the same
//! helpers evaluate borrowed constraint or lookup expressions using Horner's method.
//!
//! Typical packing bases:
//!
//! - `base = 2` — bit decomposition reconstruction (e.g.
//!   [`byte_pair_lut`](crate::precompiles::primitives::byte_pair_lut)'s 8-bit operand
//!   reconstruction).
//! - `base = 256` — byte-into-32-bit-half packing (e.g. the `KeccakRound` bitwise chiplet's 64-bit
//!   lane split).

use miden_core::{Felt, field::Algebra};
use p3_field::Dup;

/// Pack base-`base` digits LSB-first into a Felt-algebra expression.
///
/// Computes `items[0] + base·items[1] + base²·items[2] + …` via
/// Horner's method. `E: Algebra<Felt>` is the natural shape for any
/// native constraint or lookup expression over Felt. `base` must fit in the
/// canonical Goldilocks range (i.e. `base < 2^64 − 2^32 + 1`).
pub fn pack_le<E: Algebra<Felt>, V: Dup + Into<E>>(items: &[V], base: u64) -> E {
    let base = Felt::new(base).expect("base fits in canonical Goldilocks range");
    items.iter().rev().fold(E::ZERO, |acc, item| acc * base + item.dup().into())
}

/// Split `items` in half and [`pack_le`] each half independently.
///
/// `items.len()` must be even; returns `[lo, hi]` where `lo` packs
/// the first half and `hi` packs the second.
///
/// Common use: splitting a 64-bit lane (8 bytes, `base = 256`) into the
/// two 32-bit halves needed because a single `Felt` cannot hold a full
/// `u64` canonically (Goldilocks `p ≈ 2^64 − 2^32 + 1`).
pub fn halves_le<E: Algebra<Felt>, V: Dup + Into<E>>(items: &[V], base: u64) -> [E; 2] {
    debug_assert_eq!(items.len() % 2, 0, "items.len() must be even");
    let (lo, hi) = items.split_at(items.len() / 2);
    [pack_le::<E, V>(lo, base), pack_le::<E, V>(hi, base)]
}

/// Split a `u64` into 32-bit halves as `[lo, hi]`, each held in a `u64`
/// (zero-extended).
///
/// `lo = x & 0xFFFF_FFFF`, `hi = x >> 32`. Useful when the halves feed
/// into further `u64` arithmetic before becoming `Felt`s — e.g.
/// `(lo + 2^32)·k` in the `KeccakRound` bitwise chiplet's ROL row
/// construction, where doing the multiply in `u64` then converting is
/// cheaper than going through `Felt` mid-stream.
pub fn split_u64_u32(x: u64) -> [u64; 2] {
    [x & 0xffff_ffff, x >> 32]
}

/// Split a `u64` into 32-bit halves as `[lo, hi]` field elements.
///
/// Goldilocks `p ≈ 2^64 − 2^32 + 1` cannot represent every `u64`
/// canonically, so 64-bit lane chiplets commit and encode the two
/// 32-bit halves rather than the full 64-bit value.
pub fn split_u64(x: u64) -> [Felt; 2] {
    let [lo, hi] = split_u64_u32(x);
    [Felt::from(lo as u32), Felt::from(hi as u32)]
}
