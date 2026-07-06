//! Helpers shared across chiplets.
//!
//! Two themes:
//!
//! - **Field-element packing** ([`pack_le`], [`halves_le`]) — LSB-first
//!   base-`base` digit reconstruction. Generic over the expression type
//!   `E` and the variable type `V`, so the same helpers serve constraint
//!   evaluation against either an `AirBuilder` or a `LookupBuilder`.
//!   Both use Horner's method.
//! - **Two-row window access** ([`current_main`], [`next_main`]) — extract
//!   a fixed-size `[V; N]` from the current or next slice of any
//!   [`WindowAccess`]-bearing window. Used to pull a row out of
//!   `builder.main()` (or any other windowed source) and release the
//!   window's borrow before calling further mutating methods on the
//!   builder.
//!
//! Typical packing bases:
//!
//! - `base = 2` — bit decomposition reconstruction (e.g.
//!   [`byte_pair_lut`](crate::primitives::byte_pair_lut)'s 8-bit operand reconstruction).
//! - `base = 256` — byte-into-32-bit-half packing (e.g.
//!   [`bitwise64`](crate::primitives::bitwise64)'s 64-bit lane split).

use core::array;

use miden_core::{Felt, field::Algebra};
use p3_air::WindowAccess;

/// Pack base-`base` digits LSB-first into a Felt-algebra expression.
///
/// Computes `items[0] + base·items[1] + base²·items[2] + …` via
/// Horner's method. `E: Algebra<Felt>` is the natural shape for any
/// `AirBuilder::Expr` or `LookupBuilder::Expr` over Felt — both
/// satisfy `Algebra<Self::F>` with `F = Felt`. `base` must fit in the
/// canonical Goldilocks range (i.e. `base < 2^64 − 2^32 + 1`).
pub fn pack_le<E: Algebra<Felt>, V: Copy + Into<E>>(items: &[V], base: u64) -> E {
    let base = Felt::new(base).expect("base fits in canonical Goldilocks range");
    items
        .iter()
        .rev()
        .fold(E::ZERO, |acc, &item| acc * base + item.into())
}

/// Split `items` in half and [`pack_le`] each half independently.
///
/// `items.len()` must be even; returns `[lo, hi]` where `lo` packs
/// the first half and `hi` packs the second.
///
/// Common use: splitting a 64-bit lane (8 bytes, `base = 256`) into the
/// two 32-bit halves needed because a single `Felt` cannot hold a full
/// `u64` canonically (Goldilocks `p ≈ 2^64 − 2^32 + 1`).
pub fn halves_le<E: Algebra<Felt>, V: Copy + Into<E>>(items: &[V], base: u64) -> [E; 2] {
    debug_assert_eq!(items.len() % 2, 0, "items.len() must be even");
    let (lo, hi) = items.split_at(items.len() / 2);
    [pack_le::<E, V>(lo, base), pack_le::<E, V>(hi, base)]
}

/// Snapshot `N` consecutive elements from `window`'s current slice,
/// starting at column `start`.
///
/// Generic over any [`WindowAccess`]-bearing window so it works against
/// `AirBuilder::main()` (returns a constraint-side window),
/// `LookupBuilder::main()` (returns the lookup-builder's mirror), or
/// any other source that exposes the same trait. Pass `start = 0` for
/// the full row.
///
/// Consuming the window by value lets the caller write the typical
/// terse form `current_main(builder.main(), 0)` — the helper produces
/// an owned `[V; N]` and drops the window so the caller can freely
/// resume mutating builder methods afterward.
pub fn current_main<W, V, const N: usize>(window: W, start: usize) -> [V; N]
where
    W: WindowAccess<V>,
    V: Copy,
{
    let row = window.current_slice();
    array::from_fn(|i| row[start + i])
}

/// Like [`current_main`], but reads from the next (cyclic) row.
pub fn next_main<W, V, const N: usize>(window: W, start: usize) -> [V; N]
where
    W: WindowAccess<V>,
    V: Copy,
{
    let row = window.next_slice();
    array::from_fn(|i| row[start + i])
}

/// Split a `u64` into 32-bit halves as `[lo, hi]`, each held in a `u64`
/// (zero-extended).
///
/// `lo = x & 0xFFFF_FFFF`, `hi = x >> 32`. Useful when the halves feed
/// into further `u64` arithmetic before becoming `Felt`s — e.g.
/// `(lo + 2^32)·k` in [`bitwise64`](crate::primitives::bitwise64)'s ROL row
/// construction, where doing the multiply in `u64` then converting is
/// cheaper than going through `Felt` mid-stream.
pub fn split_u64_u32(x: u64) -> [u64; 2] {
    [x & 0xFFFF_FFFF, x >> 32]
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
