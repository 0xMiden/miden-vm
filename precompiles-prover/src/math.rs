//! Value-layer 256-bit modular arithmetic over [`ruint`] — the witness
//! computations the Session and the trace generators perform before
//! anything reaches a trace cell, in one namespace instead of hand-rolled
//! word loops scattered near their call sites. The trace layers keep only
//! their carry- and γ-polynomial helpers: those are AIR shapes, not
//! arithmetic.
//!
//! Convention: a modulus is stored as `bound = p − 1` (≤ [`U256::MAX`]),
//! so `p = bound + 1` ranges up to `2²⁵⁶` — one bit past [`U256`].
//! Reductions lift into [`U320`] / [`U576`] headroom internally and
//! return canonical values `≤ bound`. All inputs are expected canonical;
//! the [`ruint`] operators wrap, and every interior expression below
//! stays inside its width by construction.

use core::array;

pub use ruint::aliases::{U256, U320, U512};

/// Headroom for `κₐ·a·b + κ_c·c`: `2¹⁶·2⁵¹² = 2⁵²⁸ < 2⁵⁷⁶`.
pub type U576 = ruint::Uint<576, 9>;

// LIMB VIEWS
// ================================================================================================

/// From the store's canonical view: 16 LE 16-bit limbs.
pub fn from_limbs16(v: &[u16; 16]) -> U256 {
    U256::from_limbs(array::from_fn(|w| {
        (0..4).fold(0u64, |acc, i| acc | (u64::from(v[4 * w + i]) << (16 * i)))
    }))
}

/// The store's canonical view: 16 LE 16-bit limbs.
pub fn to_limbs16(v: U256) -> [u16; 16] {
    array::from_fn(|i| (v.as_limbs()[i / 4] >> (16 * (i % 4))) as u16)
}

/// From the 4×32 view: 8 LE 32-bit limbs.
pub fn from_limbs32(v: &[u32; 8]) -> U256 {
    U256::from_limbs(array::from_fn(|w| u64::from(v[2 * w]) | (u64::from(v[2 * w + 1]) << 32)))
}

/// The 4×32 view (the eval chip's Poseidon2-rate halves): 8 LE 32-bit
/// limbs.
pub fn to_limbs32(v: U256) -> [u32; 8] {
    array::from_fn(|i| (v.as_limbs()[i / 2] >> (32 * (i % 2))) as u32)
}

/// Big-endian hex, the KAT-fixture format (no `0x` prefix, ≤ 64 nibbles).
pub fn from_hex(s: &str) -> U256 {
    U256::from_str_radix(s, 16).expect("valid big-endian hex")
}

// MODULAR ARITHMETIC (p = bound + 1)
// ================================================================================================

fn p320(bound: U256) -> U320 {
    U320::from(bound) + U320::ONE
}

/// `(a + b) mod p`.
pub fn add_reduce(a: U256, b: U256, bound: U256) -> U256 {
    U320::from(a).add_mod(U320::from(b), p320(bound)).to()
}

/// `(a − b) mod p`, as `a + (p − b)` — no negative anything exists
/// anywhere.
pub fn sub_reduce(a: U256, b: U256, bound: U256) -> U256 {
    let p = p320(bound);
    U320::from(a).add_mod(p - U320::from(b), p).to()
}

/// `(κₐ·a·b + κ_c·c) mod p` — the scaled-MAC reduction.
pub fn mac_reduce(kappa_a: u16, a: U256, b: U256, kappa_c: u16, c: U256, bound: U256) -> U256 {
    mac_div_rem(kappa_a, a, b, kappa_c, c, bound).1
}

/// `(q, r)` of `(κₐ·a·b + κ_c·c) / p`. For canonical operands
/// (`a, b, c ≤ bound`) the quotient is `< κₐ·p ≤ 2²⁷²` — the trace's 17
/// 16-bit quotient limbs; the contract check stays with the trace layer.
pub fn mac_div_rem(
    kappa_a: u16,
    a: U256,
    b: U256,
    kappa_c: u16,
    c: U256,
    bound: U256,
) -> (U320, U256) {
    let ab: U512 = a.widening_mul(b);
    let n = U576::from(ab) * U576::from(kappa_a) + U576::from(c) * U576::from(kappa_c);
    let (q, r) = n.div_rem(U576::from(bound) + U576::ONE);
    (q.to(), r.to())
}

/// `v⁻¹ mod p` (requires `gcd(v, p) = 1`) — the witness inverse for
/// slope denominators and friends. Extended-gcd under the hood, so no
/// primality assumption.
pub fn mod_inv(v: U256, bound: U256) -> U256 {
    U320::from(v)
        .inv_mod(p320(bound))
        .expect("value not invertible under the modulus")
        .to()
}
