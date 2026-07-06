//! Reference Keccak-f[1600] permutation, FIPS 202 §3.2.
//!
//! Straightforward `u64` implementation, used as an oracle in tests and
//! by the sponge chiplet's [`crate::hash::keccak::sponge`] trace generation
//! to fill state-lane witness values. State is indexed `state[x + 5·y]`
//! with `x, y ∈ [0, 5)` matching FIPS 202's coordinate convention.
//!
//! `KECCAK_RC` (the round constants) is defined in
//! [`crate::hash::keccak::sponge::program`] alongside the periodic-column
//! representation; this module re-exposes it for the reference path's
//! convenience but doesn't redefine it.

pub use crate::hash::keccak::sponge::program::KECCAK_RC;

/// Per-lane rotation amounts (`RHO[x][y]`) from FIPS 202 Table 2.
const RHO: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// Apply one Keccak-f round to `state` with round constant `rc`.
///
/// Performs θ, ρ + π, χ, ι in order on a 25-lane (1600-bit) state.
pub fn keccak_round(state: &mut [u64; 25], rc: u64) {
    // θ.
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    for x in 0..5 {
        for y in 0..5 {
            state[x + 5 * y] ^= d[x];
        }
    }

    // ρ + π.
    let mut b = [0u64; 25];
    for x in 0..5 {
        for y in 0..5 {
            b[y + 5 * ((2 * x + 3 * y) % 5)] = state[x + 5 * y].rotate_left(RHO[x][y]);
        }
    }

    // χ.
    for y in 0..5 {
        for x in 0..5 {
            state[x + 5 * y] =
                b[x + 5 * y] ^ ((!b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
        }
    }

    // ι.
    state[0] ^= rc;
}

/// Run all 24 rounds of Keccak-f[1600] on the input state, returning the
/// permutation output.
pub fn keccak_f1600(state: [u64; 25]) -> [u64; 25] {
    let mut s = state;
    for r in 0..24 {
        keccak_round(&mut s, KECCAK_RC[r]);
    }
    s
}
