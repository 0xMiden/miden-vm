//! FIPS 202 constants for Keccak-f[1600] and Keccak-256.
//!
//! Source of truth for the Rust reference implementation in
//! [`super::reference`]. Auditing this file is sufficient to verify constant
//! correctness; consumers parameterise on these values rather than hard-coding
//! their own. The MASM port at
//! `crates/lib/core/asm/crypto/hashes/keccak256_native.masm` reproduces the
//! same constants by hand.
//!
//! All section references are to NIST FIPS 202 (August 2015):
//! "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions".

// STATE LAYOUT
// ================================================================================================

/// Number of lanes in the Keccak-f[1600] state. Layout is a 5x5 grid of
/// 64-bit lanes (FIPS 202, sec. 3.1).
pub const NUM_LANES: usize = 25;

/// Number of rounds in Keccak-f[1600] (FIPS 202, sec. 3.4):
/// `n_r = 12 + 2*l` where `l = log2(w/25) = 6` for `w = 1600/25 = 64`,
/// giving `n_r = 24`.
pub const NUM_ROUNDS: usize = 24;

/// Lane index for grid coordinates `(x, y)`, where `x, y in 0..5`.
/// The state is laid out in row-major order with `y` (the row) outer:
/// lane `(x, y)` lives at index `5*y + x`.
#[inline]
pub const fn lane_idx(x: usize, y: usize) -> usize {
    debug_assert!(x < 5 && y < 5);
    5 * y + x
}

// RHO STEP: ROTATION OFFSETS
// ================================================================================================

/// Rotation offsets for the rho step (FIPS 202, sec. 3.2.2, Algorithm 2).
///
/// Indexed by `lane_idx(x, y)`. Each value is the left-rotation amount applied
/// to lane `(x, y)`. Reproduces FIPS 202 Table 1:
///
/// ```text
///        x=0   x=1   x=2   x=3   x=4
/// y=0:    0     1    62    28    27
/// y=1:   36    44     6    55    20
/// y=2:    3    10    43    25    39
/// y=3:   41    45    15    21     8
/// y=4:   18     2    61    56    14
/// ```
///
/// (Note that FIPS 202 displays the table transposed, with x as the row.
/// The values here are arranged in `[lane_idx(x, y) for y in 0..5 for x in 0..5]`
/// order, i.e. row-major with y outer to match `lane_idx`.)
#[rustfmt::skip]
pub const RHO: [u32; NUM_LANES] = [
    //   x=0  x=1  x=2  x=3  x=4
          0,   1,  62,  28,  27,   // y = 0
         36,  44,   6,  55,  20,   // y = 1
          3,  10,  43,  25,  39,   // y = 2
         41,  45,  15,  21,   8,   // y = 3
         18,   2,  61,  56,  14,   // y = 4
];

// IOTA STEP: ROUND CONSTANTS
// ================================================================================================

/// Round constants for the iota step (FIPS 202, sec. 3.2.5, Algorithm 6).
///
/// `IOTA[r]` is XORed into lane `(0, 0)` after the chi step of round `r`.
/// These are the `RC[r]` values from FIPS 202 Table 2 (24 values for `n_r = 24`),
/// reproduced verbatim from the standard.
pub const IOTA: [u64; NUM_ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

// SPONGE PARAMETERS
// ================================================================================================

/// Keccak-256 rate in bytes (FIPS 202, sec. 6.1).
///
/// Capacity `c = 2 * d = 512 bits` (where `d = 256` is the output length);
/// rate `r = b - c = 1600 - 512 = 1088 bits = 136 bytes`. The first 17 lanes
/// of the state hold the rate portion; the remaining 8 hold the capacity.
pub const RATE_BYTES: usize = 136;

/// Number of rate lanes (= `RATE_BYTES / 8 = 17`). The capacity occupies
/// the remaining `NUM_LANES - RATE_LANES = 8` lanes.
pub const RATE_LANES: usize = RATE_BYTES / 8;

/// Keccak-256 output length in bytes (FIPS 202, sec. 6.1: `d = 256` bits).
pub const DIGEST_BYTES: usize = 32;

/// Domain-separator byte appended to the message during padding.
///
/// **Important**: this is the *Keccak* (pre-FIPS) variant used by Ethereum
/// (`0x01`), not the FIPS-202 SHA-3 variant (`0x06`). The two share the
/// permutation but disagree on this single byte; mixing them produces
/// completely different digests.
///
/// The padding rule (multi-rate `pad10*1`) is implemented as:
///   1. Append `DOMAIN_BYTE` after the message.
///   2. Zero-pad to one byte short of the rate boundary.
///   3. OR `0x80` into the final byte of the padded block.
pub const DOMAIN_BYTE: u8 = 0x01;
