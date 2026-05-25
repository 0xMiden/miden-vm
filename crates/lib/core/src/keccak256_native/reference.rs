//! Rust reference implementation of Keccak-256, used as the comparison target
//! for the MASM Keccak-256 port at
//! `crates/lib/core/asm/crypto/hashes/keccak256_native.masm`. Mirrors the FIPS
//! 202 pseudocode line-for-line, prioritising readability over performance:
//! every state-mutating step lives in its own function with a docstring citing
//! the corresponding FIPS section.
//!
//! Cross-checked against [`miden_core::crypto::hash::Keccak256`] via the
//! proptest in `tests/crypto/keccak256_native.rs`, so a typo in this mirror
//! would be caught by an independent production implementation.
//!
//! All section references are to NIST FIPS 202 (August 2015).

use alloc::{format, string::String};

use super::spec::{
    DIGEST_BYTES, DOMAIN_BYTE, IOTA, NUM_LANES, NUM_ROUNDS, RATE_BYTES, RATE_LANES, RHO, lane_idx,
};

/// The 25-lane state for `Keccak-f[1600]`. Lane `(x, y)` lives at index `lane_idx(x, y)`.
pub type State = [u64; NUM_LANES];

// PERMUTATION STEPS
// ================================================================================================

/// Theta step (FIPS 202, sec. 3.2.1, Algorithm 1).
///
///   `C[x] = A[x, 0] XOR A[x, 1] XOR A[x, 2] XOR A[x, 3] XOR A[x, 4]`
///   `D[x] = C[x-1] XOR ROT(C[x+1], 1)`
///   `A'[x, y] = A[x, y] XOR D[x]`
///
/// All indices are mod 5.
pub fn theta(s: &mut State) {
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = s[lane_idx(x, 0)]
            ^ s[lane_idx(x, 1)]
            ^ s[lane_idx(x, 2)]
            ^ s[lane_idx(x, 3)]
            ^ s[lane_idx(x, 4)];
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    for y in 0..5 {
        for x in 0..5 {
            s[lane_idx(x, y)] ^= d[x];
        }
    }
}

/// Rho step (FIPS 202, sec. 3.2.2, Algorithm 2).
///
///   `A'[x, y] = ROT(A[x, y], RHO[x, y])`
///
/// where `RHO[x, y]` is the rotation table from FIPS 202 sec. 3.2.2 Table 1
/// (mirrored in [`super::spec::RHO`]).
pub fn rho(s: &mut State) {
    for i in 0..NUM_LANES {
        s[i] = s[i].rotate_left(RHO[i]);
    }
}

/// Pi step (FIPS 202, sec. 3.2.3, Algorithm 3).
///
///   `A'[x, y] = A[(x + 3*y) mod 5, x]`
///
/// All indices are mod 5. The substitution is computed out-of-place because
/// each output lane reads from a different input lane.
pub fn pi(s: &mut State) {
    let original = *s;
    for y in 0..5 {
        for x in 0..5 {
            s[lane_idx(x, y)] = original[lane_idx((x + 3 * y) % 5, x)];
        }
    }
}

/// Chi step (FIPS 202, sec. 3.2.4, Algorithm 4).
///
///   `A'[x, y] = A[x, y] XOR ((NOT A[x+1, y]) AND A[x+2, y])`
///
/// Indices on `x` are mod 5. Each row `y` is processed independently; the
/// per-row computation is staged into a snapshot so the in-place update reads
/// pre-step values.
pub fn chi(s: &mut State) {
    for y in 0..5 {
        let mut row = [0u64; 5];
        for x in 0..5 {
            row[x] = s[lane_idx(x, y)];
        }
        for x in 0..5 {
            s[lane_idx(x, y)] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
        }
    }
}

/// Iota step (FIPS 202, sec. 3.2.5, Algorithm 6).
///
///   `A'[0, 0] = A[0, 0] XOR RC[round]`
///
/// where `RC[round]` is from FIPS 202 sec. 3.2.5 Table 2 (mirrored in
/// [`super::spec::IOTA`]). `round` must be in `0..NUM_ROUNDS`.
pub fn iota(s: &mut State, round: usize) {
    s[lane_idx(0, 0)] ^= IOTA[round];
}

/// One `Keccak-f[1600]` round (FIPS 202, sec. 3.3, Algorithm 7).
pub fn round(s: &mut State, r: usize) {
    theta(s);
    rho(s);
    pi(s);
    chi(s);
    iota(s, r);
}

/// Full `Keccak-f[1600]` permutation: [`NUM_ROUNDS`] rounds applied in sequence.
pub fn permute(s: &mut State) {
    for r in 0..NUM_ROUNDS {
        round(s, r);
    }
}

// SPONGE: KECCAK-256 HASH
// ================================================================================================

/// Keccak-256 hash of an arbitrary byte slice. Returns the 32-byte digest.
///
/// Uses the sponge construction with rate [`RATE_BYTES`] and the multi-rate
/// padding rule from FIPS 202 sec. B.2 (with the Keccak/Ethereum domain byte
/// [`DOMAIN_BYTE`] = `0x01`, *not* the SHA-3 byte `0x06`).
pub fn keccak256(input: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut state: State = [0u64; NUM_LANES];

    // Absorb every full rate-sized block.
    let mut chunks = input.chunks_exact(RATE_BYTES);
    for chunk in chunks.by_ref() {
        absorb_block(&mut state, chunk);
        permute(&mut state);
    }

    // Final block: pad the remainder up to one rate-sized block, then absorb.
    let remainder = chunks.remainder();
    let mut padded = [0u8; RATE_BYTES];
    padded[..remainder.len()].copy_from_slice(remainder);
    padded[remainder.len()] = DOMAIN_BYTE;
    padded[RATE_BYTES - 1] |= 0x80;
    absorb_block(&mut state, &padded);
    permute(&mut state);

    // Squeeze the first DIGEST_BYTES bytes from the rate portion. For
    // Keccak-256 the digest fits inside a single squeeze (32 < 136 bytes).
    let mut out = [0u8; DIGEST_BYTES];
    for (i, byte) in out.iter_mut().enumerate() {
        let lane = i / 8;
        let shift = 8 * (i % 8);
        *byte = (state[lane] >> shift) as u8;
    }
    out
}

/// XOR a full rate-sized block of bytes into the rate portion of `state`.
/// Bytes are interpreted as little-endian u64 lanes (FIPS 202 sec. B.1).
fn absorb_block(state: &mut State, block: &[u8]) {
    debug_assert_eq!(block.len(), RATE_BYTES);
    for i in 0..RATE_LANES {
        let lane_bytes: [u8; 8] = block[8 * i..8 * (i + 1)].try_into().expect("8-byte slice");
        state[i] ^= u64::from_le_bytes(lane_bytes);
    }
}

// DEBUG HELPER
// ================================================================================================

/// Pretty-print a Keccak state as a 5x5 grid of hex u64 values, with `y` as
/// the row and `x` as the column. Used by the MASM differential-test harness
/// to surface *where* in a round a divergence occurred.
///
/// Example output (state initialised to `1, 2, ..., 25`):
///
/// ```text
/// 0000000000000001 0000000000000002 0000000000000003 0000000000000004 0000000000000005
/// 0000000000000006 0000000000000007 0000000000000008 0000000000000009 000000000000000a
/// 000000000000000b 000000000000000c 000000000000000d 000000000000000e 000000000000000f
/// 0000000000000010 0000000000000011 0000000000000012 0000000000000013 0000000000000014
/// 0000000000000015 0000000000000016 0000000000000017 0000000000000018 0000000000000019
/// ```
pub fn format_state(s: &State) -> String {
    let mut out = String::new();
    for y in 0..5 {
        for x in 0..5 {
            if x > 0 {
                out.push(' ');
            }
            out.push_str(&format!("{:016x}", s[lane_idx(x, y)]));
        }
        out.push('\n');
    }
    out
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke check that `format_state` produces the documented layout for a
    /// state initialised to `[1, 2, ..., 25]`. Catches accidental row/column
    /// transposition in the debug helper itself.
    #[test]
    fn format_state_grid_layout() {
        let mut s = [0u64; NUM_LANES];
        for (i, lane) in s.iter_mut().enumerate() {
            *lane = (i + 1) as u64;
        }
        let formatted = format_state(&s);
        let expected = "\
0000000000000001 0000000000000002 0000000000000003 0000000000000004 0000000000000005
0000000000000006 0000000000000007 0000000000000008 0000000000000009 000000000000000a
000000000000000b 000000000000000c 000000000000000d 000000000000000e 000000000000000f
0000000000000010 0000000000000011 0000000000000012 0000000000000013 0000000000000014
0000000000000015 0000000000000016 0000000000000017 0000000000000018 0000000000000019
";
        assert_eq!(formatted, expected);
    }

    /// `lane_idx` is the inverse of `(idx -> (x = idx % 5, y = idx / 5))`.
    #[test]
    fn lane_idx_round_trips() {
        for y in 0..5 {
            for x in 0..5 {
                let idx = lane_idx(x, y);
                assert_eq!(idx % 5, x);
                assert_eq!(idx / 5, y);
            }
        }
    }
}
