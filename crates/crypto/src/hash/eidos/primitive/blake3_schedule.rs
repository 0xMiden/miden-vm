//! Local BLAKE3 compression schedule used by Eidos.
//!
//! This module owns only the raw BLAKE3 round schedule and architecture-specific packed
//! backends. Eidos compression output masking, field packing, and Eidos framing stay in
//! `primitive.rs` and `framing.rs`. The local schedule accepts batches of caller-supplied chaining
//! values and message blocks and exposes the raw CV and XOF folds required by Eidos.

#[cfg(any(
    test,
    not(target_arch = "x86_64"),
    feature = "std",
    not(target_feature = "avx512f")
))]
use core::array;

#[cfg(target_arch = "x86_64")]
mod row_x86;

/// BLAKE3 IV.
pub(super) const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

#[cfg(any(test, not(target_arch = "x86_64")))]
const ROUNDS: usize = 7;

/// BLAKE3 message-word schedule for the compression rounds.
#[cfg(any(test, not(target_arch = "x86_64")))]
const MSG_SCHEDULE: [[usize; 16]; ROUNDS] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// Fixed logical width of a packed compression batch.
///
/// This is independent of any particular SIMD backend. Every backend below fills a 16-lane
/// batch using as many physical-width calls as its vector registers need: one call of 16 for
/// AVX-512, two calls of 8 for AVX2, four calls of 4 for SSE2 or NEON. A stable logical width
/// keeps `PackedFelt` and friends the same public type regardless of which physical backend
/// ends up selected.
pub(super) const PACKED_LANES: usize = 16;

/// Splits a `PACKED_LANES`-wide batch into `PACKED_LANES / W` sub-batches of width `W`, applies
/// `f` to each, and reassembles the results.
#[cfg(any(
    all(target_arch = "x86_64", feature = "std"),
    all(target_arch = "x86_64", not(target_feature = "avx512f")),
    all(target_arch = "aarch64", target_feature = "neon"),
))]
#[inline]
fn compress_via_sub_batches<const W: usize>(
    cv: &[[u32; PACKED_LANES]; 8],
    block: &[[u32; PACKED_LANES]; 16],
    f: impl Fn([[u32; W]; 8], [[u32; W]; 16]) -> [[u32; W]; 8],
) -> [[u32; PACKED_LANES]; 8] {
    let mut out = [[0u32; PACKED_LANES]; 8];
    for chunk in 0..(PACKED_LANES / W) {
        let base = chunk * W;
        let sub_cv: [[u32; W]; 8] =
            array::from_fn(|word| array::from_fn(|lane| cv[word][base + lane]));
        let sub_block: [[u32; W]; 16] =
            array::from_fn(|word| array::from_fn(|lane| block[word][base + lane]));
        let sub_out = f(sub_cv, sub_block);
        for (word, sub_word) in out.iter_mut().zip(sub_out) {
            word[base..base + W].copy_from_slice(&sub_word);
        }
    }
    out
}

/// Backend selection: on x86_64 with the `std` feature, the physical SIMD tier (AVX-512, AVX2,
/// or SSE2) is detected once at runtime and cached, so an off-the-shelf build picks up whatever
/// the host CPU actually supports. Without `std` (or off x86_64), selection falls back to
/// `target_feature` cfg, exactly as before: a native build needs `-C target-cpu=native` or an
/// explicit `+avx2`/`+avx512f` to get past the SSE2/NEON baseline.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
mod native_backend {
    use once_cell::sync::Lazy;

    use super::{PACKED_LANES, compress_via_sub_batches, x86_64_avx2, x86_64_avx512, x86_64_sse2};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Tier {
        Avx512,
        Avx2,
        Sse2,
    }

    fn detect() -> Tier {
        if std::is_x86_feature_detected!("avx512f") {
            Tier::Avx512
        } else if std::is_x86_feature_detected!("avx2") {
            Tier::Avx2
        } else {
            Tier::Sse2
        }
    }

    static TIER: Lazy<Tier> = Lazy::new(detect);

    #[inline]
    pub(super) fn compress(
        cv: &[[u32; PACKED_LANES]; 8],
        block: &[[u32; PACKED_LANES]; 16],
    ) -> [[u32; PACKED_LANES]; 8] {
        match *TIER {
            Tier::Avx512 => {
                // SAFETY: `TIER` only reports `Avx512` after `is_x86_feature_detected!("avx512f")`
                // returned true for the running CPU.
                unsafe { x86_64_avx512::compress_packed_16(*cv, *block) }
            },
            Tier::Avx2 => compress_via_sub_batches::<8>(cv, block, |cv, block| {
                // SAFETY: `TIER` only reports `Avx2` after `is_x86_feature_detected!("avx2")`
                // returned true for the running CPU.
                unsafe { x86_64_avx2::compress_packed_8(cv, block) }
            }),
            Tier::Sse2 => compress_via_sub_batches::<4>(cv, block, |cv, block| {
                // SAFETY: SSE2 is part of the x86_64 architectural baseline.
                unsafe { x86_64_sse2::compress_packed_4(cv, block) }
            }),
        }
    }
}

#[cfg(all(target_arch = "x86_64", not(feature = "std"), target_feature = "avx512f"))]
mod native_backend {
    use super::PACKED_LANES;

    #[inline(always)]
    pub(super) fn compress(
        cv: &[[u32; PACKED_LANES]; 8],
        block: &[[u32; PACKED_LANES]; 16],
    ) -> [[u32; PACKED_LANES]; 8] {
        // SAFETY: this module only compiles when `target_feature = "avx512f"` is enabled
        // crate-wide (e.g. via `-C target-cpu=native` or `-C target-feature=+avx512f`).
        unsafe { super::x86_64_avx512::compress_packed_16(*cv, *block) }
    }
}

#[cfg(all(
    target_arch = "x86_64",
    not(feature = "std"),
    target_feature = "avx2",
    not(target_feature = "avx512f")
))]
mod native_backend {
    use super::{PACKED_LANES, compress_via_sub_batches};

    #[inline(always)]
    pub(super) fn compress(
        cv: &[[u32; PACKED_LANES]; 8],
        block: &[[u32; PACKED_LANES]; 16],
    ) -> [[u32; PACKED_LANES]; 8] {
        compress_via_sub_batches::<8>(cv, block, |cv, block| {
            // SAFETY: this module only compiles when `target_feature = "avx2"` is enabled
            // crate-wide (e.g. via `-C target-cpu=native` or `-C target-feature=+avx2`).
            unsafe { super::x86_64_avx2::compress_packed_8(cv, block) }
        })
    }
}

#[cfg(all(
    target_arch = "x86_64",
    not(feature = "std"),
    not(target_feature = "avx2"),
    not(target_feature = "avx512f")
))]
mod native_backend {
    use super::{PACKED_LANES, compress_via_sub_batches};

    #[inline(always)]
    pub(super) fn compress(
        cv: &[[u32; PACKED_LANES]; 8],
        block: &[[u32; PACKED_LANES]; 16],
    ) -> [[u32; PACKED_LANES]; 8] {
        compress_via_sub_batches::<4>(cv, block, |cv, block| {
            // SAFETY: SSE2 is part of the x86_64 architectural baseline.
            unsafe { super::x86_64_sse2::compress_packed_4(cv, block) }
        })
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod native_backend {
    use super::PACKED_LANES;

    #[inline(always)]
    pub(super) fn compress(
        cv: &[[u32; PACKED_LANES]; 8],
        block: &[[u32; PACKED_LANES]; 16],
    ) -> [[u32; PACKED_LANES]; 8] {
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        {
            super::compress_via_sub_batches::<4>(cv, block, super::neon::compress_packed_4)
        }

        #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
        {
            super::compress_packed(*cv, *block)
        }
    }
}

/// Runtime dispatch for `row_x86`'s single-block path: `compress_pre` keeps up to 13 live
/// 128-bit vectors, which spills under the legacy 16-register SSE/AVX file on a default build
/// (measured ~30-37% slower than with a wider register file available). AVX-512VL's EVEX
/// encoding reaches XMM16-31 even for plain 128-bit operations, eliminating those spills with
/// the exact same instructions — so, like `native_backend` above, this is detected once at
/// runtime and cached under the `std` feature. Without `std` (or off x86_64), selection falls
/// back to `target_feature` cfg.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
mod row_dispatch {
    use once_cell::sync::Lazy;

    use super::row_x86;

    static HAS_AVX512VL: Lazy<bool> = Lazy::new(|| {
        std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512vl")
    });

    #[inline]
    pub(super) fn compress_raw(cv: &[u32; 8], block: &[u32; 16]) -> [u32; 8] {
        if *HAS_AVX512VL {
            // SAFETY: `HAS_AVX512VL` only true after `is_x86_feature_detected!` confirmed both
            // "avx512f" and "avx512vl" for the running CPU.
            unsafe { row_x86::compress_raw_avx512vl(cv, block) }
        } else {
            row_x86::compress_raw(cv, block)
        }
    }

    #[inline]
    pub(super) fn compress_raw_xof(cv: &[u32; 8], block: &[u32; 16]) -> [u32; 16] {
        if *HAS_AVX512VL {
            // SAFETY: see `compress_raw` above.
            unsafe { row_x86::compress_raw_xof_avx512vl(cv, block) }
        } else {
            row_x86::compress_raw_xof(cv, block)
        }
    }
}

#[inline(always)]
#[cfg(any(test, not(target_arch = "x86_64")))]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

#[inline(always)]
#[cfg(any(
    test,
    all(target_arch = "aarch64", not(target_feature = "neon")),
    not(any(target_arch = "aarch64", target_arch = "x86_64")),
))]
fn add_packed<const LANES: usize>(a: [u32; LANES], b: [u32; LANES]) -> [u32; LANES] {
    array::from_fn(|i| a[i].wrapping_add(b[i]))
}

#[inline(always)]
#[cfg(any(
    test,
    all(target_arch = "aarch64", not(target_feature = "neon")),
    not(any(target_arch = "aarch64", target_arch = "x86_64")),
))]
fn xor_packed<const LANES: usize>(a: [u32; LANES], b: [u32; LANES]) -> [u32; LANES] {
    array::from_fn(|i| a[i] ^ b[i])
}

#[inline(always)]
#[cfg(any(
    test,
    all(target_arch = "aarch64", not(target_feature = "neon")),
    not(any(target_arch = "aarch64", target_arch = "x86_64")),
))]
fn rotr_packed<const LANES: usize>(a: [u32; LANES], n: u32) -> [u32; LANES] {
    array::from_fn(|i| a[i].rotate_right(n))
}

#[inline(always)]
#[cfg(any(
    test,
    all(target_arch = "aarch64", not(target_feature = "neon")),
    not(any(target_arch = "aarch64", target_arch = "x86_64")),
))]
fn g_packed<const LANES: usize>(
    v: &mut [[u32; LANES]; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: [u32; LANES],
    y: [u32; LANES],
) {
    v[a] = add_packed(add_packed(v[a], v[b]), x);
    v[d] = rotr_packed(xor_packed(v[d], v[a]), 16);
    v[c] = add_packed(v[c], v[d]);
    v[b] = rotr_packed(xor_packed(v[b], v[c]), 12);
    v[a] = add_packed(add_packed(v[a], v[b]), y);
    v[d] = rotr_packed(xor_packed(v[d], v[a]), 8);
    v[c] = add_packed(v[c], v[d]);
    v[b] = rotr_packed(xor_packed(v[b], v[c]), 7);
}

#[inline(always)]
#[cfg(any(test, not(target_arch = "x86_64")))]
fn permuted_state_with_parameter_words(
    cv: [u32; 8],
    block: [u32; 16],
    parameter_words: [u32; 4],
) -> [u32; 16] {
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(&cv);
    v[8..12].copy_from_slice(&IV[..4]);
    v[12..16].copy_from_slice(&parameter_words);

    for s in MSG_SCHEDULE.iter() {
        g(&mut v, 0, 4, 8, 12, block[s[0]], block[s[1]]);
        g(&mut v, 1, 5, 9, 13, block[s[2]], block[s[3]]);
        g(&mut v, 2, 6, 10, 14, block[s[4]], block[s[5]]);
        g(&mut v, 3, 7, 11, 15, block[s[6]], block[s[7]]);
        g(&mut v, 0, 5, 10, 15, block[s[8]], block[s[9]]);
        g(&mut v, 1, 6, 11, 12, block[s[10]], block[s[11]]);
        g(&mut v, 2, 7, 8, 13, block[s[12]], block[s[13]]);
        g(&mut v, 3, 4, 9, 14, block[s[14]], block[s[15]]);
    }

    v
}

/// Returns the raw eight-word CV fold with Eidos compression's fixed parameter words.
pub(super) fn compress_raw(cv: [u32; 8], block: [u32; 16]) -> [u32; 8] {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        row_dispatch::compress_raw(&cv, &block)
    }

    #[cfg(all(target_arch = "x86_64", not(feature = "std"), target_feature = "avx512vl"))]
    {
        // SAFETY: this module only compiles when `target_feature = "avx512vl"` (and its
        // prerequisite `"avx512f"`) are enabled crate-wide (e.g. via `-C target-cpu=native` or
        // explicit `+avx512f,+avx512vl`).
        unsafe { row_x86::compress_raw_avx512vl(&cv, &block) }
    }

    #[cfg(all(target_arch = "x86_64", not(feature = "std"), not(target_feature = "avx512vl")))]
    {
        row_x86::compress_raw(&cv, &block)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let v = permuted_state_with_parameter_words(cv, block, [IV[4], IV[5], IV[6], IV[7]]);
        array::from_fn(|i| v[i] ^ v[i + 8])
    }
}

/// Returns the raw 16-word XOF fold with Eidos compression's fixed parameter words.
pub(super) fn compress_raw_xof(cv: [u32; 8], block: [u32; 16]) -> [u32; 16] {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        row_dispatch::compress_raw_xof(&cv, &block)
    }

    #[cfg(all(target_arch = "x86_64", not(feature = "std"), target_feature = "avx512vl"))]
    {
        // SAFETY: see `compress_raw` above.
        unsafe { row_x86::compress_raw_xof_avx512vl(&cv, &block) }
    }

    #[cfg(all(target_arch = "x86_64", not(feature = "std"), not(target_feature = "avx512vl")))]
    {
        row_x86::compress_raw_xof(&cv, &block)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let v = permuted_state_with_parameter_words(cv, block, [IV[4], IV[5], IV[6], IV[7]]);
        array::from_fn(|i| if i < 8 { v[i] ^ v[i + 8] } else { v[i] ^ cv[i - 8] })
    }
}

#[cfg(test)]
pub(super) fn compress_raw_with_parameter_words(
    cv: [u32; 8],
    block: [u32; 16],
    parameter_words: [u32; 4],
) -> [u32; 8] {
    let v = permuted_state_with_parameter_words(cv, block, parameter_words);
    array::from_fn(|i| v[i] ^ v[i + 8])
}

#[cfg(test)]
pub(super) fn compress_raw_xof_with_parameter_words(
    cv: [u32; 8],
    block: [u32; 16],
    parameter_words: [u32; 4],
) -> [u32; 16] {
    let v = permuted_state_with_parameter_words(cv, block, parameter_words);
    array::from_fn(|i| if i < 8 { v[i] ^ v[i + 8] } else { v[i] ^ cv[i - 8] })
}

/// Applies the raw BLAKE3 schedule to several independent lanes.
///
/// Lane `i` of the result is identical to `compress_raw(cv_i, block_i)`, where
/// `cv_i[j] = cv[j][i]` and `block_i[j] = block[j][i]`.
#[cfg(any(
    test,
    all(target_arch = "aarch64", not(target_feature = "neon")),
    not(any(target_arch = "aarch64", target_arch = "x86_64")),
))]
pub(super) fn compress_packed<const LANES: usize>(
    cv: [[u32; LANES]; 8],
    block: [[u32; LANES]; 16],
) -> [[u32; LANES]; 8] {
    let mut v = [[0u32; LANES]; 16];
    v[..8].copy_from_slice(&cv);
    for i in 0..8 {
        v[8 + i] = [IV[i]; LANES];
    }

    for s in MSG_SCHEDULE.iter() {
        g_packed(&mut v, 0, 4, 8, 12, block[s[0]], block[s[1]]);
        g_packed(&mut v, 1, 5, 9, 13, block[s[2]], block[s[3]]);
        g_packed(&mut v, 2, 6, 10, 14, block[s[4]], block[s[5]]);
        g_packed(&mut v, 3, 7, 11, 15, block[s[6]], block[s[7]]);
        g_packed(&mut v, 0, 5, 10, 15, block[s[8]], block[s[9]]);
        g_packed(&mut v, 1, 6, 11, 12, block[s[10]], block[s[11]]);
        g_packed(&mut v, 2, 7, 8, 13, block[s[12]], block[s[13]]);
        g_packed(&mut v, 3, 4, 9, 14, block[s[14]], block[s[15]]);
    }

    array::from_fn(|i| xor_packed(v[i], v[i + 8]))
}

/// Applies the raw BLAKE3 schedule to the build's selected native lane width.
#[inline]
pub(super) fn compress_packed_native(
    cv: &[[u32; PACKED_LANES]; 8],
    block: &[[u32; PACKED_LANES]; 16],
) -> [[u32; PACKED_LANES]; 8] {
    native_backend::compress(cv, block)
}

#[cfg(target_arch = "x86_64")]
#[rustfmt::skip]
macro_rules! define_x86_packed_compress {
    ($(#[$attr:meta])* $name:ident, $lanes:literal) => {
        $(#[$attr])*
        #[inline]
        pub(super) unsafe fn $name(
            cv: [[u32; $lanes]; 8],
            block: [[u32; $lanes]; 16],
        ) -> [[u32; $lanes]; 8] {
            let mut v0 = load(&cv[0]);
            let mut v1 = load(&cv[1]);
            let mut v2 = load(&cv[2]);
            let mut v3 = load(&cv[3]);
            let mut v4 = load(&cv[4]);
            let mut v5 = load(&cv[5]);
            let mut v6 = load(&cv[6]);
            let mut v7 = load(&cv[7]);
            let mut v8 = splat(IV[0]);
            let mut v9 = splat(IV[1]);
            let mut v10 = splat(IV[2]);
            let mut v11 = splat(IV[3]);
            let mut v12 = splat(IV[4]);
            let mut v13 = splat(IV[5]);
            let mut v14 = splat(IV[6]);
            let mut v15 = splat(IV[7]);

            macro_rules! round {
                (
                    $m0:literal,
                    $m1:literal,
                    $m2:literal,
                    $m3:literal,
                    $m4:literal,
                    $m5:literal,
                    $m6:literal,
                    $m7:literal,
                    $m8:literal,
                    $m9:literal,
                    $m10:literal,
                    $m11:literal,
                    $m12:literal,
                    $m13:literal,
                    $m14:literal,
                    $m15:literal
                ) => {{
                    let m0 = load(&block[$m0]);
                    let m1 = load(&block[$m1]);
                    let m2 = load(&block[$m2]);
                    let m3 = load(&block[$m3]);
                    let m4 = load(&block[$m4]);
                    let m5 = load(&block[$m5]);
                    let m6 = load(&block[$m6]);
                    let m7 = load(&block[$m7]);
                    let m8 = load(&block[$m8]);
                    let m9 = load(&block[$m9]);
                    let m10 = load(&block[$m10]);
                    let m11 = load(&block[$m11]);
                    let m12 = load(&block[$m12]);
                    let m13 = load(&block[$m13]);
                    let m14 = load(&block[$m14]);
                    let m15 = load(&block[$m15]);

                    v0 = add(add(v0, v4), m0);
                    v1 = add(add(v1, v5), m2);
                    v2 = add(add(v2, v6), m4);
                    v3 = add(add(v3, v7), m6);
                    v12 = rotr16(xor(v12, v0));
                    v13 = rotr16(xor(v13, v1));
                    v14 = rotr16(xor(v14, v2));
                    v15 = rotr16(xor(v15, v3));
                    v8 = add(v8, v12);
                    v9 = add(v9, v13);
                    v10 = add(v10, v14);
                    v11 = add(v11, v15);
                    v4 = rotr12(xor(v4, v8));
                    v5 = rotr12(xor(v5, v9));
                    v6 = rotr12(xor(v6, v10));
                    v7 = rotr12(xor(v7, v11));
                    v0 = add(add(v0, v4), m1);
                    v1 = add(add(v1, v5), m3);
                    v2 = add(add(v2, v6), m5);
                    v3 = add(add(v3, v7), m7);
                    v12 = rotr8(xor(v12, v0));
                    v13 = rotr8(xor(v13, v1));
                    v14 = rotr8(xor(v14, v2));
                    v15 = rotr8(xor(v15, v3));
                    v8 = add(v8, v12);
                    v9 = add(v9, v13);
                    v10 = add(v10, v14);
                    v11 = add(v11, v15);
                    v4 = rotr7(xor(v4, v8));
                    v5 = rotr7(xor(v5, v9));
                    v6 = rotr7(xor(v6, v10));
                    v7 = rotr7(xor(v7, v11));

                    v0 = add(add(v0, v5), m8);
                    v1 = add(add(v1, v6), m10);
                    v2 = add(add(v2, v7), m12);
                    v3 = add(add(v3, v4), m14);
                    v15 = rotr16(xor(v15, v0));
                    v12 = rotr16(xor(v12, v1));
                    v13 = rotr16(xor(v13, v2));
                    v14 = rotr16(xor(v14, v3));
                    v10 = add(v10, v15);
                    v11 = add(v11, v12);
                    v8 = add(v8, v13);
                    v9 = add(v9, v14);
                    v5 = rotr12(xor(v5, v10));
                    v6 = rotr12(xor(v6, v11));
                    v7 = rotr12(xor(v7, v8));
                    v4 = rotr12(xor(v4, v9));
                    v0 = add(add(v0, v5), m9);
                    v1 = add(add(v1, v6), m11);
                    v2 = add(add(v2, v7), m13);
                    v3 = add(add(v3, v4), m15);
                    v15 = rotr8(xor(v15, v0));
                    v12 = rotr8(xor(v12, v1));
                    v13 = rotr8(xor(v13, v2));
                    v14 = rotr8(xor(v14, v3));
                    v10 = add(v10, v15);
                    v11 = add(v11, v12);
                    v8 = add(v8, v13);
                    v9 = add(v9, v14);
                    v5 = rotr7(xor(v5, v10));
                    v6 = rotr7(xor(v6, v11));
                    v7 = rotr7(xor(v7, v8));
                    v4 = rotr7(xor(v4, v9));
                }};
            }

            round!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            round!(2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8);
            round!(3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1);
            round!(10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6);
            round!(12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4);
            round!(9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7);
            round!(11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13);

            [
                store(xor(v0, v8)),
                store(xor(v1, v9)),
                store(xor(v2, v10)),
                store(xor(v3, v11)),
                store(xor(v4, v12)),
                store(xor(v5, v13)),
                store(xor(v6, v14)),
                store(xor(v7, v15)),
            ]
        }
    };
}

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "std", not(any(target_feature = "avx2", target_feature = "avx512f")))
))]
mod x86_64_sse2 {
    use core::arch::x86_64::*;

    use super::IV;

    #[inline(always)]
    fn load(xs: &[u32; 4]) -> __m128i {
        unsafe { _mm_loadu_si128(xs.as_ptr().cast()) }
    }

    #[inline(always)]
    fn store(x: __m128i) -> [u32; 4] {
        let mut out = [0u32; 4];
        unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), x) };
        out
    }

    #[inline(always)]
    fn splat(x: u32) -> __m128i {
        unsafe { _mm_set1_epi32(x as i32) }
    }

    #[inline(always)]
    fn add(a: __m128i, b: __m128i) -> __m128i {
        unsafe { _mm_add_epi32(a, b) }
    }

    #[inline(always)]
    fn xor(a: __m128i, b: __m128i) -> __m128i {
        unsafe { _mm_xor_si128(a, b) }
    }

    #[inline(always)]
    fn rotr16(x: __m128i) -> __m128i {
        unsafe { _mm_or_si128(_mm_srli_epi32::<16>(x), _mm_slli_epi32::<16>(x)) }
    }

    #[inline(always)]
    fn rotr12(x: __m128i) -> __m128i {
        unsafe { _mm_or_si128(_mm_srli_epi32::<12>(x), _mm_slli_epi32::<20>(x)) }
    }

    #[inline(always)]
    fn rotr8(x: __m128i) -> __m128i {
        unsafe { _mm_or_si128(_mm_srli_epi32::<8>(x), _mm_slli_epi32::<24>(x)) }
    }

    #[inline(always)]
    fn rotr7(x: __m128i) -> __m128i {
        unsafe { _mm_or_si128(_mm_srli_epi32::<7>(x), _mm_slli_epi32::<25>(x)) }
    }

    define_x86_packed_compress!(compress_packed_4, 4);
}

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "std", all(target_feature = "avx2", not(target_feature = "avx512f")))
))]
mod x86_64_avx2 {
    use core::arch::x86_64::*;

    use super::IV;

    #[inline(always)]
    fn load(xs: &[u32; 8]) -> __m256i {
        unsafe { _mm256_loadu_si256(xs.as_ptr().cast()) }
    }

    #[inline(always)]
    fn store(x: __m256i) -> [u32; 8] {
        let mut out = [0u32; 8];
        unsafe { _mm256_storeu_si256(out.as_mut_ptr().cast(), x) };
        out
    }

    #[inline(always)]
    fn splat(x: u32) -> __m256i {
        unsafe { _mm256_set1_epi32(x as i32) }
    }

    #[inline(always)]
    fn add(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_add_epi32(a, b) }
    }

    #[inline(always)]
    fn xor(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_xor_si256(a, b) }
    }

    /// Rotate each 32-bit lane right by 16 bits via a single byte shuffle: this is cheaper than
    /// the shift-or sequence because the rotation amount is byte-aligned.
    #[inline(always)]
    fn rotr16(x: __m256i) -> __m256i {
        unsafe {
            let mask = _mm256_setr_epi8(
                2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10,
                11, 8, 9, 14, 15, 12, 13,
            );
            _mm256_shuffle_epi8(x, mask)
        }
    }

    #[inline(always)]
    fn rotr12(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<12>(x), _mm256_slli_epi32::<20>(x)) }
    }

    /// Rotate each 32-bit lane right by 8 bits via a single byte shuffle (see [`rotr16`]).
    #[inline(always)]
    fn rotr8(x: __m256i) -> __m256i {
        unsafe {
            let mask = _mm256_setr_epi8(
                1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9,
                10, 11, 8, 13, 14, 15, 12,
            );
            _mm256_shuffle_epi8(x, mask)
        }
    }

    #[inline(always)]
    fn rotr7(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<7>(x), _mm256_slli_epi32::<25>(x)) }
    }

    define_x86_packed_compress!(
        #[target_feature(enable = "avx2")]
        compress_packed_8,
        8
    );
}

#[cfg(all(target_arch = "x86_64", any(feature = "std", target_feature = "avx512f")))]
mod x86_64_avx512 {
    use core::arch::x86_64::*;

    use super::IV;

    #[inline(always)]
    fn load(xs: &[u32; 16]) -> __m512i {
        unsafe { _mm512_loadu_si512(xs.as_ptr().cast()) }
    }

    #[inline(always)]
    fn store(x: __m512i) -> [u32; 16] {
        let mut out = [0u32; 16];
        unsafe { _mm512_storeu_si512(out.as_mut_ptr().cast(), x) };
        out
    }

    #[inline(always)]
    fn splat(x: u32) -> __m512i {
        unsafe { _mm512_set1_epi32(x as i32) }
    }

    #[inline(always)]
    fn add(a: __m512i, b: __m512i) -> __m512i {
        unsafe { _mm512_add_epi32(a, b) }
    }

    #[inline(always)]
    fn xor(a: __m512i, b: __m512i) -> __m512i {
        unsafe { _mm512_xor_si512(a, b) }
    }

    #[inline(always)]
    fn rotr16(x: __m512i) -> __m512i {
        unsafe { _mm512_ror_epi32::<16>(x) }
    }

    #[inline(always)]
    fn rotr12(x: __m512i) -> __m512i {
        unsafe { _mm512_ror_epi32::<12>(x) }
    }

    #[inline(always)]
    fn rotr8(x: __m512i) -> __m512i {
        unsafe { _mm512_ror_epi32::<8>(x) }
    }

    #[inline(always)]
    fn rotr7(x: __m512i) -> __m512i {
        unsafe { _mm512_ror_epi32::<7>(x) }
    }

    define_x86_packed_compress!(
        #[target_feature(enable = "avx512f")]
        compress_packed_16,
        16
    );
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod neon {
    use core::arch::aarch64::*;

    use super::IV;

    #[inline(always)]
    fn load(xs: &[u32; 4]) -> uint32x4_t {
        unsafe { vld1q_u32(xs.as_ptr()) }
    }

    #[inline(always)]
    fn store(x: uint32x4_t) -> [u32; 4] {
        let mut out = [0u32; 4];
        unsafe { vst1q_u32(out.as_mut_ptr(), x) };
        out
    }

    #[inline(always)]
    fn splat(x: u32) -> uint32x4_t {
        unsafe { vdupq_n_u32(x) }
    }

    #[inline(always)]
    fn add(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        unsafe { vaddq_u32(a, b) }
    }

    #[inline(always)]
    fn xor(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        unsafe { veorq_u32(a, b) }
    }

    #[inline(always)]
    fn rotr16(x: uint32x4_t) -> uint32x4_t {
        unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x))) }
    }

    #[inline(always)]
    fn rotr12(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<12>(vshlq_n_u32::<20>(x), x) }
    }

    #[inline(always)]
    fn rotr8(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<8>(vshlq_n_u32::<24>(x), x) }
    }

    #[inline(always)]
    fn rotr7(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<7>(vshlq_n_u32::<25>(x), x) }
    }

    #[inline(always)]
    pub(super) fn compress_packed_4(cv: [[u32; 4]; 8], block: [[u32; 4]; 16]) -> [[u32; 4]; 8] {
        let mut v0 = load(&cv[0]);
        let mut v1 = load(&cv[1]);
        let mut v2 = load(&cv[2]);
        let mut v3 = load(&cv[3]);
        let mut v4 = load(&cv[4]);
        let mut v5 = load(&cv[5]);
        let mut v6 = load(&cv[6]);
        let mut v7 = load(&cv[7]);
        let mut v8 = splat(IV[0]);
        let mut v9 = splat(IV[1]);
        let mut v10 = splat(IV[2]);
        let mut v11 = splat(IV[3]);
        let mut v12 = splat(IV[4]);
        let mut v13 = splat(IV[5]);
        let mut v14 = splat(IV[6]);
        let mut v15 = splat(IV[7]);
        macro_rules! round {
            (
                $m0:literal,
                $m1:literal,
                $m2:literal,
                $m3:literal,
                $m4:literal,
                $m5:literal,
                $m6:literal,
                $m7:literal,
                $m8:literal,
                $m9:literal,
                $m10:literal,
                $m11:literal,
                $m12:literal,
                $m13:literal,
                $m14:literal,
                $m15:literal
            ) => {{
                let m0 = load(&block[$m0]);
                let m1 = load(&block[$m1]);
                let m2 = load(&block[$m2]);
                let m3 = load(&block[$m3]);
                let m4 = load(&block[$m4]);
                let m5 = load(&block[$m5]);
                let m6 = load(&block[$m6]);
                let m7 = load(&block[$m7]);
                let m8 = load(&block[$m8]);
                let m9 = load(&block[$m9]);
                let m10 = load(&block[$m10]);
                let m11 = load(&block[$m11]);
                let m12 = load(&block[$m12]);
                let m13 = load(&block[$m13]);
                let m14 = load(&block[$m14]);
                let m15 = load(&block[$m15]);

                // Keep the independent G functions in lockstep, matching BLAKE3's
                // NEON hash4 schedule.
                v0 = add(add(v0, v4), m0);
                v1 = add(add(v1, v5), m2);
                v2 = add(add(v2, v6), m4);
                v3 = add(add(v3, v7), m6);
                v12 = rotr16(xor(v12, v0));
                v13 = rotr16(xor(v13, v1));
                v14 = rotr16(xor(v14, v2));
                v15 = rotr16(xor(v15, v3));
                v8 = add(v8, v12);
                v9 = add(v9, v13);
                v10 = add(v10, v14);
                v11 = add(v11, v15);
                v4 = rotr12(xor(v4, v8));
                v5 = rotr12(xor(v5, v9));
                v6 = rotr12(xor(v6, v10));
                v7 = rotr12(xor(v7, v11));
                v0 = add(add(v0, v4), m1);
                v1 = add(add(v1, v5), m3);
                v2 = add(add(v2, v6), m5);
                v3 = add(add(v3, v7), m7);
                v12 = rotr8(xor(v12, v0));
                v13 = rotr8(xor(v13, v1));
                v14 = rotr8(xor(v14, v2));
                v15 = rotr8(xor(v15, v3));
                v8 = add(v8, v12);
                v9 = add(v9, v13);
                v10 = add(v10, v14);
                v11 = add(v11, v15);
                v4 = rotr7(xor(v4, v8));
                v5 = rotr7(xor(v5, v9));
                v6 = rotr7(xor(v6, v10));
                v7 = rotr7(xor(v7, v11));

                v0 = add(add(v0, v5), m8);
                v1 = add(add(v1, v6), m10);
                v2 = add(add(v2, v7), m12);
                v3 = add(add(v3, v4), m14);
                v15 = rotr16(xor(v15, v0));
                v12 = rotr16(xor(v12, v1));
                v13 = rotr16(xor(v13, v2));
                v14 = rotr16(xor(v14, v3));
                v10 = add(v10, v15);
                v11 = add(v11, v12);
                v8 = add(v8, v13);
                v9 = add(v9, v14);
                v5 = rotr12(xor(v5, v10));
                v6 = rotr12(xor(v6, v11));
                v7 = rotr12(xor(v7, v8));
                v4 = rotr12(xor(v4, v9));
                v0 = add(add(v0, v5), m9);
                v1 = add(add(v1, v6), m11);
                v2 = add(add(v2, v7), m13);
                v3 = add(add(v3, v4), m15);
                v15 = rotr8(xor(v15, v0));
                v12 = rotr8(xor(v12, v1));
                v13 = rotr8(xor(v13, v2));
                v14 = rotr8(xor(v14, v3));
                v10 = add(v10, v15);
                v11 = add(v11, v12);
                v8 = add(v8, v13);
                v9 = add(v9, v14);
                v5 = rotr7(xor(v5, v10));
                v6 = rotr7(xor(v6, v11));
                v7 = rotr7(xor(v7, v8));
                v4 = rotr7(xor(v4, v9));
            }};
        }

        round!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        round!(2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8);
        round!(3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1);
        round!(10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6);
        round!(12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4);
        round!(9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7);
        round!(11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13);

        [
            store(xor(v0, v8)),
            store(xor(v1, v9)),
            store(xor(v2, v10)),
            store(xor(v3, v11)),
            store(xor(v4, v12)),
            store(xor(v5, v13)),
            store(xor(v6, v14)),
            store(xor(v7, v15)),
        ]
    }
}
