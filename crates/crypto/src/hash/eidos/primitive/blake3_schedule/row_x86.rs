//! Row-wise (diagonalized) single-block BLAKE3 compression for x86_64.
//!
//! Ported from the `blake3` crate's `rust_sse2::compress_pre` (the pure-Rust SSE2 backend,
//! MIT/Apache-2.0/CC0), adapted to Eidos's fixed parameter-word tail
//! (`v[12..16] = IV[4..8]`, no counter/block_len/flags) and to a `[u32; 16]` message block
//! instead of raw bytes. Keeping one G-function row per 128-bit vector and diagonalizing via
//! shuffles (instead of one scalar 32-bit lane per `g` call) does the same seven rounds in
//! roughly a quarter of the vector instructions of the portable loop in `super`.
//!
//! SSE2 is part of the x86_64 architectural baseline, so the plain `compress_raw`/
//! `compress_raw_xof` below run unconditionally on x86_64 with no runtime feature check.
//!
//! `compress_pre` keeps up to 13 `__m128i` values alive at once (`row0..row3`, `m0..m3`,
//! `t0..t3`, `tt`), which exceeds the 16-register legacy SSE/AVX file once ABI and spill
//! bookkeeping are accounted for, forcing real stack spills on a default (non
//! `target-cpu=native`) build — measured at ~30-37% slower than with a wider register file
//! available. AVX-512VL's EVEX encoding reaches XMM16-31 even for plain 128-bit operations, so
//! the `_avx512vl` variants below are the exact same logic (generated from one macro body, so
//! there is no copy-paste divergence risk) recompiled with that attribute purely for the wider
//! register file — no wider vectors, no different instructions selected by us. `avx512f` is
//! AVX-512VL's prerequisite.

use core::arch::x86_64::*;

use super::IV;

#[inline(always)]
unsafe fn loadu(src: *const u32) -> __m128i {
    unsafe { _mm_loadu_si128(src.cast()) }
}

#[inline(always)]
unsafe fn storeu(src: __m128i, dest: *mut u32) {
    unsafe { _mm_storeu_si128(dest.cast(), src) }
}

#[inline(always)]
unsafe fn add(a: __m128i, b: __m128i) -> __m128i {
    unsafe { _mm_add_epi32(a, b) }
}

#[inline(always)]
unsafe fn xor(a: __m128i, b: __m128i) -> __m128i {
    unsafe { _mm_xor_si128(a, b) }
}

#[inline(always)]
unsafe fn set4(a: u32, b: u32, c: u32, d: u32) -> __m128i {
    unsafe { _mm_setr_epi32(a as i32, b as i32, c as i32, d as i32) }
}

#[inline(always)]
unsafe fn rot16(a: __m128i) -> __m128i {
    unsafe { _mm_or_si128(_mm_srli_epi32(a, 16), _mm_slli_epi32(a, 32 - 16)) }
}

#[inline(always)]
unsafe fn rot12(a: __m128i) -> __m128i {
    unsafe { _mm_or_si128(_mm_srli_epi32(a, 12), _mm_slli_epi32(a, 32 - 12)) }
}

#[inline(always)]
unsafe fn rot8(a: __m128i) -> __m128i {
    unsafe { _mm_or_si128(_mm_srli_epi32(a, 8), _mm_slli_epi32(a, 32 - 8)) }
}

#[inline(always)]
unsafe fn rot7(a: __m128i) -> __m128i {
    unsafe { _mm_or_si128(_mm_srli_epi32(a, 7), _mm_slli_epi32(a, 32 - 7)) }
}

#[inline(always)]
unsafe fn g1(
    row0: &mut __m128i,
    row1: &mut __m128i,
    row2: &mut __m128i,
    row3: &mut __m128i,
    m: __m128i,
) {
    unsafe {
        *row0 = add(add(*row0, m), *row1);
        *row3 = xor(*row3, *row0);
        *row3 = rot16(*row3);
        *row2 = add(*row2, *row3);
        *row1 = xor(*row1, *row2);
        *row1 = rot12(*row1);
    }
}

#[inline(always)]
unsafe fn g2(
    row0: &mut __m128i,
    row1: &mut __m128i,
    row2: &mut __m128i,
    row3: &mut __m128i,
    m: __m128i,
) {
    unsafe {
        *row0 = add(add(*row0, m), *row1);
        *row3 = xor(*row3, *row0);
        *row3 = rot8(*row3);
        *row2 = add(*row2, *row3);
        *row1 = xor(*row1, *row2);
        *row1 = rot7(*row1);
    }
}

macro_rules! mm_shuffle {
    ($z:expr, $y:expr, $x:expr, $w:expr) => {
        ($z << 6) | ($y << 4) | ($x << 2) | $w
    };
}

macro_rules! shuffle2 {
    ($a:expr, $b:expr, $c:expr) => {
        _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps($a), _mm_castsi128_ps($b), $c))
    };
}

// Note the optimization here of leaving row1 as the unrotated row, rather than row0. All the
// message loads below are adjusted to compensate. See
// https://github.com/sneves/blake2-avx2/pull/4.
#[inline(always)]
unsafe fn diagonalize(row0: &mut __m128i, row2: &mut __m128i, row3: &mut __m128i) {
    unsafe {
        *row0 = _mm_shuffle_epi32(*row0, mm_shuffle!(2, 1, 0, 3));
        *row3 = _mm_shuffle_epi32(*row3, mm_shuffle!(1, 0, 3, 2));
        *row2 = _mm_shuffle_epi32(*row2, mm_shuffle!(0, 3, 2, 1));
    }
}

#[inline(always)]
unsafe fn undiagonalize(row0: &mut __m128i, row2: &mut __m128i, row3: &mut __m128i) {
    unsafe {
        *row0 = _mm_shuffle_epi32(*row0, mm_shuffle!(0, 3, 2, 1));
        *row3 = _mm_shuffle_epi32(*row3, mm_shuffle!(1, 0, 3, 2));
        *row2 = _mm_shuffle_epi32(*row2, mm_shuffle!(2, 1, 0, 3));
    }
}

#[inline(always)]
unsafe fn blend_epi16(a: __m128i, b: __m128i, imm8: i32) -> __m128i {
    unsafe {
        let bits = _mm_set_epi16(0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01);
        let mut mask = _mm_set1_epi16(imm8 as i16);
        mask = _mm_and_si128(mask, bits);
        mask = _mm_cmpeq_epi16(mask, bits);
        _mm_or_si128(_mm_and_si128(mask, b), _mm_andnot_si128(mask, a))
    }
}

/// Row-wise diagonalized permutation, adapted from `blake3::rust_sse2::compress_pre`.
///
/// Returns `[row0, row1, row2, row3] = [v[0..4], v[4..8], v[8..12], v[12..16]]` of the standard
/// BLAKE3 permuted state after all seven rounds, with Eidos's fixed parameter-word tail
/// (`v[12..16] = IV[4..8]`, matching `super::permuted_state_with_parameter_words`).
///
/// Generated twice (see module docs): a plain variant with no feature requirement beyond SSE2,
/// and an `avx512f,avx512vl`-attributed variant that is bit-for-bit the same logic, recompiled
/// for the wider register file. Both bodies come from this one macro, so they cannot diverge.
macro_rules! define_compress_pre {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        #[inline]
        unsafe fn $name(cv: &[u32; 8], block: &[u32; 16]) -> [__m128i; 4] {
            unsafe {
                let row0 = &mut loadu(cv.as_ptr());
                let row1 = &mut loadu(cv.as_ptr().add(4));
                let row2 = &mut set4(IV[0], IV[1], IV[2], IV[3]);
                let row3 = &mut set4(IV[4], IV[5], IV[6], IV[7]);

                let mut m0 = loadu(block.as_ptr());
                let mut m1 = loadu(block.as_ptr().add(4));
                let mut m2 = loadu(block.as_ptr().add(8));
                let mut m3 = loadu(block.as_ptr().add(12));

                let mut t0;
                let mut t1;
                let mut t2;
                let mut t3;
                let mut tt;

                // Round 1 permutes the message words from the original input order into the
                // groups that get mixed in parallel.
                t0 = shuffle2!(m0, m1, mm_shuffle!(2, 0, 2, 0));
                g1(row0, row1, row2, row3, t0);
                t1 = shuffle2!(m0, m1, mm_shuffle!(3, 1, 3, 1));
                g2(row0, row1, row2, row3, t1);
                diagonalize(row0, row2, row3);
                t2 = shuffle2!(m2, m3, mm_shuffle!(2, 0, 2, 0));
                t2 = _mm_shuffle_epi32(t2, mm_shuffle!(2, 1, 0, 3));
                g1(row0, row1, row2, row3, t2);
                t3 = shuffle2!(m2, m3, mm_shuffle!(3, 1, 3, 1));
                t3 = _mm_shuffle_epi32(t3, mm_shuffle!(2, 1, 0, 3));
                g2(row0, row1, row2, row3, t3);
                undiagonalize(row0, row2, row3);
                m0 = t0;
                m1 = t1;
                m2 = t2;
                m3 = t3;

                // Rounds 2-7 apply a fixed permutation to the message words produced by the
                // round before, so the same shuffle sequence repeats.
                for _ in 0..6 {
                    t0 = shuffle2!(m0, m1, mm_shuffle!(3, 1, 1, 2));
                    t0 = _mm_shuffle_epi32(t0, mm_shuffle!(0, 3, 2, 1));
                    g1(row0, row1, row2, row3, t0);
                    t1 = shuffle2!(m2, m3, mm_shuffle!(3, 3, 2, 2));
                    tt = _mm_shuffle_epi32(m0, mm_shuffle!(0, 0, 3, 3));
                    t1 = blend_epi16(tt, t1, 0xcc);
                    g2(row0, row1, row2, row3, t1);
                    diagonalize(row0, row2, row3);
                    t2 = _mm_unpacklo_epi64(m3, m1);
                    tt = blend_epi16(t2, m2, 0xc0);
                    t2 = _mm_shuffle_epi32(tt, mm_shuffle!(1, 3, 2, 0));
                    g1(row0, row1, row2, row3, t2);
                    t3 = _mm_unpackhi_epi32(m1, m3);
                    tt = _mm_unpacklo_epi32(m2, t3);
                    t3 = _mm_shuffle_epi32(tt, mm_shuffle!(0, 1, 3, 2));
                    g2(row0, row1, row2, row3, t3);
                    undiagonalize(row0, row2, row3);
                    m0 = t0;
                    m1 = t1;
                    m2 = t2;
                    m3 = t3;
                }

                [*row0, *row1, *row2, *row3]
            }
        }
    };
}

define_compress_pre!(
    #[cfg(any(feature = "std", not(target_feature = "avx512vl")))]
    compress_pre
);
define_compress_pre!(
    #[cfg(any(feature = "std", target_feature = "avx512vl"))]
    #[target_feature(enable = "avx512f,avx512vl")]
    compress_pre_avx512vl
);

/// Returns the raw eight-word CV fold with Eidos compression's fixed parameter words:
/// `out[i] = v[i] ^ v[i + 8]`.
///
/// Generated twice (see module docs): a plain SSE2 variant needing no runtime feature check, and
/// an `avx512f,avx512vl`-attributed variant for a wider register file.
macro_rules! define_compress_raw {
    ($(#[$attr:meta])* $name:ident, $compress_pre:ident) => {
        $(#[$attr])*
        #[inline]
        pub(super) unsafe fn $name(cv: &[u32; 8], block: &[u32; 16]) -> [u32; 8] {
            unsafe {
                let [row0, row1, row2, row3] = $compress_pre(cv, block);
                let mut out = [0u32; 8];
                storeu(xor(row0, row2), out.as_mut_ptr());
                storeu(xor(row1, row3), out.as_mut_ptr().add(4));
                out
            }
        }
    };
}

define_compress_raw!(
    #[cfg(any(feature = "std", not(target_feature = "avx512vl")))]
    compress_raw_impl,
    compress_pre
);
define_compress_raw!(
    #[cfg(any(feature = "std", target_feature = "avx512vl"))]
    #[target_feature(enable = "avx512f,avx512vl")]
    compress_raw_avx512vl,
    compress_pre_avx512vl
);

/// Returns the raw sixteen-word XOF fold with Eidos compression's fixed parameter words:
/// `out[i] = v[i] ^ v[i + 8]` for `i < 8`, `out[i] = v[i] ^ cv[i - 8]` for `i >= 8`.
///
/// Generated twice (see module docs): a plain SSE2 variant needing no runtime feature check, and
/// an `avx512f,avx512vl`-attributed variant for a wider register file.
macro_rules! define_compress_raw_xof {
    ($(#[$attr:meta])* $name:ident, $compress_pre:ident) => {
        $(#[$attr])*
        #[inline]
        pub(super) unsafe fn $name(cv: &[u32; 8], block: &[u32; 16]) -> [u32; 16] {
            unsafe {
                let [row0, row1, row2, row3] = $compress_pre(cv, block);
                let cv_row0 = loadu(cv.as_ptr());
                let cv_row1 = loadu(cv.as_ptr().add(4));
                let mut out = [0u32; 16];
                storeu(xor(row0, row2), out.as_mut_ptr());
                storeu(xor(row1, row3), out.as_mut_ptr().add(4));
                storeu(xor(row2, cv_row0), out.as_mut_ptr().add(8));
                storeu(xor(row3, cv_row1), out.as_mut_ptr().add(12));
                out
            }
        }
    };
}

define_compress_raw_xof!(
    #[cfg(any(feature = "std", not(target_feature = "avx512vl")))]
    compress_raw_xof_impl,
    compress_pre
);
define_compress_raw_xof!(
    #[cfg(any(feature = "std", target_feature = "avx512vl"))]
    #[target_feature(enable = "avx512f,avx512vl")]
    compress_raw_xof_avx512vl,
    compress_pre_avx512vl
);

/// Returns the raw eight-word CV fold with Eidos compression's fixed parameter words. Needs no
/// runtime feature check: SSE2 is part of the x86_64 architectural baseline.
#[cfg(any(feature = "std", not(target_feature = "avx512vl")))]
#[inline]
pub(super) fn compress_raw(cv: &[u32; 8], block: &[u32; 16]) -> [u32; 8] {
    // SAFETY: SSE2 is part of the x86_64 architectural baseline.
    unsafe { compress_raw_impl(cv, block) }
}

/// Returns the raw sixteen-word XOF fold with Eidos compression's fixed parameter words. Needs no
/// runtime feature check: SSE2 is part of the x86_64 architectural baseline.
#[cfg(any(feature = "std", not(target_feature = "avx512vl")))]
#[inline]
pub(super) fn compress_raw_xof(cv: &[u32; 8], block: &[u32; 16]) -> [u32; 16] {
    // SAFETY: SSE2 is part of the x86_64 architectural baseline.
    unsafe { compress_raw_xof_impl(cv, block) }
}
