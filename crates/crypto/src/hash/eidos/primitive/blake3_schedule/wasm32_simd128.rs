//! Four-lane BLAKE3 compression for wasm32 `simd128`.

use core::arch::wasm32::*;

use super::{IV, MSG_SCHEDULE};

#[inline(always)]
fn load(xs: &[u32; 4]) -> v128 {
    // SAFETY: `xs` points to four initialized `u32` values; `v128_load` permits unaligned input.
    unsafe { v128_load(xs.as_ptr().cast()) }
}

#[inline(always)]
fn store(x: v128) -> [u32; 4] {
    let mut out = [0u32; 4];
    // SAFETY: `out` has space for four `u32` values and is valid for the unaligned store.
    unsafe { v128_store(out.as_mut_ptr().cast(), x) };
    out
}

#[inline(always)]
fn splat(x: u32) -> v128 {
    i32x4_splat(x as i32)
}

#[inline(always)]
fn rotr16(x: v128) -> v128 {
    v128_or(u32x4_shr(x, 16), i32x4_shl(x, 16))
}

#[inline(always)]
fn rotr12(x: v128) -> v128 {
    v128_or(u32x4_shr(x, 12), i32x4_shl(x, 20))
}

#[inline(always)]
fn rotr8(x: v128) -> v128 {
    v128_or(u32x4_shr(x, 8), i32x4_shl(x, 24))
}

#[inline(always)]
fn rotr7(x: v128) -> v128 {
    v128_or(u32x4_shr(x, 7), i32x4_shl(x, 25))
}

#[inline(always)]
fn g(v: &mut [v128; 16], a: usize, b: usize, c: usize, d: usize, x: v128, y: v128) {
    v[a] = i32x4_add(i32x4_add(v[a], v[b]), x);
    v[d] = rotr16(v128_xor(v[d], v[a]));
    v[c] = i32x4_add(v[c], v[d]);
    v[b] = rotr12(v128_xor(v[b], v[c]));
    v[a] = i32x4_add(i32x4_add(v[a], v[b]), y);
    v[d] = rotr8(v128_xor(v[d], v[a]));
    v[c] = i32x4_add(v[c], v[d]);
    v[b] = rotr7(v128_xor(v[b], v[c]));
}

#[inline]
pub(super) fn compress_packed_4(cv: [[u32; 4]; 8], block: [[u32; 4]; 16]) -> [[u32; 4]; 8] {
    let mut v = [splat(0); 16];
    for i in 0..8 {
        v[i] = load(&cv[i]);
        v[8 + i] = splat(IV[i]);
    }

    for s in MSG_SCHEDULE {
        g(&mut v, 0, 4, 8, 12, load(&block[s[0]]), load(&block[s[1]]));
        g(&mut v, 1, 5, 9, 13, load(&block[s[2]]), load(&block[s[3]]));
        g(&mut v, 2, 6, 10, 14, load(&block[s[4]]), load(&block[s[5]]));
        g(&mut v, 3, 7, 11, 15, load(&block[s[6]]), load(&block[s[7]]));
        g(&mut v, 0, 5, 10, 15, load(&block[s[8]]), load(&block[s[9]]));
        g(&mut v, 1, 6, 11, 12, load(&block[s[10]]), load(&block[s[11]]));
        g(&mut v, 2, 7, 8, 13, load(&block[s[12]]), load(&block[s[13]]));
        g(&mut v, 3, 4, 9, 14, load(&block[s[14]]), load(&block[s[15]]));
    }

    core::array::from_fn(|i| store(v128_xor(v[i], v[i + 8])))
}
