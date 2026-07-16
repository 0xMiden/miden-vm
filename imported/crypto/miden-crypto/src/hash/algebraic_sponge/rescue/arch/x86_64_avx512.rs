use core::arch::x86_64::*;

/// 12×u64 state split as:
/// - 8 lanes in AVX-512 register (__m512i) for vector operations
/// - 4 lanes as scalar u64 array
type State = (__m512i, [u64; 4]);

// CONSTANTS
// ================================================================================================

const EPS_U64: u64 = 0xffff_ffff;

#[allow(clippy::useless_transmute)]
const LO_32_BITS_MASK: __mmask16 = unsafe { core::mem::transmute(0b0101_0101_0101_0101u16) };

// S-Box
// ================================================================================================

#[inline(always)]
unsafe fn mul64_64(x: __m512i, y: __m512i) -> (__m512i, __m512i) {
    unsafe {
        let eps = _mm512_set1_epi64(EPS_U64 as i64);

        let x_hi = _mm512_castps_si512(_mm512_movehdup_ps(_mm512_castsi512_ps(x)));
        let y_hi = _mm512_castps_si512(_mm512_movehdup_ps(_mm512_castsi512_ps(y)));

        let mul_ll = _mm512_mul_epu32(x, y);
        let mul_hh = _mm512_mul_epu32(x_hi, y_hi);
        let mul_lh = _mm512_mul_epu32(x, y_hi);
        let mul_hl = _mm512_mul_epu32(x_hi, y);

        let mul_ll_hi = _mm512_srli_epi64::<32>(mul_ll);
        let t0 = _mm512_add_epi64(mul_hl, mul_ll_hi);

        let t0_lo = _mm512_and_si512(t0, eps);
        let t0_hi = _mm512_srli_epi64::<32>(t0);

        let t1 = _mm512_add_epi64(mul_lh, t0_lo);
        let t2 = _mm512_add_epi64(mul_hh, t0_hi);

        let t1_hi = _mm512_srli_epi64::<32>(t1);
        let res_hi = _mm512_add_epi64(t2, t1_hi);

        let t1_lo = _mm512_castps_si512(_mm512_moveldup_ps(_mm512_castsi512_ps(t1)));
        let res_lo = _mm512_mask_blend_epi32(LO_32_BITS_MASK, t1_lo, mul_ll);

        (res_lo, res_hi)
    }
}

#[inline(always)]
unsafe fn square64(x: __m512i) -> (__m512i, __m512i) {
    unsafe {
        let x_hi = _mm512_castps_si512(_mm512_movehdup_ps(_mm512_castsi512_ps(x)));

        let mul_ll = _mm512_mul_epu32(x, x);
        let mul_hh = _mm512_mul_epu32(x_hi, x_hi);
        let mul_lh = _mm512_mul_epu32(x, x_hi);

        let mul_ll_hi = _mm512_srli_epi64::<33>(mul_ll);
        let t0 = _mm512_add_epi64(mul_lh, mul_ll_hi);
        let t0_hi = _mm512_srli_epi64::<31>(t0);
        let res_hi = _mm512_add_epi64(mul_hh, t0_hi);

        let mul_lh_lo = _mm512_slli_epi64::<33>(mul_lh);
        let res_lo = _mm512_add_epi64(mul_ll, mul_lh_lo);

        (res_lo, res_hi)
    }
}

#[inline(always)]
unsafe fn reduce128(x: (__m512i, __m512i)) -> __m512i {
    unsafe {
        let (lo, hi) = x;
        let sign = _mm512_set1_epi64(i64::MIN);
        let eps = _mm512_set1_epi64(EPS_U64 as i64);

        let lo_s = _mm512_xor_si512(lo, sign);
        let hi_hi = _mm512_srli_epi64::<32>(hi);

        // NOTE: On some Zen4+ CPUs, mask-based conditional operations
        // (like the masked subtract below) can be slightly slower than the
        // scalar fixup approach used in the AVX2 path. This all-vector
        // implementation keeps the code branch-free and still yields the
        // expected speedup on Zen5, but future maintainers may want to revisit
        // this if they notice performance regressions on other architectures.
        let lo1_s = {
            let diff = _mm512_sub_epi64(lo_s, hi_hi);
            let mask: __mmask8 = _mm512_cmpgt_epi64_mask(diff, lo_s);
            if mask == 0 {
                diff
            } else {
                let adj = _mm512_maskz_set1_epi64(mask, EPS_U64 as i64);
                _mm512_sub_epi64(diff, adj)
            }
        };

        let t1 = _mm512_mul_epu32(hi, eps);
        let sum = _mm512_add_epi64(lo1_s, t1);
        let carry: __mmask8 = _mm512_cmplt_epi64_mask(sum, lo1_s);
        let adj = _mm512_maskz_set1_epi64(carry, EPS_U64 as i64);
        let lo2_s = _mm512_add_epi64(sum, adj);

        _mm512_xor_si512(lo2_s, sign)
    }
}

#[inline(always)]
fn reduce128_u64(lo: u64, hi: u64) -> u64 {
    let (mut lo1, borrow) = lo.overflowing_sub(hi >> 32);
    if borrow {
        lo1 = lo1.wrapping_sub(EPS_U64)
    }
    let t1 = (hi & EPS_U64).wrapping_mul(EPS_U64);
    let (mut out, carry) = lo1.overflowing_add(t1);
    if carry {
        out = out.wrapping_add(EPS_U64)
    }
    out
}

#[inline(always)]
fn mul_reduce_u64(a: u64, b: u64) -> u64 {
    let p = (a as u128) * (b as u128);
    reduce128_u64(p as u64, (p >> 64) as u64)
}

#[inline(always)]
fn square_reduce_u64(a: u64) -> u64 {
    let p = (a as u128) * (a as u128);
    reduce128_u64(p as u64, (p >> 64) as u64)
}

#[inline(always)]
unsafe fn mul_reduce(a: State, b: State) -> State {
    unsafe {
        let head = reduce128(mul64_64(a.0, b.0));
        let t0 = mul_reduce_u64(a.1[0], b.1[0]);
        let t1 = mul_reduce_u64(a.1[1], b.1[1]);
        let t2 = mul_reduce_u64(a.1[2], b.1[2]);
        let t3 = mul_reduce_u64(a.1[3], b.1[3]);
        (head, [t0, t1, t2, t3])
    }
}

#[inline(always)]
unsafe fn square_reduce(x: State) -> State {
    unsafe {
        let head = reduce128(square64(x.0));
        let t0 = square_reduce_u64(x.1[0]);
        let t1 = square_reduce_u64(x.1[1]);
        let t2 = square_reduce_u64(x.1[2]);
        let t3 = square_reduce_u64(x.1[3]);
        (head, [t0, t1, t2, t3])
    }
}

#[inline(always)]
unsafe fn exp_acc(mut high: State, low: State, exp: usize) -> State {
    unsafe {
        for _ in 0..exp {
            high = square_reduce(high);
        }
        mul_reduce(high, low)
    }
}

#[inline(always)]
unsafe fn do_apply_sbox(state: State) -> State {
    unsafe {
        let s2 = square_reduce(state);
        let s4 = square_reduce(s2);
        let s3 = mul_reduce(s2, state);
        mul_reduce(s3, s4)
    }
}

#[inline(always)]
unsafe fn do_apply_inv_sbox(state: State) -> State {
    unsafe {
        let t1 = square_reduce(state);
        let t2 = square_reduce(t1);
        let t3 = exp_acc(t2, t2, 3);
        let t4 = exp_acc(t3, t3, 6);
        let t5 = exp_acc(t4, t4, 12);
        let t6 = exp_acc(t5, t3, 6);
        let t7 = exp_acc(t6, t6, 31);
        let a = square_reduce(square_reduce(mul_reduce(square_reduce(t7), t6)));
        let b = mul_reduce(t1, mul_reduce(t2, state));
        mul_reduce(a, b)
    }
}

#[inline(always)]
unsafe fn load12(src: &[u64; 12]) -> State {
    unsafe {
        let head = _mm512_loadu_si512(src.as_ptr().cast::<__m512i>());
        let tail = [src[8], src[9], src[10], src[11]];
        (head, tail)
    }
}

#[inline(always)]
unsafe fn store12(dst: &mut [u64; 12], s: State) {
    unsafe {
        _mm512_storeu_si512(dst.as_mut_ptr().cast::<__m512i>(), s.0);
        dst[8..12].copy_from_slice(&s.1);
    }
}

#[inline(always)]
pub unsafe fn apply_sbox(buf: &mut [u64; 12]) {
    unsafe {
        let s = load12(buf);
        let s = do_apply_sbox(s);
        store12(buf, s);
    }
}

#[inline(always)]
pub unsafe fn apply_inv_sbox(buf: &mut [u64; 12]) {
    unsafe {
        let s = load12(buf);
        let s = do_apply_inv_sbox(s);
        store12(buf, s);
    }
}

// RPX E-round
// ================================================================================================

const P_U64: u64 = 0xffff_ffff_0000_0001;

#[inline(always)]
unsafe fn load_ext(buf: &[u64; 12]) -> (__m512i, __m512i, __m512i) {
    unsafe {
        let a0 = _mm512_setr_epi64(
            buf[0] as i64,
            buf[3] as i64,
            buf[6] as i64,
            buf[9] as i64,
            0,
            0,
            0,
            0,
        );
        let a1 = _mm512_setr_epi64(
            buf[1] as i64,
            buf[4] as i64,
            buf[7] as i64,
            buf[10] as i64,
            0,
            0,
            0,
            0,
        );
        let a2 = _mm512_setr_epi64(
            buf[2] as i64,
            buf[5] as i64,
            buf[8] as i64,
            buf[11] as i64,
            0,
            0,
            0,
            0,
        );
        (a0, a1, a2)
    }
}

#[inline(always)]
unsafe fn store_ext(buf: &mut [u64; 12], a0: __m512i, a1: __m512i, a2: __m512i) {
    unsafe {
        let v0: [i64; 8] = core::mem::transmute(a0);
        let v1: [i64; 8] = core::mem::transmute(a1);
        let v2: [i64; 8] = core::mem::transmute(a2);
        buf[0] = v0[0] as u64;
        buf[3] = v0[1] as u64;
        buf[6] = v0[2] as u64;
        buf[9] = v0[3] as u64;
        buf[1] = v1[0] as u64;
        buf[4] = v1[1] as u64;
        buf[7] = v1[2] as u64;
        buf[10] = v1[3] as u64;
        buf[2] = v2[0] as u64;
        buf[5] = v2[1] as u64;
        buf[8] = v2[2] as u64;
        buf[11] = v2[3] as u64;
    }
}

#[inline(always)]
unsafe fn add_mod(z: __m512i, w: __m512i) -> __m512i {
    unsafe {
        let p = _mm512_set1_epi64(P_U64 as i64);

        // Inputs are already canonical from reduce128, so no need to call canon()
        let s = _mm512_add_epi64(z, w);

        // If carry or s >= p, subtract p once
        let carry = _mm512_cmp_epu64_mask(s, z, _MM_CMPINT_LT);
        let ge_p = _mm512_cmpge_epu64_mask(s, p);
        let need = carry | ge_p;

        _mm512_mask_sub_epi64(s, need, s, p)
    }
}

#[inline(always)]
unsafe fn dbl_mod(z: __m512i) -> __m512i {
    unsafe { add_mod(z, z) }
}

#[inline(always)]
unsafe fn canonicalize_vec(x: __m512i) -> __m512i {
    unsafe {
        let p = _mm512_set1_epi64(P_U64 as i64);
        let ge = _mm512_cmpge_epu64_mask(x, p);
        _mm512_mask_sub_epi64(x, ge, x, p)
    }
}

#[inline(always)]
unsafe fn mul_reduce_vec(x: __m512i, y: __m512i) -> __m512i {
    unsafe { canonicalize_vec(reduce128(mul64_64(x, y))) }
}

#[inline(always)]
unsafe fn square_reduce_vec(x: __m512i) -> __m512i {
    unsafe { canonicalize_vec(reduce128(square64(x))) }
}

#[inline(always)]
unsafe fn ext_square(a0: __m512i, a1: __m512i, a2: __m512i) -> (__m512i, __m512i, __m512i) {
    unsafe {
        let s0 = square_reduce_vec(a0);
        let s1 = dbl_mod(mul_reduce_vec(a0, a1));
        let s2 = add_mod(dbl_mod(mul_reduce_vec(a0, a2)), square_reduce_vec(a1));
        let s3 = dbl_mod(mul_reduce_vec(a1, a2));
        let s4 = square_reduce_vec(a2);

        let out0 = add_mod(s0, s3);
        let out1 = add_mod(add_mod(s1, s3), s4);
        let out2 = add_mod(s2, s4);
        (out0, out1, out2)
    }
}

#[inline(always)]
unsafe fn ext_mul(
    a0: __m512i,
    a1: __m512i,
    a2: __m512i,
    b0: __m512i,
    b1: __m512i,
    b2: __m512i,
) -> (__m512i, __m512i, __m512i) {
    unsafe {
        let a0b0 = mul_reduce_vec(a0, b0);
        let a1b1 = mul_reduce_vec(a1, b1);
        let a2b2 = mul_reduce_vec(a2, b2);

        let a0b1 = mul_reduce_vec(a0, b1);
        let a1b0 = mul_reduce_vec(a1, b0);
        let a0b2 = mul_reduce_vec(a0, b2);
        let a2b0 = mul_reduce_vec(a2, b0);
        let a1b2 = mul_reduce_vec(a1, b2);
        let a2b1 = mul_reduce_vec(a2, b1);

        let r0 = a0b0;
        let r1 = add_mod(a0b1, a1b0);
        let r2 = add_mod(add_mod(a0b2, a1b1), a2b0);
        let r3 = add_mod(a1b2, a2b1);
        let r4 = a2b2;

        let out0 = add_mod(r0, r3);
        let out1 = add_mod(add_mod(r1, r3), r4);
        let out2 = add_mod(r2, r4);
        (out0, out1, out2)
    }
}

#[inline(always)]
unsafe fn ext_exp7(a0: __m512i, a1: __m512i, a2: __m512i) -> (__m512i, __m512i, __m512i) {
    unsafe {
        let (x2_0, x2_1, x2_2) = ext_square(a0, a1, a2);
        let (x4_0, x4_1, x4_2) = ext_square(x2_0, x2_1, x2_2);
        let (x3_0, x3_1, x3_2) = ext_mul(x2_0, x2_1, x2_2, a0, a1, a2);
        ext_mul(x3_0, x3_1, x3_2, x4_0, x4_1, x4_2)
    }
}

#[inline(always)]
pub unsafe fn apply_ext_round(buf: &mut [u64; 12]) {
    unsafe {
        let (mut a0, mut a1, mut a2) = load_ext(buf);
        (a0, a1, a2) = ext_exp7(a0, a1, a2);
        store_ext(buf, a0, a1, a2);
    }
}
