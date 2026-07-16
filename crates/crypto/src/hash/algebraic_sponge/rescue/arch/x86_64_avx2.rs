use core::arch::x86_64::*;

// The following AVX2 implementation has been copied from plonky2:
// https://github.com/0xPolygonZero/plonky2/blob/main/plonky2/src/hash/arch/x86_64/poseidon_goldilocks_avx2_bmi2.rs

// Preliminary notes:
// 1. AVX does not support addition with carry but 128-bit (2-word) addition can be easily emulated.
//    The method recognizes that for a + b overflowed iff (a + b) < a:
//    1. res_lo = a_lo + b_lo
//    2. carry_mask = res_lo < a_lo
//    3. res_hi = a_hi + b_hi - carry_mask
//
//    Notice that carry_mask is subtracted, not added. This is because AVX comparison instructions
//    return -1 (all bits 1) for true and 0 for false.
//
// 2. AVX does not have unsigned 64-bit comparisons. Those can be emulated with signed comparisons
//    by recognizing that a <u b iff a + (1 << 63) <s b + (1 << 63), where the addition wraps around
//    and the comparisons are unsigned and signed respectively. The shift function adds/subtracts 1
//    << 63 to enable this trick. Addition with carry example:
//    1. a_lo_s = shift(a_lo)
//    2. res_lo_s = a_lo_s + b_lo
//    3. carry_mask = res_lo_s <s a_lo_s
//    4. res_lo = shift(res_lo_s)
//    5. res_hi = a_hi + b_hi - carry_mask
//
//    The suffix _s denotes a value that has been shifted by 1 << 63. The result of addition
//    is shifted if exactly one of the operands is shifted, as is the case on
//    line 2. Line 3. performs a signed comparison res_lo_s <s a_lo_s on shifted values to
//    emulate unsigned comparison res_lo <u a_lo on unshifted values. Finally, line 4. reverses the
//    shift so the result can be returned.
//
//    When performing a chain of calculations, we can often save instructions by letting
//    the shift propagate through and only undoing it when necessary.
//    For example, to compute the addition of three two-word (128-bit) numbers we can do:
//    1. a_lo_s = shift(a_lo)
//    2. tmp_lo_s = a_lo_s + b_lo
//    3. tmp_carry_mask = tmp_lo_s <s a_lo_s
//    4. tmp_hi = a_hi + b_hi - tmp_carry_mask
//    5. res_lo_s = tmp_lo_s + c_lo vi. res_carry_mask = res_lo_s <s tmp_lo_s
//    6. res_carry_mask = res_lo_s <s tmp_lo_s
//    7. res_lo = shift(res_lo_s)
//    8. res_hi = tmp_hi + c_hi - res_carry_mask
//
//    Notice that the above 3-value addition still only requires two calls to shift, just like our
//    2-value addition.

#[inline(always)]
pub fn branch_hint() {
    // NOTE: These are the currently supported assembly architectures. See the
    // [nightly reference](https://doc.rust-lang.org/nightly/reference/inline-assembly.html) for
    // the most up-to-date list.
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "x86",
        target_arch = "x86_64",
    ))]
    unsafe {
        core::arch::asm!("", options(nomem, nostack, preserves_flags));
    }
}

macro_rules! map3 {
    ($f:ident:: < $l:literal > , $v:ident) => {
        ($f::<$l>($v.0), $f::<$l>($v.1), $f::<$l>($v.2))
    };
    ($f:ident:: < $l:literal > , $v1:ident, $v2:ident) => {
        ($f::<$l>($v1.0, $v2.0), $f::<$l>($v1.1, $v2.1), $f::<$l>($v1.2, $v2.2))
    };
    ($f:ident, $v:ident) => {
        ($f($v.0), $f($v.1), $f($v.2))
    };
    ($f:ident, $v0:ident, $v1:ident) => {
        ($f($v0.0, $v1.0), $f($v0.1, $v1.1), $f($v0.2, $v1.2))
    };
    ($f:ident,rep $v0:ident, $v1:ident) => {
        ($f($v0, $v1.0), $f($v0, $v1.1), $f($v0, $v1.2))
    };

    ($f:ident, $v0:ident,rep $v1:ident) => {
        ($f($v0.0, $v1), $f($v0.1, $v1), $f($v0.2, $v1))
    };
}

#[inline(always)]
unsafe fn square3(
    x: (__m256i, __m256i, __m256i),
) -> ((__m256i, __m256i, __m256i), (__m256i, __m256i, __m256i)) {
    unsafe {
        let x_hi = {
            // Move high bits to low position. The high bits of x_hi are ignored. Swizzle is faster
            // than bitshift. This instruction only has a floating-point flavor, so we
            // cast to/from float. This is safe and free.
            let x_ps = map3!(_mm256_castsi256_ps, x);
            let x_hi_ps = map3!(_mm256_movehdup_ps, x_ps);
            map3!(_mm256_castps_si256, x_hi_ps)
        };

        // All pairwise multiplications.
        let mul_ll = map3!(_mm256_mul_epu32, x, x);
        let mul_lh = map3!(_mm256_mul_epu32, x, x_hi);
        let mul_hh = map3!(_mm256_mul_epu32, x_hi, x_hi);

        // Bignum addition, but mul_lh is shifted by 33 bits (not 32).
        let mul_ll_hi = map3!(_mm256_srli_epi64::<33>, mul_ll);
        let t0 = map3!(_mm256_add_epi64, mul_lh, mul_ll_hi);
        let t0_hi = map3!(_mm256_srli_epi64::<31>, t0);
        let res_hi = map3!(_mm256_add_epi64, mul_hh, t0_hi);

        // Form low result by adding the mul_ll and the low 31 bits of mul_lh (shifted to the high
        // position).
        let mul_lh_lo = map3!(_mm256_slli_epi64::<33>, mul_lh);
        let res_lo = map3!(_mm256_add_epi64, mul_ll, mul_lh_lo);

        (res_lo, res_hi)
    }
}

#[inline(always)]
unsafe fn mul3(
    x: (__m256i, __m256i, __m256i),
    y: (__m256i, __m256i, __m256i),
) -> ((__m256i, __m256i, __m256i), (__m256i, __m256i, __m256i)) {
    unsafe {
        let epsilon = _mm256_set1_epi64x(0xffffffff);
        let x_hi = {
            // Move high bits to low position. The high bits of x_hi are ignored. Swizzle is faster
            // than bitshift. This instruction only has a floating-point flavor, so we
            // cast to/from float. This is safe and free.
            let x_ps = map3!(_mm256_castsi256_ps, x);
            let x_hi_ps = map3!(_mm256_movehdup_ps, x_ps);
            map3!(_mm256_castps_si256, x_hi_ps)
        };
        let y_hi = {
            let y_ps = map3!(_mm256_castsi256_ps, y);
            let y_hi_ps = map3!(_mm256_movehdup_ps, y_ps);
            map3!(_mm256_castps_si256, y_hi_ps)
        };

        // All four pairwise multiplications
        let mul_ll = map3!(_mm256_mul_epu32, x, y);
        let mul_lh = map3!(_mm256_mul_epu32, x, y_hi);
        let mul_hl = map3!(_mm256_mul_epu32, x_hi, y);
        let mul_hh = map3!(_mm256_mul_epu32, x_hi, y_hi);

        // Bignum addition
        // Extract high 32 bits of mul_ll and add to mul_hl. This cannot overflow.
        let mul_ll_hi = map3!(_mm256_srli_epi64::<32>, mul_ll);
        let t0 = map3!(_mm256_add_epi64, mul_hl, mul_ll_hi);
        // Extract low 32 bits of t0 and add to mul_lh. Again, this cannot overflow.
        // Also, extract high 32 bits of t0 and add to mul_hh.
        let t0_lo = map3!(_mm256_and_si256, t0, rep epsilon);
        let t0_hi = map3!(_mm256_srli_epi64::<32>, t0);
        let t1 = map3!(_mm256_add_epi64, mul_lh, t0_lo);
        let t2 = map3!(_mm256_add_epi64, mul_hh, t0_hi);
        // Lastly, extract the high 32 bits of t1 and add to t2.
        let t1_hi = map3!(_mm256_srli_epi64::<32>, t1);
        let res_hi = map3!(_mm256_add_epi64, t2, t1_hi);

        // Form res_lo by combining the low half of mul_ll with the low half of t1 (shifted into
        // high position).
        let t1_lo = {
            let t1_ps = map3!(_mm256_castsi256_ps, t1);
            let t1_lo_ps = map3!(_mm256_moveldup_ps, t1_ps);
            map3!(_mm256_castps_si256, t1_lo_ps)
        };
        let res_lo = map3!(_mm256_blend_epi32::<0xaa>, mul_ll, t1_lo);

        (res_lo, res_hi)
    }
}

/// Addition, where the second operand is `0 <= y < 0xffffffff00000001`.
#[inline(always)]
unsafe fn add_small(
    x_s: (__m256i, __m256i, __m256i),
    y: (__m256i, __m256i, __m256i),
) -> (__m256i, __m256i, __m256i) {
    unsafe {
        let res_wrapped_s = map3!(_mm256_add_epi64, x_s, y);
        let mask = map3!(_mm256_cmpgt_epi32, x_s, res_wrapped_s);
        let wrapback_amt = map3!(_mm256_srli_epi64::<32>, mask); // EPSILON if overflowed else 0.
        map3!(_mm256_add_epi64, res_wrapped_s, wrapback_amt)
    }
}

#[inline(always)]
unsafe fn maybe_adj_sub(res_wrapped_s: __m256i, mask: __m256i) -> __m256i {
    // The subtraction is very unlikely to overflow so we're best off branching.
    // The even u32s in `mask` are meaningless, so we want to ignore them. `_mm256_testz_pd`
    // branches depending on the sign bit of double-precision (64-bit) floats. Bit cast `mask` to
    // floating-point (this is free).
    unsafe {
        let mask_pd = _mm256_castsi256_pd(mask);
        // `_mm256_testz_pd(mask_pd, mask_pd) == 1` iff all sign bits are 0, meaning that underflow
        // did not occur for any of the vector elements.
        if _mm256_testz_pd(mask_pd, mask_pd) == 1 {
            res_wrapped_s
        } else {
            branch_hint();
            // Highly unlikely: underflow did occur. Find adjustment per element and apply it.
            let adj_amount = _mm256_srli_epi64::<32>(mask); // EPSILON if underflow.
            _mm256_sub_epi64(res_wrapped_s, adj_amount)
        }
    }
}

/// Addition, where the second operand is much smaller than `0xffffffff00000001`.
#[inline(always)]
unsafe fn sub_tiny(
    x_s: (__m256i, __m256i, __m256i),
    y: (__m256i, __m256i, __m256i),
) -> (__m256i, __m256i, __m256i) {
    unsafe {
        let res_wrapped_s = map3!(_mm256_sub_epi64, x_s, y);
        let mask = map3!(_mm256_cmpgt_epi32, res_wrapped_s, x_s);
        map3!(maybe_adj_sub, res_wrapped_s, mask)
    }
}

#[inline(always)]
unsafe fn reduce3(
    (lo0, hi0): ((__m256i, __m256i, __m256i), (__m256i, __m256i, __m256i)),
) -> (__m256i, __m256i, __m256i) {
    unsafe {
        let sign_bit = _mm256_set1_epi64x(i64::MIN);
        let epsilon = _mm256_set1_epi64x(0xffffffff);
        let lo0_s = map3!(_mm256_xor_si256, lo0, rep sign_bit);
        let hi_hi0 = map3!(_mm256_srli_epi64::<32>, hi0);
        let lo1_s = sub_tiny(lo0_s, hi_hi0);
        let t1 = map3!(_mm256_mul_epu32, hi0, rep epsilon);
        let lo2_s = add_small(lo1_s, t1);
        map3!(_mm256_xor_si256, lo2_s, rep sign_bit)
    }
}

#[inline(always)]
unsafe fn mul_reduce(
    a: (__m256i, __m256i, __m256i),
    b: (__m256i, __m256i, __m256i),
) -> (__m256i, __m256i, __m256i) {
    unsafe { reduce3(mul3(a, b)) }
}

#[inline(always)]
unsafe fn square_reduce(state: (__m256i, __m256i, __m256i)) -> (__m256i, __m256i, __m256i) {
    unsafe { reduce3(square3(state)) }
}

#[inline(always)]
unsafe fn exp_acc(
    high: (__m256i, __m256i, __m256i),
    low: (__m256i, __m256i, __m256i),
    exp: usize,
) -> (__m256i, __m256i, __m256i) {
    let mut result = high;
    unsafe {
        for _ in 0..exp {
            result = square_reduce(result);
        }
        mul_reduce(result, low)
    }
}

#[inline(always)]
unsafe fn do_apply_sbox(state: (__m256i, __m256i, __m256i)) -> (__m256i, __m256i, __m256i) {
    unsafe {
        let state2 = square_reduce(state);
        let state4_unreduced = square3(state2);
        let state3_unreduced = mul3(state2, state);
        let state4 = reduce3(state4_unreduced);
        let state3 = reduce3(state3_unreduced);
        let state7_unreduced = mul3(state3, state4);
        reduce3(state7_unreduced)
    }
}

#[inline(always)]
unsafe fn do_apply_inv_sbox(state: (__m256i, __m256i, __m256i)) -> (__m256i, __m256i, __m256i) {
    unsafe {
        // compute base^10540996611094048183 using 72 multiplications per array element
        // 10540996611094048183 = b1001001001001001001001001001000110110110110110110110110110110111

        // compute base^10
        let t1 = square_reduce(state);

        // compute base^100
        let t2 = square_reduce(t1);

        // compute base^100100
        let t3 = exp_acc(t2, t2, 3);

        // compute base^100100100100
        let t4 = exp_acc(t3, t3, 6);

        // compute base^100100100100100100100100
        let t5 = exp_acc(t4, t4, 12);

        // compute base^100100100100100100100100100100
        let t6 = exp_acc(t5, t3, 6);

        // compute base^1001001001001001001001001001000100100100100100100100100100100
        let t7 = exp_acc(t6, t6, 31);

        // compute base^1001001001001001001001001001000110110110110110110110110110110111
        let a = square_reduce(square_reduce(mul_reduce(square_reduce(t7), t6)));
        let b = mul_reduce(t1, mul_reduce(t2, state));
        mul_reduce(a, b)
    }
}

#[inline(always)]
unsafe fn avx2_load(state: &[u64; 12]) -> (__m256i, __m256i, __m256i) {
    unsafe {
        (
            _mm256_loadu_si256((state[0..4]).as_ptr().cast::<__m256i>()),
            _mm256_loadu_si256((state[4..8]).as_ptr().cast::<__m256i>()),
            _mm256_loadu_si256((state[8..12]).as_ptr().cast::<__m256i>()),
        )
    }
}

#[inline(always)]
unsafe fn avx2_store(buf: &mut [u64; 12], state: (__m256i, __m256i, __m256i)) {
    unsafe {
        _mm256_storeu_si256((buf[0..4]).as_mut_ptr().cast::<__m256i>(), state.0);
        _mm256_storeu_si256((buf[4..8]).as_mut_ptr().cast::<__m256i>(), state.1);
        _mm256_storeu_si256((buf[8..12]).as_mut_ptr().cast::<__m256i>(), state.2);
    }
}

#[inline(always)]
pub unsafe fn apply_sbox(buffer: &mut [u64; 12]) {
    unsafe {
        let mut state = avx2_load(buffer);
        state = do_apply_sbox(state);
        avx2_store(buffer, state);
    }
}

#[inline(always)]
pub unsafe fn apply_inv_sbox(buffer: &mut [u64; 12]) {
    unsafe {
        let mut state = avx2_load(buffer);
        state = do_apply_inv_sbox(state);
        avx2_store(buffer, state);
    }
}

// RPX E-round
// ================================================================================================

const P_U64: u64 = 0xffff_ffff_0000_0001;

#[inline(always)]
unsafe fn load_ext(buf: &[u64; 12]) -> (__m256i, __m256i, __m256i) {
    unsafe {
        // a0 = [s0,s3,s6,s9], a1 = [s1,s4,s7,s10], a2 = [s2,s5,s8,s11]
        let a0 = _mm256_setr_epi64x(buf[0] as i64, buf[3] as i64, buf[6] as i64, buf[9] as i64);
        let a1 = _mm256_setr_epi64x(buf[1] as i64, buf[4] as i64, buf[7] as i64, buf[10] as i64);
        let a2 = _mm256_setr_epi64x(buf[2] as i64, buf[5] as i64, buf[8] as i64, buf[11] as i64);
        (a0, a1, a2)
    }
}

#[inline(always)]
unsafe fn store_ext(buf: &mut [u64; 12], a0: __m256i, a1: __m256i, a2: __m256i) {
    unsafe {
        let mut t0 = [0i64; 4];
        let mut t1 = [0i64; 4];
        let mut t2 = [0i64; 4];
        _mm256_storeu_si256(t0.as_mut_ptr().cast(), a0);
        _mm256_storeu_si256(t1.as_mut_ptr().cast(), a1);
        _mm256_storeu_si256(t2.as_mut_ptr().cast(), a2);

        buf[0] = t0[0] as u64;
        buf[3] = t0[1] as u64;
        buf[6] = t0[2] as u64;
        buf[9] = t0[3] as u64;
        buf[1] = t1[0] as u64;
        buf[4] = t1[1] as u64;
        buf[7] = t1[2] as u64;
        buf[10] = t1[3] as u64;
        buf[2] = t2[0] as u64;
        buf[5] = t2[1] as u64;
        buf[8] = t2[2] as u64;
        buf[11] = t2[3] as u64;
    }
}

#[inline(always)]
unsafe fn add_mod(x: __m256i, y: __m256i) -> __m256i {
    unsafe {
        let p = _mm256_set1_epi64x(P_U64 as i64);
        let sign = _mm256_set1_epi64x(i64::MIN);

        // Inputs are already canonical from reduce3, so no need to call canon()
        let sum = _mm256_add_epi64(x, y);

        let x_s = _mm256_xor_si256(x, sign);
        let sum_s = _mm256_xor_si256(sum, sign);
        let carry_mask = _mm256_cmpgt_epi64(x_s, sum_s);

        let p_s = _mm256_xor_si256(p, sign);
        let p_gt_sum = _mm256_cmpgt_epi64(p_s, sum_s);
        let ge_p_mask = _mm256_xor_si256(p_gt_sum, _mm256_set1_epi64x(-1));

        let need = _mm256_or_si256(carry_mask, ge_p_mask);
        let adj = _mm256_and_si256(need, p);

        _mm256_sub_epi64(sum, adj)
    }
}

#[inline(always)]
unsafe fn dbl_mod(x: __m256i) -> __m256i {
    unsafe { add_mod(x, x) }
}

#[inline(always)]
unsafe fn canonicalize(x: (__m256i, __m256i, __m256i)) -> (__m256i, __m256i, __m256i) {
    unsafe {
        let sign_bit = _mm256_set1_epi64x(i64::MIN);
        let p = _mm256_set1_epi64x(P_U64 as i64);
        let all_ones = _mm256_set1_epi64x(-1);

        let x_s = map3!(_mm256_xor_si256, x, rep sign_bit);
        let p_s = _mm256_xor_si256(p, sign_bit);
        let p_gt = map3!(_mm256_cmpgt_epi64, rep p_s, x_s);
        let ge_mask = map3!(_mm256_xor_si256, p_gt, rep all_ones);
        let adj = map3!(_mm256_and_si256, ge_mask, rep p);
        map3!(_mm256_sub_epi64, x, adj)
    }
}

#[inline(always)]
unsafe fn mul_reduce_vec(a: __m256i, b: __m256i) -> __m256i {
    unsafe { canonicalize(mul_reduce((a, a, a), (b, b, b))).0 }
}

#[inline(always)]
unsafe fn square_reduce_vec(state: __m256i) -> __m256i {
    unsafe { canonicalize(square_reduce((state, state, state))).0 }
}

#[inline(always)]
unsafe fn ext_square(a0: __m256i, a1: __m256i, a2: __m256i) -> (__m256i, __m256i, __m256i) {
    unsafe {
        let a0_sq = square_reduce_vec(a0);
        let a1_sq = square_reduce_vec(a1);
        let a2_sq = square_reduce_vec(a2);

        let a0a1 = mul_reduce_vec(a0, a1);
        let a0a2 = mul_reduce_vec(a0, a2);
        let a1a2 = mul_reduce_vec(a1, a2);

        let s0 = a0_sq;
        let s1 = dbl_mod(a0a1);
        let s2 = add_mod(dbl_mod(a0a2), a1_sq);
        let s3 = dbl_mod(a1a2);
        let s4 = a2_sq;

        let out0 = add_mod(s0, s3);
        let out1 = add_mod(add_mod(s1, s3), s4);
        let out2 = add_mod(s2, s4);
        (out0, out1, out2)
    }
}

#[inline(always)]
unsafe fn ext_mul(
    a0: __m256i,
    a1: __m256i,
    a2: __m256i,
    b0: __m256i,
    b1: __m256i,
    b2: __m256i,
) -> (__m256i, __m256i, __m256i) {
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
unsafe fn ext_exp7(a0: __m256i, a1: __m256i, a2: __m256i) -> (__m256i, __m256i, __m256i) {
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
