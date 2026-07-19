// Poseidon2 Goldilocks WIDTH=12 packed permutation — SVE2 intrinsics kernel.
//
// Written in C, like the RPO SVE kernels beside it, so the compiler schedules
// the SVE vector work, the scalar GPR work (S-box chains), and the external
// linear-layer additions in one global window; Rust inline-asm blocks are
// opaque to the scheduler and measurably slower here.
//
// SVE types are sizeless, so there are no arrays of svuint64_t; the state
// lives in named variables driven by X-macros, mirroring the RPO kernels.
//
// Layout contract with the Rust caller: `state` is 24 u64 values — 12 field
// elements x 2 lanes (two independent permutation states), element i at
// state[2i] and state[2i+1]. All predication is fixed to two 64-bit lanes
// (svptrue_pat_b64(SV_VL2)), so the kernel is correct at any SVE vector
// length and never touches memory beyond the 24 declared values.
//
// Field arithmetic matches the aarch64_neon path of p3-goldilocks: values are
// carried as arbitrary u64 residues of P = 2^64 - 2^32 + 1, every op returns
// a residue below 2^64, and EPS = 2^32 - 1 ≡ 2^64 (mod P) is the wraparound
// correction.

#include <arm_sve.h>
#include <stddef.h>
#include <stdint.h>

#define GL_EPS 0xFFFFFFFFull
#define GL_HALF_P_PLUS_1 0x7FFFFFFF80000001ull

#define FOR12(M) M(0) M(1) M(2) M(3) M(4) M(5) M(6) M(7) M(8) M(9) M(10) M(11)
#define FOR8(M) M(0) M(1) M(2) M(3) M(4) M(5) M(6) M(7)

// ---------------------------------------------------------------------------
// Vector field ops (two 64-bit lanes; pg is the VL2 predicate)
// ---------------------------------------------------------------------------

// Full mul: SVE2 64-bit low/high products; shift-epsilon reduction with the
// widening-MAC trick (svmlalb: even 32-bit sub-lanes = hi_lo) — 9 vector ops.
static inline svuint64_t gl_mul(svbool_t pg, svuint64_t a, svuint64_t b) {
    svuint64_t lo = svmul_u64_x(pg, a, b);
    svuint64_t hi = svmulh_u64_x(pg, a, b);
    svuint64_t hi_hi = svlsr_n_u64_x(pg, hi, 32);
    svbool_t borrow = svcmplt_u64(pg, lo, hi_hi);
    svuint64_t t1 = svsub_u64_x(pg, lo, hi_hi);
    t1 = svsub_n_u64_m(borrow, t1, GL_EPS);
    svuint64_t res = svmlalb_u64(t1, svreinterpret_u32_u64(hi), svdup_n_u32((uint32_t)GL_EPS));
    svbool_t ovf = svcmplt_u64(pg, res, t1);
    return svadd_n_u64_m(ovf, res, GL_EPS);
}

static inline svuint64_t gl_add(svbool_t pg, svuint64_t a, svuint64_t b) {
    svuint64_t res = svadd_u64_x(pg, a, b);
    svbool_t ovf = svcmplt_u64(pg, res, a);
    return svadd_n_u64_m(ovf, res, GL_EPS);
}

static inline svuint64_t gl_sub(svbool_t pg, svuint64_t a, svuint64_t b) {
    svbool_t borrow = svcmplt_u64(pg, a, b);
    svuint64_t res = svsub_u64_x(pg, a, b);
    return svsub_n_u64_m(borrow, res, GL_EPS);
}

static inline svuint64_t gl_double(svbool_t pg, svuint64_t a) {
    return gl_add(pg, a, a);
}

static inline svuint64_t gl_div2(svbool_t pg, svuint64_t x) {
    svuint64_t half = svlsr_n_u64_x(pg, x, 1);
    svbool_t odd = svcmpne_n_u64(pg, svand_n_u64_x(pg, x, 1), 0);
    return svadd_n_u64_m(odd, half, GL_HALF_P_PLUS_1);
}

static inline svuint64_t gl_div4(svbool_t pg, svuint64_t x) {
    return gl_div2(pg, gl_div2(pg, x));
}

static inline svuint64_t gl_div8(svbool_t pg, svuint64_t x) {
    return gl_div2(pg, gl_div4(pg, x));
}

// ---------------------------------------------------------------------------
// Scalar field ops (plonky2-style, for the internal-round s0 chains)
// ---------------------------------------------------------------------------

static inline uint64_t gl_mul_scalar(uint64_t x, uint64_t y) {
    unsigned __int128 xy = (unsigned __int128)x * (unsigned __int128)y;
    uint64_t lo = (uint64_t)xy;
    uint64_t hi = (uint64_t)(xy >> 64);
    uint64_t t1;
    if (__builtin_expect(__builtin_sub_overflow(lo, hi >> 32, &t1), 0)) {
        t1 -= GL_EPS;
    }
    uint64_t hle = (uint64_t)(uint32_t)hi * (uint32_t)GL_EPS; // umull
    uint64_t res;
    if (__builtin_add_overflow(t1, hle, &res)) {
        res += GL_EPS;
    }
    return res;
}

static inline uint64_t gl_add_scalar(uint64_t a, uint64_t b) {
    uint64_t res;
    if (__builtin_add_overflow(a, b, &res)) {
        res += GL_EPS;
    }
    return res;
}

static inline uint64_t gl_sub_scalar(uint64_t a, uint64_t b) {
    uint64_t res;
    if (__builtin_sub_overflow(a, b, &res)) {
        res -= GL_EPS;
    }
    return res;
}

static inline uint64_t sbox7_scalar(uint64_t x) {
    uint64_t x2 = gl_mul_scalar(x, x);
    uint64_t x3 = gl_mul_scalar(x2, x);
    uint64_t x4 = gl_mul_scalar(x2, x2);
    return gl_mul_scalar(x3, x4);
}

// Lane extraction. LASTA over an empty predicate yields element 0; LASTB over
// the VL2 predicate yields element 1.
static inline uint64_t gl_lane0(svuint64_t v) {
    return svlasta_u64(svpfalse_b(), v);
}

static inline uint64_t gl_lane1(svbool_t pg, svuint64_t v) {
    return svlastb_u64(pg, v);
}

// ---------------------------------------------------------------------------
// Poseidon2 layers (named-variable style; pointers because SVE is sizeless)
// ---------------------------------------------------------------------------

// 4x4 circulant [2,3,1,1] block of the external linear layer (same addition
// structure as Plonky3's apply_mat4).
static inline void gl_mat4(
    svbool_t pg,
    svuint64_t *x0,
    svuint64_t *x1,
    svuint64_t *x2,
    svuint64_t *x3
) {
    svuint64_t t01 = gl_add(pg, *x0, *x1);
    svuint64_t t23 = gl_add(pg, *x2, *x3);
    svuint64_t t0123 = gl_add(pg, t01, t23);
    svuint64_t t01123 = gl_add(pg, t0123, *x1);
    svuint64_t t01233 = gl_add(pg, t0123, *x3);
    svuint64_t y3 = gl_add(pg, t01233, gl_double(pg, *x0));
    svuint64_t y1 = gl_add(pg, t01123, gl_double(pg, *x2));
    *x0 = gl_add(pg, t01123, t01);
    *x2 = gl_add(pg, t01233, t23);
    *x1 = y1;
    *x3 = y3;
}

// External linear layer M_E ("MDS-light" in the Poseidon2 paper; Plonky3's
// mds_light_permutation): mat4 blocks, then column sums added back.
#define GL_MDS_LIGHT(pg) \
    do { \
        gl_mat4(pg, &s0, &s1, &s2, &s3); \
        gl_mat4(pg, &s4, &s5, &s6, &s7); \
        gl_mat4(pg, &s8, &s9, &s10, &s11); \
        svuint64_t sum0 = gl_add(pg, gl_add(pg, s0, s4), s8); \
        svuint64_t sum1 = gl_add(pg, gl_add(pg, s1, s5), s9); \
        svuint64_t sum2 = gl_add(pg, gl_add(pg, s2, s6), s10); \
        svuint64_t sum3 = gl_add(pg, gl_add(pg, s3, s7), s11); \
        s0 = gl_add(pg, s0, sum0); \
        s4 = gl_add(pg, s4, sum0); \
        s8 = gl_add(pg, s8, sum0); \
        s1 = gl_add(pg, s1, sum1); \
        s5 = gl_add(pg, s5, sum1); \
        s9 = gl_add(pg, s9, sum1); \
        s2 = gl_add(pg, s2, sum2); \
        s6 = gl_add(pg, s6, sum2); \
        s10 = gl_add(pg, s10, sum2); \
        s3 = gl_add(pg, s3, sum3); \
        s7 = gl_add(pg, s7, sum3); \
        s11 = gl_add(pg, s11, sum3); \
    } while (0)

// add-rc + x^7 for all 12 elements, stage-major. Expanded as macros over the
// named state so the compiler schedules across everything.
#define GL_RC_ADD1(i) \
    { \
        s##i = svadd_n_u64_x(pg, s##i, (rc)[i]); \
        svbool_t o_##i = svcmplt_n_u64(pg, s##i, (rc)[i]); \
        s##i = svadd_n_u64_m(o_##i, s##i, GL_EPS); \
    }
#define GL_SBOX_S1(i) svuint64_t x2_##i = gl_mul(pg, s##i, s##i);
#define GL_SBOX_S2(i) \
    svuint64_t x3_##i = gl_mul(pg, x2_##i, s##i); \
    svuint64_t x4_##i = gl_mul(pg, x2_##i, x2_##i);
#define GL_SBOX_S3(i) s##i = gl_mul(pg, x3_##i, x4_##i);

// Round-constant add + x^7 S-box, dual-domain: elements 0..7 through the SVE2
// stages, elements 8..11 as scalar GPR chains. Splitting the work across both
// register files lets the out-of-order core run them concurrently; the
// interleaving below is only a hint, the compiler reschedules freely.
#define GL_RC_SBOX(pg, rc) \
    do { \
        uint64_t t8a = gl_add_scalar(gl_lane0(s8), (rc)[8]); \
        uint64_t t8b = gl_add_scalar(gl_lane1(pg, s8), (rc)[8]); \
        uint64_t t9a = gl_add_scalar(gl_lane0(s9), (rc)[9]); \
        uint64_t t9b = gl_add_scalar(gl_lane1(pg, s9), (rc)[9]); \
        uint64_t t10a = gl_add_scalar(gl_lane0(s10), (rc)[10]); \
        uint64_t t10b = gl_add_scalar(gl_lane1(pg, s10), (rc)[10]); \
        uint64_t t11a = gl_add_scalar(gl_lane0(s11), (rc)[11]); \
        uint64_t t11b = gl_add_scalar(gl_lane1(pg, s11), (rc)[11]); \
        FOR8(GL_RC_ADD1) \
        FOR8(GL_SBOX_S1) \
        t8a = sbox7_scalar(t8a); \
        t8b = sbox7_scalar(t8b); \
        FOR8(GL_SBOX_S2) \
        t9a = sbox7_scalar(t9a); \
        t9b = sbox7_scalar(t9b); \
        t10a = sbox7_scalar(t10a); \
        t10b = sbox7_scalar(t10b); \
        FOR8(GL_SBOX_S3) \
        t11a = sbox7_scalar(t11a); \
        t11b = sbox7_scalar(t11b); \
        s8 = svdupq_n_u64(t8a, t8b); \
        s9 = svdupq_n_u64(t9a, t9b); \
        s10 = svdupq_n_u64(t10a, t10b); \
        s11 = svdupq_n_u64(t11a, t11b); \
    } while (0)

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

void poseidon2_w12_packed_sve2(
    uint64_t *state,           // 24 u64: element i lanes at [2i, 2i+1]
    const uint64_t *init_rc,   // n_init x 12, canonical
    size_t n_init,
    const uint64_t *int_rc,    // n_int, canonical
    size_t n_int,
    const uint64_t *term_rc,   // n_term x 12, canonical
    size_t n_term
) {
    svbool_t pg = svptrue_pat_b64(SV_VL2);

#define GL_LOAD(i) svuint64_t s##i = svld1_u64(pg, state + 2 * (i));
    FOR12(GL_LOAD)
#undef GL_LOAD

    GL_MDS_LIGHT(pg);
    for (size_t r = 0; r < n_init; r++) {
        const uint64_t *rc = init_rc + 12 * r;
        GL_RC_SBOX(pg, rc);
        GL_MDS_LIGHT(pg);
    }

    // Internal rounds: s0 lives as two scalars (one per lane) across all
    // rounds; the state sums and the diagonal run in SVE.
    uint64_t s0_a = gl_lane0(s0);
    uint64_t s0_b = gl_lane1(pg, s0);
    for (size_t r = 0; r < n_int; r++) {
        uint64_t rc = int_rc[r];
        s0_a = gl_add_scalar(s0_a, rc);
        s0_b = gl_add_scalar(s0_b, rc);
        uint64_t s07_a = sbox7_scalar(s0_a);
        uint64_t s07_b = sbox7_scalar(s0_b);

        svuint64_t sum1 = gl_add(pg, s1, s2);
        svuint64_t sum2 = gl_add(pg, s3, s4);
        svuint64_t sum3 = gl_add(pg, s5, s6);
        svuint64_t sum4 = gl_add(pg, s7, s8);
        svuint64_t sum5 = gl_add(pg, s9, s10);
        svuint64_t sum12 = gl_add(pg, sum1, sum2);
        svuint64_t sum34 = gl_add(pg, sum3, sum4);
        svuint64_t sum511 = gl_add(pg, sum5, s11);
        svuint64_t sum_hi = gl_add(pg, gl_add(pg, sum12, sum34), sum511);

        svuint64_t d1 = s1;
        svuint64_t d2 = gl_double(pg, s2);
        svuint64_t d3 = gl_div2(pg, s3);
        svuint64_t d4 = gl_add(pg, gl_double(pg, s4), s4);
        svuint64_t d5 = gl_double(pg, gl_double(pg, s5));
        svuint64_t d6 = gl_div2(pg, s6);
        svuint64_t d7 = gl_add(pg, gl_double(pg, s7), s7);
        svuint64_t d8 = gl_double(pg, gl_double(pg, s8));
        svuint64_t d9 = gl_div4(pg, s9);
        svuint64_t d10 = gl_div4(pg, s10);
        svuint64_t d11 = gl_div8(pg, s11);

        uint64_t sumhi_a = gl_lane0(sum_hi);
        uint64_t sumhi_b = gl_lane1(pg, sum_hi);
        uint64_t sum_a = gl_add_scalar(sumhi_a, s07_a);
        uint64_t sum_b = gl_add_scalar(sumhi_b, s07_b);
        s0_a = gl_sub_scalar(sumhi_a, s07_a);
        s0_b = gl_sub_scalar(sumhi_b, s07_b);
        svuint64_t sum = svdupq_n_u64(sum_a, sum_b);

        s1 = gl_add(pg, d1, sum);
        s2 = gl_add(pg, d2, sum);
        s3 = gl_add(pg, d3, sum);
        s4 = gl_add(pg, d4, sum);
        s5 = gl_add(pg, d5, sum);
        s6 = gl_sub(pg, sum, d6);
        s7 = gl_sub(pg, sum, d7);
        s8 = gl_sub(pg, sum, d8);
        s9 = gl_add(pg, d9, sum);
        s10 = gl_sub(pg, sum, d10);
        s11 = gl_add(pg, d11, sum);
    }
    s0 = svdupq_n_u64(s0_a, s0_b);

    for (size_t r = 0; r < n_term; r++) {
        const uint64_t *rc = term_rc + 12 * r;
        GL_RC_SBOX(pg, rc);
        GL_MDS_LIGHT(pg);
    }

#define GL_STORE(i) svst1_u64(pg, state + 2 * (i), s##i);
    FOR12(GL_STORE)
#undef GL_STORE
}
