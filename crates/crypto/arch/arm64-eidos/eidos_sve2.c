#include "eidos_arm.h"
#include <arm_sve.h>

// The caller guarantees active_lanes <= 16. Every memory access uses the active predicate.
#define LOAD(word) svld1_u32(pg, block + (word) * 16 + base)
#define ADD(a, b) svadd_u32_x(pg, (a), (b))
#define XOR(a, b) sveor_u32_x(pg, (a), (b))
// XAR is unpredicated, but inactive lanes never reach a memory access.
#define XOR_ROTATE(a, b, n) svxar_n_u32((a), (b), (n))

// Advance the four independent G chains together; message vectors die at each add.
#define G4(a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3, \
           m0, m1, m2, m3, m4, m5, m6, m7) do { \
    a0 = ADD(ADD(a0, b0), LOAD(m0)); \
    a1 = ADD(ADD(a1, b1), LOAD(m2)); \
    a2 = ADD(ADD(a2, b2), LOAD(m4)); \
    a3 = ADD(ADD(a3, b3), LOAD(m6)); \
    d0 = XOR_ROTATE(d0, a0, 16); \
    d1 = XOR_ROTATE(d1, a1, 16); \
    d2 = XOR_ROTATE(d2, a2, 16); \
    d3 = XOR_ROTATE(d3, a3, 16); \
    c0 = ADD(c0, d0); \
    c1 = ADD(c1, d1); \
    c2 = ADD(c2, d2); \
    c3 = ADD(c3, d3); \
    b0 = XOR_ROTATE(b0, c0, 12); \
    b1 = XOR_ROTATE(b1, c1, 12); \
    b2 = XOR_ROTATE(b2, c2, 12); \
    b3 = XOR_ROTATE(b3, c3, 12); \
    a0 = ADD(ADD(a0, b0), LOAD(m1)); \
    a1 = ADD(ADD(a1, b1), LOAD(m3)); \
    a2 = ADD(ADD(a2, b2), LOAD(m5)); \
    a3 = ADD(ADD(a3, b3), LOAD(m7)); \
    d0 = XOR_ROTATE(d0, a0, 8); \
    d1 = XOR_ROTATE(d1, a1, 8); \
    d2 = XOR_ROTATE(d2, a2, 8); \
    d3 = XOR_ROTATE(d3, a3, 8); \
    c0 = ADD(c0, d0); \
    c1 = ADD(c1, d1); \
    c2 = ADD(c2, d2); \
    c3 = ADD(c3, d3); \
    b0 = XOR_ROTATE(b0, c0, 7); \
    b1 = XOR_ROTATE(b1, c1, 7); \
    b2 = XOR_ROTATE(b2, c2, 7); \
    b3 = XOR_ROTATE(b3, c3, 7); \
} while (0)

#define ROUNDS() do { \
        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
           0, 1, 2, 3, 4, 5, 6, 7); \
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14, \
           8, 9, 10, 11, 12, 13, 14, 15); \
 \
        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
           2, 6, 3, 10, 7, 0, 4, 13); \
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14, \
           1, 11, 12, 5, 9, 14, 15, 8); \
 \
        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
           3, 4, 10, 12, 13, 2, 7, 14); \
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14, \
           6, 5, 9, 0, 11, 15, 8, 1); \
 \
        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
           10, 7, 12, 9, 14, 3, 13, 15); \
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14, \
           4, 0, 11, 2, 5, 8, 1, 6); \
 \
        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
           12, 13, 9, 11, 15, 10, 14, 8); \
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14, \
           7, 2, 5, 3, 0, 1, 6, 4); \
 \
        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
           9, 14, 11, 5, 8, 12, 15, 1); \
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14, \
           13, 3, 0, 10, 2, 6, 4, 7); \
 \
        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
           11, 15, 5, 0, 1, 9, 8, 6); \
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14, \
           14, 10, 2, 12, 3, 4, 7, 13); \
 \
} while (0)

void eidos_compress16_sve2(
    const uint32_t *cv, const uint32_t *block, uint32_t *out, size_t active_lanes) {
    for (size_t base = 0; base < active_lanes; base += svcntw()) {
        svbool_t pg = svwhilelt_b32((uint64_t)base, (uint64_t)active_lanes);
        svuint32_t v0 = svld1_u32(pg, cv + 0 * 16 + base);
        svuint32_t v1 = svld1_u32(pg, cv + 1 * 16 + base);
        svuint32_t v2 = svld1_u32(pg, cv + 2 * 16 + base);
        svuint32_t v3 = svld1_u32(pg, cv + 3 * 16 + base);
        svuint32_t v4 = svld1_u32(pg, cv + 4 * 16 + base);
        svuint32_t v5 = svld1_u32(pg, cv + 5 * 16 + base);
        svuint32_t v6 = svld1_u32(pg, cv + 6 * 16 + base);
        svuint32_t v7 = svld1_u32(pg, cv + 7 * 16 + base);
        svuint32_t v8 = svdup_n_u32(0x6a09e667);
        svuint32_t v9 = svdup_n_u32(0xbb67ae85);
        svuint32_t v10 = svdup_n_u32(0x3c6ef372);
        svuint32_t v11 = svdup_n_u32(0xa54ff53a);
        svuint32_t v12 = svdup_n_u32(0x510e527f);
        svuint32_t v13 = svdup_n_u32(0x9b05688c);
        svuint32_t v14 = svdup_n_u32(0x1f83d9ab);
        svuint32_t v15 = svdup_n_u32(0x5be0cd19);

        ROUNDS();

        svst1_u32(pg, out + 0 * 16 + base, XOR(v0, v8));
        svst1_u32(pg, out + 1 * 16 + base, XOR(v1, v9));
        svst1_u32(pg, out + 2 * 16 + base, XOR(v2, v10));
        svst1_u32(pg, out + 3 * 16 + base, XOR(v3, v11));
        svst1_u32(pg, out + 4 * 16 + base, XOR(v4, v12));
        svst1_u32(pg, out + 5 * 16 + base, XOR(v5, v13));
        svst1_u32(pg, out + 6 * 16 + base, XOR(v6, v14));
        svst1_u32(pg, out + 7 * 16 + base, XOR(v7, v15));
    }
}

// Decode each row once; inactive halves use an in-range pointer and a false predicate.
#undef LOAD
#define LOAD(word) m##word
#define UNPACK(ptr, row, lo, hi) \
    svuint32_t lo, hi; \
    do { \
        svuint32_t first = svreinterpret_u32_u64(svld1_u64(pg_lo, (ptr) + (row) * 16 + base)); \
        svuint32_t second = svreinterpret_u32_u64(svld1_u64(pg_hi, (ptr) + (row) * 16 + second_base)); \
        lo = svuzp1_u32(first, second); \
        hi = svuzp2_u32(first, second); \
    } while (0)
#define PACK(row, lo, hi) do { \
    svuint32_t masked = svand_n_u32_x(pg, (hi), 0x7fffffff); \
    svst1_u64(pg_lo, out + (row) * 16 + base, \
              svreinterpret_u64_u32(svzip1_u32((lo), masked))); \
    svst1_u64(pg_hi, out + (row) * 16 + second_base, \
              svreinterpret_u64_u32(svzip2_u32((lo), masked))); \
} while (0)

void eidos_compress16_u64_sve2(
    const uint64_t *cv, const uint64_t *block, uint64_t *out, size_t active_lanes) {
    const size_t words = svcntw();
    const size_t half = svcntd();
    for (size_t base = 0; base < active_lanes; base += words) {
        svbool_t pg = svwhilelt_b32((uint64_t)base, (uint64_t)active_lanes);
        svbool_t pg_lo = svwhilelt_b64((uint64_t)base, (uint64_t)active_lanes);
        svbool_t pg_hi = svwhilelt_b64((uint64_t)(base + half), (uint64_t)active_lanes);
        // VL can exceed the entire logical batch. Do not even form a pointer past its rows.
        size_t second_base = base + half < active_lanes ? base + half : base;
        UNPACK(cv, 0, v0, v1);
        UNPACK(cv, 1, v2, v3);
        UNPACK(cv, 2, v4, v5);
        UNPACK(cv, 3, v6, v7);
        UNPACK(block, 0, m0, m1);
        UNPACK(block, 1, m2, m3);
        UNPACK(block, 2, m4, m5);
        UNPACK(block, 3, m6, m7);
        UNPACK(block, 4, m8, m9);
        UNPACK(block, 5, m10, m11);
        UNPACK(block, 6, m12, m13);
        UNPACK(block, 7, m14, m15);
        svuint32_t v8 = svdup_n_u32(0x6a09e667);
        svuint32_t v9 = svdup_n_u32(0xbb67ae85);
        svuint32_t v10 = svdup_n_u32(0x3c6ef372);
        svuint32_t v11 = svdup_n_u32(0xa54ff53a);
        svuint32_t v12 = svdup_n_u32(0x510e527f);
        svuint32_t v13 = svdup_n_u32(0x9b05688c);
        svuint32_t v14 = svdup_n_u32(0x1f83d9ab);
        svuint32_t v15 = svdup_n_u32(0x5be0cd19);

        ROUNDS();

        PACK(0, XOR(v0, v8), XOR(v1, v9));
        PACK(1, XOR(v2, v10), XOR(v3, v11));
        PACK(2, XOR(v4, v12), XOR(v5, v13));
        PACK(3, XOR(v6, v14), XOR(v7, v15));
    }
}

#undef UNPACK
#undef PACK

// Single-block rows use only lanes 0..3, independently of the hardware vector length.
#define WORDS(a, b, c, d) svld1_gather_u32index_u32(pg, block, svdupq_n_u32(a, b, c, d))
#define G(x, y) do { \
    a = ADD(ADD(a, b), (x)); \
    d = XOR_ROTATE(d, a, 16); \
    c = ADD(c, d); \
    b = XOR_ROTATE(b, c, 12); \
    a = ADD(ADD(a, b), (y)); \
    d = XOR_ROTATE(d, a, 8); \
    c = ADD(c, d); \
    b = XOR_ROTATE(b, c, 7); \
} while (0)

// Table indices always select the first four lanes, including when VL exceeds 128 bits.
#define ROUND(m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15) do { \
    G(WORDS(m0, m2, m4, m6), WORDS(m1, m3, m5, m7)); \
    b = svtbl_u32(b, left1); \
    c = svtbl_u32(c, left2); \
    d = svtbl_u32(d, left3); \
    G(WORDS(m8, m10, m12, m14), WORDS(m9, m11, m13, m15)); \
    b = svtbl_u32(b, left3); \
    c = svtbl_u32(c, left2); \
    d = svtbl_u32(d, left1); \
} while (0)

static inline __attribute__((always_inline)) svuint32x4_t compress_pre(const uint32_t *cv, const uint32_t *block) {
    const svbool_t pg = svptrue_pat_b32(SV_VL4);
    const svuint32_t left1 = svdupq_n_u32(1, 2, 3, 0);
    const svuint32_t left2 = svdupq_n_u32(2, 3, 0, 1);
    const svuint32_t left3 = svdupq_n_u32(3, 0, 1, 2);
    svuint32_t a = svld1_u32(pg, cv);
    svuint32_t b = svld1_u32(pg, cv + 4);
    svuint32_t c = svdupq_n_u32(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a);
    svuint32_t d = svdupq_n_u32(0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);

    ROUND(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    ROUND(2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8);
    ROUND(3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1);
    ROUND(10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6);
    ROUND(12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4);
    ROUND(9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7);
    ROUND(11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13);
    return svcreate4_u32(a, b, c, d);
}

void eidos_compress_raw_sve2(const uint32_t *cv, const uint32_t *block, uint32_t *out) {
    const svbool_t pg = svptrue_pat_b32(SV_VL4);
    const svuint32x4_t v = compress_pre(cv, block);
    svst1_u32(pg, out, XOR(svget4_u32(v, 0), svget4_u32(v, 2)));
    svst1_u32(pg, out + 4, XOR(svget4_u32(v, 1), svget4_u32(v, 3)));
}

void eidos_compress_xof_sve2(const uint32_t *cv, const uint32_t *block, uint32_t *out) {
    const svbool_t pg = svptrue_pat_b32(SV_VL4);
    const svuint32x4_t v = compress_pre(cv, block);
    const svuint32_t cv0 = svld1_u32(pg, cv);
    const svuint32_t cv1 = svld1_u32(pg, cv + 4);
    svst1_u32(pg, out, XOR(svget4_u32(v, 0), svget4_u32(v, 2)));
    svst1_u32(pg, out + 4, XOR(svget4_u32(v, 1), svget4_u32(v, 3)));
    svst1_u32(pg, out + 8, XOR(svget4_u32(v, 2), cv0));
    svst1_u32(pg, out + 12, XOR(svget4_u32(v, 3), cv1));
}

void eidos_compress_blocks_sve2(const uint32_t *cv, const uint32_t *blocks, uint32_t *out, size_t count) {
    uint32_t state[8];
    for (size_t i = 0; i < 8; ++i) state[i] = cv[i];
    for (size_t i = 0; i < count; ++i) {
        const svbool_t pg = svptrue_pat_b32(SV_VL4);
        const svuint32x4_t v = compress_pre(state, blocks + 16 * i);
        const svuint32_t mask = svdupq_n_u32(UINT32_MAX, 0x7fffffff, UINT32_MAX, 0x7fffffff);
        svst1_u32(pg, state, svand_u32_x(pg, XOR(svget4_u32(v, 0), svget4_u32(v, 2)), mask));
        svst1_u32(pg, state + 4, svand_u32_x(pg, XOR(svget4_u32(v, 1), svget4_u32(v, 3)), mask));
    }
    for (size_t i = 0; i < 8; ++i) out[i] = state[i];
}

// Prepared canonical CV already includes the partial-buffer transition tag.
#undef LOAD
#define LOAD(word) (squeeze ? svdup_n_u32(0) : \
    ((word) == 2 * buffer_len ? nonce_lo : \
    ((word) == 2 * buffer_len + 1 ? nonce_hi : \
    svdup_n_u32((uint32_t)(buffer[(word) / 2] >> (32 * ((word) % 2)))))))

uint16_t eidos_check_witness_batch_sve2(const uint64_t *cv, const uint64_t *buffer,
    size_t buffer_len, uint64_t nonce_base, size_t count, uint64_t mask) {
    uint16_t accepted = 0;
    for (size_t base = 0; base < count; base += svcntw()) {
        svbool_t pg = svwhilelt_b32((uint64_t)base, (uint64_t)count);
        svuint32_t offsets = svindex_u32((uint32_t)base, 1);
        svuint32_t nonce_lo = svadd_n_u32_x(pg, offsets, (uint32_t)nonce_base);
        svuint32_t carry = svdup_n_u32_z(svcmplt_n_u32(pg, nonce_lo, (uint32_t)nonce_base), 1);
        svuint32_t nonce_hi = svadd_n_u32_x(pg, carry, (uint32_t)(nonce_base >> 32));
        svuint32_t v0 = svdup_n_u32((uint32_t)(cv[0] >> 0));
        svuint32_t v1 = svdup_n_u32((uint32_t)(cv[0] >> 32));
        svuint32_t v2 = svdup_n_u32((uint32_t)(cv[1] >> 0));
        svuint32_t v3 = svdup_n_u32((uint32_t)(cv[1] >> 32));
        svuint32_t v4 = svdup_n_u32((uint32_t)(cv[2] >> 0));
        svuint32_t v5 = svdup_n_u32((uint32_t)(cv[2] >> 32));
        svuint32_t v6 = svdup_n_u32((uint32_t)(cv[3] >> 0));
        svuint32_t v7 = svdup_n_u32((uint32_t)(cv[3] >> 32));
        for (int squeeze = 0; ; ++squeeze) {
            svuint32_t v8 = svdup_n_u32(0x6a09e667);
            svuint32_t v9 = svdup_n_u32(0xbb67ae85);
            svuint32_t v10 = svdup_n_u32(0x3c6ef372);
            svuint32_t v11 = svdup_n_u32(0xa54ff53a);
            svuint32_t v12 = svdup_n_u32(0x510e527f);
            svuint32_t v13 = svdup_n_u32(0x9b05688c);
            svuint32_t v14 = svdup_n_u32(0x1f83d9ab);
            svuint32_t v15 = svdup_n_u32(0x5be0cd19);

            ROUNDS();
            if (buffer_len != 7 || squeeze) {
                svuint32_t lo = svand_n_u32_x(pg, XOR(v0, v8), (uint32_t)mask);
                svuint32_t hi = svand_n_u32_x(pg, XOR(v1, v9), (uint32_t)(mask >> 32) & 0x7fffffff);
                svbool_t pass = svcmpeq_n_u32(pg, svorr_u32_x(pg, lo, hi), 0);
                svuint32_t bits = svlsl_u32_x(pg, svdup_n_u32(1), offsets);
                accepted |= (uint16_t)svorv_u32(pg, svsel_u32(pass, bits, svdup_n_u32(0)));
                break;
            }
            v0 = XOR(v0, v8);
            v1 = svand_n_u32_x(pg, XOR(v1, v9), 0x7fffffff);
            v2 = XOR(v2, v10);
            v3 = svand_n_u32_x(pg, XOR(v3, v11), 0x7fffffff);
            v4 = XOR(v4, v12);
            v5 = svand_n_u32_x(pg, XOR(v5, v13), 0x7fffffff);
            v6 = XOR(v6, v14);
            v7 = svand_n_u32_x(pg, XOR(v7, v15), 0x7fffffff);
            // Packed intermediate word is 63 bits, so the tag needs only a low-word carry.
            svuint32_t old6 = v6;
            v6 = svadd_n_u32_x(pg, v6, 1);
            v7 = svadd_u32_x(pg, v7, svdup_n_u32_z(svcmplt_u32(pg, v6, old6), 1));
        }
    }
    return accepted;
}
