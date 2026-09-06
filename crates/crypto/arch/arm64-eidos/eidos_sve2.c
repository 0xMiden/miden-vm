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

        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15,
           0, 1, 2, 3, 4, 5, 6, 7);
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14,
           8, 9, 10, 11, 12, 13, 14, 15);

        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15,
           2, 6, 3, 10, 7, 0, 4, 13);
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14,
           1, 11, 12, 5, 9, 14, 15, 8);

        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15,
           3, 4, 10, 12, 13, 2, 7, 14);
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14,
           6, 5, 9, 0, 11, 15, 8, 1);

        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15,
           10, 7, 12, 9, 14, 3, 13, 15);
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14,
           4, 0, 11, 2, 5, 8, 1, 6);

        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15,
           12, 13, 9, 11, 15, 10, 14, 8);
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14,
           7, 2, 5, 3, 0, 1, 6, 4);

        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15,
           9, 14, 11, 5, 8, 12, 15, 1);
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14,
           13, 3, 0, 10, 2, 6, 4, 7);

        G4(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15,
           11, 15, 5, 0, 1, 9, 8, 6);
        G4(v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14,
           14, 10, 2, 12, 3, 4, 7, 13);

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

static inline svuint32x4_t compress_pre(const uint32_t *cv, const uint32_t *block) {
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
