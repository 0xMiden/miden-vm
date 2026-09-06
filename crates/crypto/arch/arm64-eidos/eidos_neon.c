#include "eidos_arm.h"
#include <arm_neon.h>

static inline uint32x4_t rotate16(uint32x4_t x) {
    return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)));
}

static inline uint32x4_t rotate8(uint32x4_t x) {
    const uint8x16_t indices = {1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12};
    return vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), indices));
}

// Each vector holds a row of four state words; G advances four columns together.
#define WORDS(a, b, c, d) ((uint32x4_t){block[a], block[b], block[c], block[d]})
#define G(x, y) do { \
    a = vaddq_u32(vaddq_u32(a, b), (x)); \
    d = rotate16(veorq_u32(d, a)); \
    c = vaddq_u32(c, d); \
    b = veorq_u32(b, c); \
    b = vsriq_n_u32(vshlq_n_u32(b, 20), b, 12); \
    a = vaddq_u32(vaddq_u32(a, b), (y)); \
    d = rotate8(veorq_u32(d, a)); \
    c = vaddq_u32(c, d); \
    b = veorq_u32(b, c); \
    b = vsriq_n_u32(vshlq_n_u32(b, 25), b, 7); \
} while (0)

#define ROUND(m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15) do { \
    G(WORDS(m0, m2, m4, m6), WORDS(m1, m3, m5, m7)); \
    b = vextq_u32(b, b, 1); \
    c = vextq_u32(c, c, 2); \
    d = vextq_u32(d, d, 3); \
    G(WORDS(m8, m10, m12, m14), WORDS(m9, m11, m13, m15)); \
    b = vextq_u32(b, b, 3); \
    c = vextq_u32(c, c, 2); \
    d = vextq_u32(d, d, 1); \
} while (0)

static inline uint32x4x4_t compress_pre(const uint32_t *cv, const uint32_t *block) {
    uint32x4_t a = vld1q_u32(cv);
    uint32x4_t b = vld1q_u32(cv + 4);
    uint32x4_t c = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a};
    uint32x4_t d = {0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    ROUND(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    ROUND(2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8);
    ROUND(3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1);
    ROUND(10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6);
    ROUND(12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4);
    ROUND(9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7);
    ROUND(11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13);
    return (uint32x4x4_t){{a, b, c, d}};
}

void eidos_compress_raw_neon(const uint32_t *cv, const uint32_t *block, uint32_t *out) {
    const uint32x4x4_t v = compress_pre(cv, block);
    vst1q_u32(out, veorq_u32(v.val[0], v.val[2]));
    vst1q_u32(out + 4, veorq_u32(v.val[1], v.val[3]));
}

void eidos_compress_xof_neon(const uint32_t *cv, const uint32_t *block, uint32_t *out) {
    const uint32x4x4_t v = compress_pre(cv, block);
    const uint32x4_t cv0 = vld1q_u32(cv);
    const uint32x4_t cv1 = vld1q_u32(cv + 4);
    vst1q_u32(out, veorq_u32(v.val[0], v.val[2]));
    vst1q_u32(out + 4, veorq_u32(v.val[1], v.val[3]));
    vst1q_u32(out + 8, veorq_u32(v.val[2], cv0));
    vst1q_u32(out + 12, veorq_u32(v.val[3], cv1));
}
