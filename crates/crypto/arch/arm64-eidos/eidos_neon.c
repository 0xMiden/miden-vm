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

static inline __attribute__((always_inline)) uint32x4x4_t compress_pre(const uint32_t *cv, const uint32_t *block) {
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

void eidos_compress_blocks_neon(const uint32_t *cv, const uint32_t *blocks, uint32_t *out, size_t count) {
    uint32_t state[8];
    for (size_t i = 0; i < 8; ++i) state[i] = cv[i];
    for (size_t i = 0; i < count; ++i) {
        const uint32x4x4_t v = compress_pre(state, blocks + 16 * i);
        const uint32x4_t mask = {UINT32_MAX, 0x7fffffff, UINT32_MAX, 0x7fffffff};
        vst1q_u32(state, vandq_u32(veorq_u32(v.val[0], v.val[2]), mask));
        vst1q_u32(state + 4, vandq_u32(veorq_u32(v.val[1], v.val[3]), mask));
    }
    for (size_t i = 0; i < 8; ++i) out[i] = state[i];
}

// Each vector holds one state word across four consecutive candidates.
#define ADD(a, b) vaddq_u32((a), (b))
#define XOR(a, b) veorq_u32((a), (b))
#define XOR_ROTATE(a, b, n) rotate##n(XOR((a), (b)))

static inline uint32x4_t rotate12(uint32x4_t x) {
    return vsriq_n_u32(vshlq_n_u32(x, 20), x, 12);
}

static inline uint32x4_t rotate7(uint32x4_t x) {
    return vsriq_n_u32(vshlq_n_u32(x, 25), x, 7);
}

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

// Tail staging is bounded to one four-candidate row; full groups load directly.
static inline uint32x4x2_t unpack_u64(const uint64_t *input, size_t count) {
    uint64_t tail[4] = {0};
    if (count < 4) {
        for (size_t i = 0; i < count; ++i) tail[i] = input[i];
        input = tail;
    }
    uint32x4_t a = vreinterpretq_u32_u64(vld1q_u64(input));
    uint32x4_t b = vreinterpretq_u32_u64(vld1q_u64(input + 2));
    return (uint32x4x2_t){{vuzp1q_u32(a, b), vuzp2q_u32(a, b)}};
}

static inline void pack_u64(uint64_t *out, uint32x4_t lo, uint32x4_t hi, size_t count) {
    hi = vandq_u32(hi, vdupq_n_u32(0x7fffffff));
    uint64x2_t a = vreinterpretq_u64_u32(vzip1q_u32(lo, hi));
    uint64x2_t b = vreinterpretq_u64_u32(vzip2q_u32(lo, hi));
    if (count == 4) {
        vst1q_u64(out, a);
        vst1q_u64(out + 2, b);
    } else {
        uint64_t tail[4];
        vst1q_u64(tail, a);
        vst1q_u64(tail + 2, b);
        for (size_t i = 0; i < count; ++i) out[i] = tail[i];
    }
}

#define LOAD(word) unpack_u64(block + ((word) / 2) * 16 + base, count).val[(word) % 2]
void eidos_compress16_u64_neon(const uint64_t *cv, const uint64_t *block,
    uint64_t *out, size_t active_lanes) {
    for (size_t base = 0; base < active_lanes; base += 4) {
        size_t count = active_lanes - base < 4 ? active_lanes - base : 4;
        uint32x4x2_t c0 = unpack_u64(cv + base, count);
        uint32x4x2_t c1 = unpack_u64(cv + 16 + base, count);
        uint32x4x2_t c2 = unpack_u64(cv + 32 + base, count);
        uint32x4x2_t c3 = unpack_u64(cv + 48 + base, count);
        uint32x4_t v0 = c0.val[0], v1 = c0.val[1];
        uint32x4_t v2 = c1.val[0], v3 = c1.val[1];
        uint32x4_t v4 = c2.val[0], v5 = c2.val[1];
        uint32x4_t v6 = c3.val[0], v7 = c3.val[1];
        uint32x4_t v8 = vdupq_n_u32(0x6a09e667), v9 = vdupq_n_u32(0xbb67ae85);
        uint32x4_t v10 = vdupq_n_u32(0x3c6ef372), v11 = vdupq_n_u32(0xa54ff53a);
        uint32x4_t v12 = vdupq_n_u32(0x510e527f), v13 = vdupq_n_u32(0x9b05688c);
        uint32x4_t v14 = vdupq_n_u32(0x1f83d9ab), v15 = vdupq_n_u32(0x5be0cd19);
        ROUNDS();
        pack_u64(out + base, XOR(v0, v8), XOR(v1, v9), count);
        pack_u64(out + 16 + base, XOR(v2, v10), XOR(v3, v11), count);
        pack_u64(out + 32 + base, XOR(v4, v12), XOR(v5, v13), count);
        pack_u64(out + 48 + base, XOR(v6, v14), XOR(v7, v15), count);
    }
}
#undef LOAD

// Prepared canonical CV already includes the partial-buffer transition tag.
#define LOAD(word) (squeeze ? vdupq_n_u32(0) : \
    ((word) == 2 * buffer_len ? nonce_lo : \
    ((word) == 2 * buffer_len + 1 ? nonce_hi : \
    vdupq_n_u32((uint32_t)(buffer[(word) / 2] >> (32 * ((word) % 2)))))))

uint16_t eidos_check_witness_batch_neon(const uint64_t *cv, const uint64_t *buffer,
    size_t buffer_len, uint64_t nonce_base, size_t count, uint64_t mask) {
    uint16_t accepted = 0;
    for (size_t base = 0; base < count; base += 4) {
        uint32x4_t offsets = vaddq_u32(vdupq_n_u32((uint32_t)base), (uint32x4_t){0, 1, 2, 3});
        uint32x4_t active = vcltq_u32(offsets, vdupq_n_u32((uint32_t)count));
        uint32x4_t nonce_lo = vaddq_u32(offsets, vdupq_n_u32((uint32_t)nonce_base));
        uint32x4_t carry = vshrq_n_u32(vcltq_u32(nonce_lo, vdupq_n_u32((uint32_t)nonce_base)), 31);
        uint32x4_t nonce_hi = vaddq_u32(carry, vdupq_n_u32((uint32_t)(nonce_base >> 32)));
        uint32x4_t v0 = vdupq_n_u32((uint32_t)(cv[0] >> 0));
        uint32x4_t v1 = vdupq_n_u32((uint32_t)(cv[0] >> 32));
        uint32x4_t v2 = vdupq_n_u32((uint32_t)(cv[1] >> 0));
        uint32x4_t v3 = vdupq_n_u32((uint32_t)(cv[1] >> 32));
        uint32x4_t v4 = vdupq_n_u32((uint32_t)(cv[2] >> 0));
        uint32x4_t v5 = vdupq_n_u32((uint32_t)(cv[2] >> 32));
        uint32x4_t v6 = vdupq_n_u32((uint32_t)(cv[3] >> 0));
        uint32x4_t v7 = vdupq_n_u32((uint32_t)(cv[3] >> 32));
        for (int squeeze = 0; ; ++squeeze) {
            uint32x4_t v8 = vdupq_n_u32(0x6a09e667);
            uint32x4_t v9 = vdupq_n_u32(0xbb67ae85);
            uint32x4_t v10 = vdupq_n_u32(0x3c6ef372);
            uint32x4_t v11 = vdupq_n_u32(0xa54ff53a);
            uint32x4_t v12 = vdupq_n_u32(0x510e527f);
            uint32x4_t v13 = vdupq_n_u32(0x9b05688c);
            uint32x4_t v14 = vdupq_n_u32(0x1f83d9ab);
            uint32x4_t v15 = vdupq_n_u32(0x5be0cd19);

            ROUNDS();
            if (buffer_len != 7 || squeeze) {
                uint32x4_t lo = vandq_u32(XOR(v0, v8), vdupq_n_u32((uint32_t)mask));
                uint32x4_t hi = vandq_u32(XOR(v1, v9), vdupq_n_u32((uint32_t)(mask >> 32) & 0x7fffffff));
                uint32x4_t pass = vandq_u32(active, vceqq_u32(vorrq_u32(lo, hi), vdupq_n_u32(0)));
                uint32x4_t bits = vshlq_u32(vdupq_n_u32(1), vreinterpretq_s32_u32(offsets));
                accepted |= (uint16_t)vaddvq_u32(vandq_u32(pass, bits));
                break;
            }
            v0 = XOR(v0, v8);
            v1 = vandq_u32(XOR(v1, v9), vdupq_n_u32(0x7fffffff));
            v2 = XOR(v2, v10);
            v3 = vandq_u32(XOR(v3, v11), vdupq_n_u32(0x7fffffff));
            v4 = XOR(v4, v12);
            v5 = vandq_u32(XOR(v5, v13), vdupq_n_u32(0x7fffffff));
            v6 = XOR(v6, v14);
            v7 = vandq_u32(XOR(v7, v15), vdupq_n_u32(0x7fffffff));
            // Packed intermediate word is 63 bits, so the tag needs only a low-word carry.
            uint32x4_t old6 = v6;
            v6 = vaddq_u32(v6, vdupq_n_u32(1));
            v7 = vaddq_u32(v7, vshrq_n_u32(vcltq_u32(v6, old6), 31));
        }
    }
    return accepted;
}
