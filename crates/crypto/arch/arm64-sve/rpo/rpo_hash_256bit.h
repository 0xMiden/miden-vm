#ifndef RPO_SVE_RPO_HASH_256_H
#define RPO_SVE_RPO_HASH_256_H

#include <arm_sve.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define STATE_WIDTH 12

#define COPY_256(NAME, VIN1, VIN2, SIN3)                \
    svuint64_t NAME ## _1 = VIN1;                   \
    svuint64_t NAME ## _2 = VIN2;                   \
    uint64_t NAME ## _3[4];                         \
    memcpy(NAME ## _3, SIN3, 4 * sizeof(uint64_t))

#define MULTIPLY_256(PRED, DEST, OP)                    \
    mul_256(PRED, &DEST ## _1, &OP ## _1, &DEST ## _2, &OP ## _2, DEST ## _3, OP ## _3)

#define SQUARE_256(PRED, NAME)                          \
    sq_256(PRED, &NAME ## _1, &NAME ## _2, NAME ## _3)

#define SQUARE_DEST_256(PRED, DEST, SRC)                \
    COPY_256(DEST, SRC ## _1, SRC ## _2, SRC ## _3);    \
    SQUARE_256(PRED, DEST);

#define POW_ACC(PRED, NAME, CNT, TAIL)              \
    for (size_t i = 0; i < CNT; i++) {              \
        SQUARE_256(PRED, NAME);                         \
    }                                               \
    MULTIPLY_256(PRED, NAME, TAIL);

#define POW_ACC_DEST_256(PRED, DEST, CNT, HEAD, TAIL)   \
    COPY_256(DEST, HEAD ## _1, HEAD ## _2, HEAD ## _3); \
    POW_ACC(PRED, DEST, CNT, TAIL)

extern inline void add_constants_256(
    svbool_t pg,
    svuint64_t *state1,
    svuint64_t *const1,
    svuint64_t *state2,
    svuint64_t *const2,
    uint64_t *state3,
    uint64_t *const3
) {
    uint64_t Ms = 0xFFFFFFFF00000001ull;
    svuint64_t Mv = svindex_u64(Ms, 0);

    uint64_t p_1 = Ms - const3[0];
    uint64_t p_2 = Ms - const3[1];
    uint64_t p_3 = Ms - const3[2];
    uint64_t p_4 = Ms - const3[3];

    uint64_t x_1, x_2, x_3, x_4;
    uint32_t adj_1 = -__builtin_sub_overflow(state3[0], p_1, &x_1);
    uint32_t adj_2 = -__builtin_sub_overflow(state3[1], p_2, &x_2);
    uint32_t adj_3 = -__builtin_sub_overflow(state3[2], p_3, &x_3);
    uint32_t adj_4 = -__builtin_sub_overflow(state3[3], p_4, &x_4);

    state3[0] = x_1 - (uint64_t)adj_1;
    state3[1] = x_2 - (uint64_t)adj_2;
    state3[2] = x_3 - (uint64_t)adj_3;
    state3[3] = x_4 - (uint64_t)adj_4;

    svuint64_t p1 = svsub_x(pg, Mv, *const1);
    svuint64_t p2 = svsub_x(pg, Mv, *const2);

    svuint64_t x1 = svsub_x(pg, *state1, p1);
    svuint64_t x2 = svsub_x(pg, *state2, p2);

    svbool_t pt1 = svcmplt_u64(pg, *state1, p1);
    svbool_t pt2 = svcmplt_u64(pg, *state2, p2);

    *state1 = svsub_m(pt1, x1, (uint32_t)-1);
    *state2 = svsub_m(pt2, x2, (uint32_t)-1);
}

extern inline void mul_256(
    svbool_t pg,
    svuint64_t *r1,
    const svuint64_t *op1,
    svuint64_t *r2,
    const svuint64_t *op2,
    uint64_t *r3,
    const uint64_t *op3
) {
    __uint128_t x_1 = r3[0];
    __uint128_t x_2 = r3[1];
    __uint128_t x_3 = r3[2];
    __uint128_t x_4 = r3[3];

    x_1 *= (__uint128_t) op3[0];
    x_2 *= (__uint128_t) op3[1];
    x_3 *= (__uint128_t) op3[2];
    x_4 *= (__uint128_t) op3[3];

    uint64_t x0_1 = x_1;
    uint64_t x0_2 = x_2;
    uint64_t x0_3 = x_3;
    uint64_t x0_4 = x_4;

    svuint64_t l1 = svmul_x(pg, *r1, *op1);
    svuint64_t l2 = svmul_x(pg, *r2, *op2);

    uint64_t x1_1 = (x_1 >> 64);
    uint64_t x1_2 = (x_2 >> 64);
    uint64_t x1_3 = (x_3 >> 64);
    uint64_t x1_4 = (x_4 >> 64);

    uint64_t a_1, a_2, a_3, a_4;
    uint64_t e_1 = __builtin_add_overflow(x0_1, (x0_1 << 32), &a_1);
    uint64_t e_2 = __builtin_add_overflow(x0_2, (x0_2 << 32), &a_2);
    uint64_t e_3 = __builtin_add_overflow(x0_3, (x0_3 << 32), &a_3);
    uint64_t e_4 = __builtin_add_overflow(x0_4, (x0_4 << 32), &a_4);

    svuint64_t ls1 = svlsl_x(pg, l1, 32);
    svuint64_t ls2 = svlsl_x(pg, l2, 32);

    svuint64_t a1 = svadd_x(pg, l1, ls1);
    svuint64_t a2 = svadd_x(pg, l2, ls2);

    svbool_t e1 = svcmplt(pg, a1, l1);
    svbool_t e2 = svcmplt(pg, a2, l2);

    svuint64_t as1 = svlsr_x(pg, a1, 32);
    svuint64_t as2 = svlsr_x(pg, a2, 32);

    svuint64_t b1 = svsub_x(pg, a1, as1);
    svuint64_t b2 = svsub_x(pg, a2, as2);

    b1 = svsub_m(e1, b1, 1);
    b2 = svsub_m(e2, b2, 1);

    uint64_t b_1 = a_1 - (a_1 >> 32) - e_1;
    uint64_t b_2 = a_2 - (a_2 >> 32) - e_2;
    uint64_t b_3 = a_3 - (a_3 >> 32) - e_3;
    uint64_t b_4 = a_4 - (a_4 >> 32) - e_4;

    uint64_t r_1, r_2, r_3, r_4;
    uint32_t c_1 = __builtin_sub_overflow(x1_1, b_1, &r_1);
    uint32_t c_2 = __builtin_sub_overflow(x1_2, b_2, &r_2);
    uint32_t c_3 = __builtin_sub_overflow(x1_3, b_3, &r_3);
    uint32_t c_4 = __builtin_sub_overflow(x1_4, b_4, &r_4);

    svuint64_t h1 = svmulh_x(pg, *r1, *op1);
    svuint64_t h2 = svmulh_x(pg, *r2, *op2);

    svuint64_t tr1 = svsub_x(pg, h1, b1);
    svuint64_t tr2 = svsub_x(pg, h2, b2);

    svbool_t c1 = svcmplt_u64(pg, h1, b1);
    svbool_t c2 = svcmplt_u64(pg, h2, b2);

    *r1 = svsub_m(c1, tr1, (uint32_t) -1);
    *r2 = svsub_m(c2, tr2, (uint32_t) -1);

    uint32_t minus1_1 = 0 - c_1;
    uint32_t minus1_2 = 0 - c_2;
    uint32_t minus1_3 = 0 - c_3;
    uint32_t minus1_4 = 0 - c_4;

    r3[0] = r_1 - (uint64_t)minus1_1;
    r3[1] = r_2 - (uint64_t)minus1_2;
    r3[2] = r_3 - (uint64_t)minus1_3;
    r3[3] = r_4 - (uint64_t)minus1_4;
}

extern inline void sq_256(svbool_t pg, svuint64_t *a, svuint64_t *b, uint64_t *c) {
    mul_256(pg, a, a, b, b, c, c);
}

extern inline void apply_sbox_256(
    svbool_t pg,
    svuint64_t *state1,
    svuint64_t *state2,
    uint64_t *state3
) {
    COPY_256(x, *state1, *state2, state3);                // copy input to x
    SQUARE_256(pg, x);                                    // x contains input^2
    mul_256(pg, state1, &x_1, state2, &x_2, state3, x_3); // state contains input^3
    SQUARE_256(pg, x);                                    // x contains input^4
    mul_256(pg, state1, &x_1, state2, &x_2, state3, x_3); // state contains input^7
}

extern inline void apply_inv_sbox_256(
    svbool_t pg,
    svuint64_t *state_1,
    svuint64_t *state_2,
    uint64_t *state_3
) {
    // base^10
    COPY_256(t1, *state_1, *state_2, state_3);
    SQUARE_256(pg, t1);

    // base^100
    SQUARE_DEST_256(pg, t2, t1);

    // base^100100
    POW_ACC_DEST_256(pg, t3, 3, t2, t2);

    // base^100100100100
    POW_ACC_DEST_256(pg, t4, 6, t3, t3);

    // compute base^100100100100100100100100
    POW_ACC_DEST_256(pg, t5, 12, t4, t4);

    // compute base^100100100100100100100100100100
    POW_ACC_DEST_256(pg, t6, 6, t5, t3);

    // compute base^1001001001001001001001001001000100100100100100100100100100100
    POW_ACC_DEST_256(pg, t7, 31, t6, t6);

    // compute base^1001001001001001001001001001000110110110110110110110110110110111
    SQUARE_256(pg, t7);
    MULTIPLY_256(pg, t7, t6);
    SQUARE_256(pg, t7);
    SQUARE_256(pg, t7);
    MULTIPLY_256(pg, t7, t1);
    MULTIPLY_256(pg, t7, t2);
    mul_256(pg, state_1, &t7_1, state_2, &t7_2, state_3, t7_3);
}

bool add_constants_and_apply_sbox_256(uint64_t state[STATE_WIDTH], uint64_t constants[STATE_WIDTH]) {
    const uint64_t vl = 4;   // number of u64 numbers in one 128 bit SVE vector
    svbool_t ptrue = svptrue_b64();

    svuint64_t state1 = svld1(ptrue, state + 0 * vl);
    svuint64_t state2 = svld1(ptrue, state + 1 * vl);

    svuint64_t const1 = svld1(ptrue, constants + 0 * vl);
    svuint64_t const2 = svld1(ptrue, constants + 1 * vl);

    add_constants_256(ptrue, &state1, &const1, &state2, &const2, state + 8, constants + 8);
    apply_sbox_256(ptrue, &state1, &state2, state + 8);

    svst1(ptrue, state + 0 * vl, state1);
    svst1(ptrue, state + 1 * vl, state2);

    return true;
}

bool add_constants_and_apply_inv_sbox_256(uint64_t state[STATE_WIDTH], uint64_t constants[STATE_WIDTH]) {
    const uint64_t vl = 4;   // number of u64 numbers in one 128 bit SVE vector
    svbool_t ptrue = svptrue_b64();

    svuint64_t state1 = svld1(ptrue, state + 0 * vl);
    svuint64_t state2 = svld1(ptrue, state + 1 * vl);

    svuint64_t const1 = svld1(ptrue, constants + 0 * vl);
    svuint64_t const2 = svld1(ptrue, constants + 1 * vl);

    add_constants_256(ptrue, &state1, &const1, &state2, &const2, state + 8, constants + 8);
    apply_inv_sbox_256(ptrue, &state1, &state2, state + 8);

    svst1(ptrue, state + 0 * vl, state1);
    svst1(ptrue, state + 1 * vl, state2);

    return true;
}

#endif //RPO_SVE_RPO_HASH_256_H
