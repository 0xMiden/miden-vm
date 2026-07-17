#ifndef RPO_SVE_RPO_HASH_128_H
#define RPO_SVE_RPO_HASH_128_H

#include <arm_sve.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define STATE_WIDTH 12

#define COPY_128(NAME, VIN1, VIN2, VIN3, VIN4, SIN)     \
    svuint64_t NAME ## _1 = VIN1;                   \
    svuint64_t NAME ## _2 = VIN2;                   \
    svuint64_t NAME ## _3 = VIN3;                   \
    svuint64_t NAME ## _4 = VIN4;                   \
    uint64_t NAME ## _tail[4];                      \
    memcpy(NAME ## _tail, SIN, 4 * sizeof(uint64_t))

#define MULTIPLY_128(PRED, DEST, OP)                    \
    mul_128(PRED, &DEST ## _1, &OP ## _1, &DEST ## _2, &OP ## _2, &DEST ## _3, &OP ## _3, &DEST ## _4, &OP ## _4, DEST ## _tail, OP ## _tail)

#define SQUARE_128(PRED, NAME)                          \
    sq_128(PRED, &NAME ## _1, &NAME ## _2, &NAME ## _3, &NAME ## _4, NAME ## _tail)

#define SQUARE_DEST_128(PRED, DEST, SRC)                \
    COPY_128(DEST, SRC ## _1, SRC ## _2, SRC ## _3, SRC ## _4, SRC ## _tail);    \
    SQUARE_128(PRED, DEST);

#define POW_ACC_128(PRED, NAME, CNT, TAIL)              \
    for (size_t i = 0; i < CNT; i++) {              \
        SQUARE_128(PRED, NAME);                         \
    }                                               \
    MULTIPLY_128(PRED, NAME, TAIL);

#define POW_ACC_DEST(PRED, DEST, CNT, HEAD, TAIL)   \
    COPY_128(DEST, HEAD ## _1, HEAD ## _2, HEAD ## _3, HEAD ## _4, HEAD ## _tail); \
    POW_ACC_128(PRED, DEST, CNT, TAIL)

extern inline void add_constants_128(
    svbool_t pg,
    svuint64_t *state1,
    svuint64_t *const1,
    svuint64_t *state2,
    svuint64_t *const2,
    svuint64_t *state3,
    svuint64_t *const3,
    svuint64_t *state4,
    svuint64_t *const4,

    uint64_t *state_tail,
    uint64_t *const_tail
) {
    uint64_t Ms = 0xFFFFFFFF00000001ull;
    svuint64_t Mv = svindex_u64(Ms, 0);

    uint64_t p_1 = Ms - const_tail[0];
    uint64_t p_2 = Ms - const_tail[1];
    uint64_t p_3 = Ms - const_tail[2];
    uint64_t p_4 = Ms - const_tail[3];

    uint64_t x_1, x_2, x_3, x_4;
    uint32_t adj_1 = -__builtin_sub_overflow(state_tail[0], p_1, &x_1);
    uint32_t adj_2 = -__builtin_sub_overflow(state_tail[1], p_2, &x_2);
    uint32_t adj_3 = -__builtin_sub_overflow(state_tail[2], p_3, &x_3);
    uint32_t adj_4 = -__builtin_sub_overflow(state_tail[3], p_4, &x_4);

    state_tail[0] = x_1 - (uint64_t)adj_1;
    state_tail[1] = x_2 - (uint64_t)adj_2;
    state_tail[2] = x_3 - (uint64_t)adj_3;
    state_tail[3] = x_4 - (uint64_t)adj_4;

    svuint64_t p1 = svsub_x(pg, Mv, *const1);
    svuint64_t p2 = svsub_x(pg, Mv, *const2);
    svuint64_t p3 = svsub_x(pg, Mv, *const3);
    svuint64_t p4 = svsub_x(pg, Mv, *const4);

    svuint64_t x1 = svsub_x(pg, *state1, p1);
    svuint64_t x2 = svsub_x(pg, *state2, p2);
    svuint64_t x3 = svsub_x(pg, *state3, p3);
    svuint64_t x4 = svsub_x(pg, *state4, p4);

    svbool_t pt1 = svcmplt_u64(pg, *state1, p1);
    svbool_t pt2 = svcmplt_u64(pg, *state2, p2);
    svbool_t pt3 = svcmplt_u64(pg, *state3, p3);
    svbool_t pt4 = svcmplt_u64(pg, *state4, p4);

    *state1 = svsub_m(pt1, x1, (uint32_t)-1);
    *state2 = svsub_m(pt2, x2, (uint32_t)-1);
    *state3 = svsub_m(pt3, x3, (uint32_t)-1);
    *state4 = svsub_m(pt4, x4, (uint32_t)-1);
}

extern inline void mul_128(
    svbool_t pg,
    svuint64_t *r1,
    const svuint64_t *op1,
    svuint64_t *r2,
    const svuint64_t *op2,
    svuint64_t *r3,
    const svuint64_t *op3,
    svuint64_t *r4,
    const svuint64_t *op4,
    uint64_t *r_tail,
    const uint64_t *op_tail
) {
    __uint128_t x_1 = r_tail[0];
    __uint128_t x_2 = r_tail[1];
    __uint128_t x_3 = r_tail[2];
    __uint128_t x_4 = r_tail[3];

    x_1 *= (__uint128_t) op_tail[0];
    x_2 *= (__uint128_t) op_tail[1];
    x_3 *= (__uint128_t) op_tail[2];
    x_4 *= (__uint128_t) op_tail[3];

    uint64_t x0_1 = x_1;
    uint64_t x0_2 = x_2;
    uint64_t x0_3 = x_3;
    uint64_t x0_4 = x_4;

    svuint64_t l1 = svmul_x(pg, *r1, *op1);
    svuint64_t l2 = svmul_x(pg, *r2, *op2);
    svuint64_t l3 = svmul_x(pg, *r3, *op3);
    svuint64_t l4 = svmul_x(pg, *r4, *op4);

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
    svuint64_t ls3 = svlsl_x(pg, l3, 32);
    svuint64_t ls4 = svlsl_x(pg, l4, 32);

    svuint64_t a1 = svadd_x(pg, l1, ls1);
    svuint64_t a2 = svadd_x(pg, l2, ls2);
    svuint64_t a3 = svadd_x(pg, l3, ls3);
    svuint64_t a4 = svadd_x(pg, l4, ls4);

    svbool_t e1 = svcmplt(pg, a1, l1);
    svbool_t e2 = svcmplt(pg, a2, l2);
    svbool_t e3 = svcmplt(pg, a3, l3);
    svbool_t e4 = svcmplt(pg, a4, l4);

    svuint64_t as1 = svlsr_x(pg, a1, 32);
    svuint64_t as2 = svlsr_x(pg, a2, 32);
    svuint64_t as3 = svlsr_x(pg, a3, 32);
    svuint64_t as4 = svlsr_x(pg, a4, 32);

    svuint64_t b1 = svsub_x(pg, a1, as1);
    svuint64_t b2 = svsub_x(pg, a2, as2);
    svuint64_t b3 = svsub_x(pg, a3, as3);
    svuint64_t b4 = svsub_x(pg, a4, as4);

    b1 = svsub_m(e1, b1, 1);
    b2 = svsub_m(e2, b2, 1);
    b3 = svsub_m(e3, b3, 1);
    b4 = svsub_m(e4, b4, 1);

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
    svuint64_t h3 = svmulh_x(pg, *r3, *op3);
    svuint64_t h4 = svmulh_x(pg, *r4, *op4);

    svuint64_t tr1 = svsub_x(pg, h1, b1);
    svuint64_t tr2 = svsub_x(pg, h2, b2);
    svuint64_t tr3 = svsub_x(pg, h3, b3);
    svuint64_t tr4 = svsub_x(pg, h4, b4);

    svbool_t c1 = svcmplt_u64(pg, h1, b1);
    svbool_t c2 = svcmplt_u64(pg, h2, b2);
    svbool_t c3 = svcmplt_u64(pg, h3, b3);
    svbool_t c4 = svcmplt_u64(pg, h4, b4);

    *r1 = svsub_m(c1, tr1, (uint32_t) -1);
    *r2 = svsub_m(c2, tr2, (uint32_t) -1);
    *r3 = svsub_m(c3, tr3, (uint32_t) -1);
    *r4 = svsub_m(c4, tr4, (uint32_t) -1);

    uint32_t minus1_1 = 0 - c_1;
    uint32_t minus1_2 = 0 - c_2;
    uint32_t minus1_3 = 0 - c_3;
    uint32_t minus1_4 = 0 - c_4;

    r_tail[0] = r_1 - (uint64_t)minus1_1;
    r_tail[1] = r_2 - (uint64_t)minus1_2;
    r_tail[2] = r_3 - (uint64_t)minus1_3;
    r_tail[3] = r_4 - (uint64_t)minus1_4;
}

extern inline void sq_128(svbool_t pg, svuint64_t *a, svuint64_t *b, svuint64_t *c, svuint64_t *d, uint64_t *e) {
    mul_128(pg, a, a, b, b, c, c, d, d, e, e);
}

extern inline void apply_sbox_128(
    svbool_t pg,
    svuint64_t *state1,
    svuint64_t *state2,
    svuint64_t *state3,
    svuint64_t *state4,
    uint64_t *state_tail
) {
    COPY_128(x, *state1, *state2, *state3, *state4, state_tail);                // copy input to x
    SQUARE_128(pg, x);                                    // x contains input^2
    mul_128(pg, state1, &x_1, state2, &x_2, state3, &x_3, state4, &x_4, state_tail, x_tail); // state contains input^3
    SQUARE_128(pg, x);                                    // x contains input^4
    mul_128(pg, state1, &x_1, state2, &x_2, state3, &x_3, state4, &x_4, state_tail, x_tail); // state contains input^7
}

extern inline void apply_inv_sbox_128(
    svbool_t pg,
    svuint64_t *state1,
    svuint64_t *state2,
    svuint64_t *state3,
    svuint64_t *state4,
    uint64_t *state_tail
) {
    // base^10
    COPY_128(t1, *state1, *state2, *state3, *state4, state_tail);
    SQUARE_128(pg, t1);

    // base^100
    SQUARE_DEST_128(pg, t2, t1);

    // base^100100
    POW_ACC_DEST(pg, t3, 3, t2, t2);

    // base^100100100100
    POW_ACC_DEST(pg, t4, 6, t3, t3);

    // compute base^100100100100100100100100
    POW_ACC_DEST(pg, t5, 12, t4, t4);

    // compute base^100100100100100100100100100100
    POW_ACC_DEST(pg, t6, 6, t5, t3);

    // compute base^1001001001001001001001001001000100100100100100100100100100100
    POW_ACC_DEST(pg, t7, 31, t6, t6);

    // compute base^1001001001001001001001001001000110110110110110110110110110110111
    SQUARE_128(pg, t7);
    MULTIPLY_128(pg, t7, t6);
    SQUARE_128(pg, t7);
    SQUARE_128(pg, t7);
    MULTIPLY_128(pg, t7, t1);
    MULTIPLY_128(pg, t7, t2);
    mul_128(pg, state1, &t7_1, state2, &t7_2, state3, &t7_3, state4, &t7_4, state_tail, t7_tail);
}

bool add_constants_and_apply_sbox_128(uint64_t state[STATE_WIDTH], uint64_t constants[STATE_WIDTH]) {
    const uint64_t vl = 2;   // number of u64 numbers in one 128 bit SVE vector
    svbool_t ptrue = svptrue_b64();

    svuint64_t state1 = svld1(ptrue, state + 0 * vl);
    svuint64_t state2 = svld1(ptrue, state + 1 * vl);
    svuint64_t state3 = svld1(ptrue, state + 2 * vl);
    svuint64_t state4 = svld1(ptrue, state + 3 * vl);

    svuint64_t const1 = svld1(ptrue, constants + 0 * vl);
    svuint64_t const2 = svld1(ptrue, constants + 1 * vl);
    svuint64_t const3 = svld1(ptrue, constants + 2 * vl);
    svuint64_t const4 = svld1(ptrue, constants + 3 * vl);

    add_constants_128(ptrue, &state1, &const1, &state2, &const2, &state3, &const3, &state4, &const4, state + 8, constants + 8);
    apply_sbox_128(ptrue, &state1, &state2, &state3, &state4, state + 8);

    svst1(ptrue, state + 0 * vl, state1);
    svst1(ptrue, state + 1 * vl, state2);
    svst1(ptrue, state + 2 * vl, state3);
    svst1(ptrue, state + 3 * vl, state4);

    return true;
}

bool add_constants_and_apply_inv_sbox_128(uint64_t state[STATE_WIDTH], uint64_t constants[STATE_WIDTH]) {
    const uint64_t vl = 2;   // number of u64 numbers in one 128 bit SVE vector
    svbool_t ptrue = svptrue_b64();

    svuint64_t state1 = svld1(ptrue, state + 0 * vl);
    svuint64_t state2 = svld1(ptrue, state + 1 * vl);
    svuint64_t state3 = svld1(ptrue, state + 2 * vl);
    svuint64_t state4 = svld1(ptrue, state + 3 * vl);

    svuint64_t const1 = svld1(ptrue, constants + 0 * vl);
    svuint64_t const2 = svld1(ptrue, constants + 1 * vl);
    svuint64_t const3 = svld1(ptrue, constants + 2 * vl);
    svuint64_t const4 = svld1(ptrue, constants + 3 * vl);

    add_constants_128(ptrue, &state1, &const1, &state2, &const2, &state3, &const3, &state4, &const4, state + 8, constants + 8);
    apply_inv_sbox_128(ptrue, &state1, &state2, &state3, &state4, state + 8);

    svst1(ptrue, state + 0 * vl, state1);
    svst1(ptrue, state + 1 * vl, state2);
    svst1(ptrue, state + 2 * vl, state3);
    svst1(ptrue, state + 3 * vl, state4);

    return true;
}

#endif //RPO_SVE_RPO_HASH_128_H
