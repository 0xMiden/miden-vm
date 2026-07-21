#include <metal_stdlib>
using namespace metal;

typedef uint64_t u64;
typedef uint32_t u32;
typedef int64_t i64;

constant u64 GL_P = 0xFFFFFFFF00000001ULL;
constant uint STATE_WIDTH = 12;
constant uint RATE = 8;
constant uint DIGEST_SIZE = 4;
constant uint RPO_NUM_ROUNDS = 7;

inline u64 gl_canon(u64 x) {
    return (x >= GL_P) ? (x - GL_P) : x;
}

inline u64 gl_add(u64 a, u64 b) {
    u64 r = a + b;
    if (r < a) {
        return r + 0xFFFFFFFFULL;
    }
    return (r >= GL_P) ? (r - GL_P) : r;
}

inline u64 gl_sub(u64 a, u64 b) {
    if (a >= b) return gl_canon(a - b);
    return a - b + GL_P;
}

struct u128 {
    u64 lo;
    u64 hi;
};

inline u128 mul_wide(u64 a, u64 b) {
    u64 a_lo = a & 0xFFFFFFFF;
    u64 a_hi = a >> 32;
    u64 b_lo = b & 0xFFFFFFFF;
    u64 b_hi = b >> 32;

    u64 p0 = a_lo * b_lo;
    u64 p1 = a_lo * b_hi;
    u64 p2 = a_hi * b_lo;
    u64 p3 = a_hi * b_hi;

    u64 mid_sum = p1 + p2;
    u64 mid_carry = (mid_sum < p1) ? 1ULL : 0;

    u64 lo = p0 + (mid_sum << 32);
    u64 lo_carry = (lo < p0) ? 1ULL : 0;
    u64 hi = p3 + (mid_sum >> 32) + (mid_carry << 32) + lo_carry;

    return {lo, hi};
}

inline u128 square_wide(u64 a) {
    u64 a_lo = a & 0xFFFFFFFF;
    u64 a_hi = a >> 32;

    u64 p0 = a_lo * a_lo;
    u64 p1 = a_lo * a_hi;
    u64 p3 = a_hi * a_hi;

    u64 mid_sum = p1 << 1;
    u64 mid_carry = p1 >> 63;

    u64 lo = p0 + (mid_sum << 32);
    u64 lo_carry = (lo < p0) ? 1ULL : 0;
    u64 hi = p3 + (mid_sum >> 32) + (mid_carry << 32) + lo_carry;

    return {lo, hi};
}

inline u64 gl_reduce(u64 lo, u64 hi) {
    u64 hi_hi = hi >> 32;
    u64 hi_lo = hi & 0xFFFFFFFF;

    u64 t0 = lo - hi_hi;
    bool borrow = lo < hi_hi;
    if (borrow) {
        t0 -= 0xFFFFFFFF;
    }

    u64 t1 = hi_lo * 0xFFFFFFFFULL;
    u64 r = t0 + t1;
    bool carry = (r < t0);

    if (carry || r >= GL_P) {
        r -= GL_P;
    }
    return r;
}

inline u64 gl_mul(u64 a, u64 b) {
    u128 prod = mul_wide(a, b);
    return gl_reduce(prod.lo, prod.hi);
}

inline u64 gl_square(u64 x) {
    u128 prod = square_wide(x);
    return gl_reduce(prod.lo, prod.hi);
}

inline u64 gl_exp7(u64 x) {
    u64 x2 = gl_square(x);
    u64 x3 = gl_mul(x2, x);
    u64 x4 = gl_square(x2);
    return gl_mul(x4, x3);
}

constant u64 RPO_ARK1[7][12] = {
    {5789762306288267392ULL,6522564764413701783ULL,17809893479458208203ULL,107145243989736508ULL,
     6388978042437517382ULL,15844067734406016715ULL,9975000513555218239ULL,3344984123768313364ULL,
     9959189626657347191ULL,12960773468763563665ULL,9602914297752488475ULL,16657542370200465908ULL},
    {12987190162843096997ULL,653957632802705281ULL,4441654670647621225ULL,4038207883745915761ULL,
     5613464648874830118ULL,13222989726778338773ULL,3037761201230264149ULL,16683759727265180203ULL,
     8337364536491240715ULL,3227397518293416448ULL,8110510111539674682ULL,2872078294163232137ULL},
    {18072785500942327487ULL,6200974112677013481ULL,17682092219085884187ULL,10599526828986756440ULL,
     975003873302957338ULL,8264241093196931281ULL,10065763900435475170ULL,2181131744534710197ULL,
     6317303992309418647ULL,1401440938888741532ULL,8884468225181997494ULL,13066900325715521532ULL},
    {5674685213610121970ULL,5759084860419474071ULL,13943282657648897737ULL,1352748651966375394ULL,
     17110913224029905221ULL,1003883795902368422ULL,4141870621881018291ULL,8121410972417424656ULL,
     14300518605864919529ULL,13712227150607670181ULL,17021852944633065291ULL,6252096473787587650ULL},
    {4887609836208846458ULL,3027115137917284492ULL,9595098600469470675ULL,10528569829048484079ULL,
     7864689113198939815ULL,17533723827845969040ULL,5781638039037710951ULL,17024078752430719006ULL,
     109659393484013511ULL,7158933660534805869ULL,2955076958026921730ULL,7433723648458773977ULL},
    {16308865189192447297ULL,11977192855656444890ULL,12532242556065780287ULL,14594890931430968898ULL,
     7291784239689209784ULL,5514718540551361949ULL,10025733853830934803ULL,7293794580341021693ULL,
     6728552937464861756ULL,6332385040983343262ULL,13277683694236792804ULL,2600778905124452676ULL},
    {7123075680859040534ULL,1034205548717903090ULL,7717824418247931797ULL,3019070937878604058ULL,
     11403792746066867460ULL,10280580802233112374ULL,337153209462421218ULL,13333398568519923717ULL,
     3596153696935337464ULL,8104208463525993784ULL,14345062289456085693ULL,17036731477169661256ULL},
};

constant u64 RPO_ARK2[7][12] = {
    {6077062762357204287ULL,15277620170502011191ULL,5358738125714196705ULL,14233283787297595718ULL,
     13792579614346651365ULL,11614812331536767105ULL,14871063686742261166ULL,10148237148793043499ULL,
     4457428952329675767ULL,15590786458219172475ULL,10063319113072092615ULL,14200078843431360086ULL},
    {6202948458916099932ULL,17690140365333231091ULL,3595001575307484651ULL,373995945117666487ULL,
     1235734395091296013ULL,14172757457833931602ULL,707573103686350224ULL,15453217512188187135ULL,
     219777875004506018ULL,17876696346199469008ULL,17731621626449383378ULL,2897136237748376248ULL},
    {8023374565629191455ULL,15013690343205953430ULL,4485500052507912973ULL,12489737547229155153ULL,
     9500452585969030576ULL,2054001340201038870ULL,12420704059284934186ULL,355990932618543755ULL,
     9071225051243523860ULL,12766199826003448536ULL,9045979173463556963ULL,12934431667190679898ULL},
    {18389244934624494276ULL,16731736864863925227ULL,4440209734760478192ULL,17208448209698888938ULL,
     8739495587021565984ULL,17000774922218161967ULL,13533282547195532087ULL,525402848358706231ULL,
     16987541523062161972ULL,5466806524462797102ULL,14512769585918244983ULL,10973956031244051118ULL},
    {6982293561042362913ULL,14065426295947720331ULL,16451845770444974180ULL,7139138592091306727ULL,
     9012006439959783127ULL,14619614108529063361ULL,1394813199588124371ULL,4635111139507788575ULL,
     16217473952264203365ULL,10782018226466330683ULL,6844229992533662050ULL,7446486531695178711ULL},
    {3736792340494631448ULL,577852220195055341ULL,6689998335515779805ULL,13886063479078013492ULL,
     14358505101923202168ULL,7744142531772274164ULL,16135070735728404443ULL,12290902521256031137ULL,
     12059913662657709804ULL,16456018495793751911ULL,4571485474751953524ULL,17200392109565783176ULL},
    {17130398059294018733ULL,519782857322261988ULL,9625384390925085478ULL,1664893052631119222ULL,
     7629576092524553570ULL,3485239601103661425ULL,9755891797164033838ULL,15218148195153269027ULL,
     16460604813734957368ULL,9643968136937729763ULL,3611348709641382851ULL,18256379591337759196ULL},
};

inline u64 rpo_exp_acc_3(u64 base, u64 tail) {
    u64 result = base;
    result = gl_square(result);
    result = gl_square(result);
    result = gl_square(result);
    return gl_mul(result, tail);
}

inline u64 rpo_exp_acc_6(u64 base, u64 tail) {
    u64 result = base;
    for (uint i = 0; i < 6; i++) result = gl_square(result);
    return gl_mul(result, tail);
}

inline u64 rpo_exp_acc_12(u64 base, u64 tail) {
    u64 result = base;
    for (uint i = 0; i < 12; i++) result = gl_square(result);
    return gl_mul(result, tail);
}

inline u64 rpo_exp_acc_31(u64 base, u64 tail) {
    u64 result = base;
    for (uint i = 0; i < 31; i++) result = gl_square(result);
    return gl_mul(result, tail);
}

inline u64 rpo_inv_sbox(u64 x) {
    // Same exponentiation chain as the CPU Rescue/RPO implementation.
    u64 t1 = gl_square(x);
    u64 t2 = gl_square(t1);
    u64 t3 = rpo_exp_acc_3(t2, t2);
    u64 t4 = rpo_exp_acc_6(t3, t3);
    u64 t5 = rpo_exp_acc_12(t4, t4);
    u64 t6 = rpo_exp_acc_6(t5, t3);
    u64 t7 = rpo_exp_acc_31(t6, t6);

    t7 = gl_square(t7);
    t7 = gl_mul(t7, t6);
    t7 = gl_square(t7);
    t7 = gl_square(t7);
    t7 = gl_mul(t7, t1);
    t7 = gl_mul(t7, t2);
    return gl_mul(t7, x);
}

inline void rpo_block2(
    i64 x0r, i64 x0i, i64 x1r, i64 x1i, i64 x2r, i64 x2i,
    thread i64 &z0r, thread i64 &z0i,
    thread i64 &z1r, thread i64 &z1i,
    thread i64 &z2r, thread i64 &z2i
) {
    i64 y0r = -1, y0i = 2;
    i64 y1r = -1, y1i = 1;
    i64 y2r = 4, y2i = 8;

    i64 x0s = x0r + x0i;
    i64 x1s = x1r + x1i;
    i64 x2s = x2r + x2i;
    i64 y0s = y0r + y0i;
    i64 y1s = y1r + y1i;
    i64 y2s = y2r + y2i;

    i64 m0r = x0r * y0r, m0i = x0i * y0i;
    i64 m1r = x1r * y2r, m1i = x1i * y2i;
    i64 m2r = x2r * y1r, m2i = x2i * y1i;
    z0r = (m0r - m0i) + (x1s * y2s - m1r - m1i) + (x2s * y1s - m2r - m2i);
    z0i = (x0s * y0s - m0r - m0i) + (-m1r + m1i) + (-m2r + m2i);

    m0r = x0r * y1r; m0i = x0i * y1i;
    m1r = x1r * y0r; m1i = x1i * y0i;
    m2r = x2r * y2r; m2i = x2i * y2i;
    z1r = (m0r - m0i) + (m1r - m1i) + (x2s * y2s - m2r - m2i);
    z1i = (x0s * y1s - m0r - m0i) + (x1s * y0s - m1r - m1i) + (-m2r + m2i);

    m0r = x0r * y2r; m0i = x0i * y2i;
    m1r = x1r * y1r; m1i = x1i * y1i;
    m2r = x2r * y0r; m2i = x2i * y0i;
    z2r = (m0r - m0i) + (m1r - m1i) + (m2r - m2i);
    z2i = (x0s * y2s - m0r - m0i) + (x1s * y1s - m1r - m1i) + (x2s * y0s - m2r - m2i);
}

inline void rpo_ifft4_store(i64 y0, i64 y1r, i64 y1i, i64 y2, thread i64 *out, uint a, uint b, uint c, uint d) {
    i64 z0 = y0 + y2;
    i64 z1 = y0 - y2;
    i64 z2 = y1r;
    i64 z3 = -y1i;
    out[a] = z0 + z2;
    out[b] = z1 + z3;
    out[c] = z0 - z2;
    out[d] = z1 - z3;
}

inline void rpo_mds_freq(thread u64 *x, thread i64 *out) {
    i64 s0 = (i64)x[0], s1 = (i64)x[1], s2 = (i64)x[2], s3 = (i64)x[3];
    i64 s4 = (i64)x[4], s5 = (i64)x[5], s6 = (i64)x[6], s7 = (i64)x[7];
    i64 s8 = (i64)x[8], s9 = (i64)x[9], s10 = (i64)x[10], s11 = (i64)x[11];

    i64 z0 = s0 + s6, z2 = s0 - s6, z1 = s3 + s9, z3 = s3 - s9;
    i64 u0 = z0 + z1, u1r = z2, u1i = -z3, u2 = z0 - z1;

    z0 = s1 + s7; z2 = s1 - s7; z1 = s4 + s10; z3 = s4 - s10;
    i64 u4 = z0 + z1, u5r = z2, u5i = -z3, u6 = z0 - z1;

    z0 = s2 + s8; z2 = s2 - s8; z1 = s5 + s11; z3 = s5 - s11;
    i64 u8 = z0 + z1, u9r = z2, u9i = -z3, u10 = z0 - z1;

    i64 v0 = u0 * 16 + u4 * 16 + u8 * 8;
    i64 v4 = u0 * 8 + u4 * 16 + u8 * 16;
    i64 v8 = u0 * 16 + u4 * 8 + u8 * 16;

    i64 v1r, v1i, v5r, v5i, v9r, v9i;
    rpo_block2(u1r, u1i, u5r, u5i, u9r, u9i, v1r, v1i, v5r, v5i, v9r, v9i);

    i64 v2 = -8 * u2 - u6 - u10;
    i64 v6 = u2 - 8 * u6 - u10;
    i64 v10 = u2 + u6 - 8 * u10;

    rpo_ifft4_store(v0, v1r, v1i, v2, out, 0, 3, 6, 9);
    rpo_ifft4_store(v4, v5r, v5i, v6, out, 1, 4, 7, 10);
    rpo_ifft4_store(v8, v9r, v9i, v10, out, 2, 5, 8, 11);
}

inline u64 rpo_mds_reduce(i64 lo_signed, i64 hi_signed) {
    u64 lo = (u64)lo_signed;
    u64 hi = (u64)hi_signed;
    u64 shifted = hi << 32;
    u64 s_lo = lo + shifted;
    u64 carry = (s_lo < lo) ? 1 : 0;
    u64 s_hi = (hi >> 32) + carry;
    u64 z = (s_hi << 32) - s_hi;
    u64 res = s_lo + z;
    bool over = res < s_lo;
    return res + (over ? 0xffffffffULL : 0ULL);
}

inline void rpo_mds(thread u64 *state) {
    u64 low[STATE_WIDTH];
    u64 high[STATE_WIDTH];
    for (uint i = 0; i < STATE_WIDTH; i++) {
        low[i] = state[i] & 0xffffffffULL;
        high[i] = state[i] >> 32;
    }

    i64 low_out[STATE_WIDTH];
    i64 high_out[STATE_WIDTH];
    rpo_mds_freq(low, low_out);
    rpo_mds_freq(high, high_out);

    for (uint i = 0; i < STATE_WIDTH; i++) {
        state[i] = rpo_mds_reduce(low_out[i], high_out[i]);
    }
}

inline void rpo_permute(thread u64 *state) {
    for (uint r = 0; r < RPO_NUM_ROUNDS; r++) {
        rpo_mds(state);
        for (uint i = 0; i < STATE_WIDTH; i++) state[i] = gl_add(state[i], RPO_ARK1[r][i]);
        for (uint i = 0; i < STATE_WIDTH; i++) state[i] = gl_exp7(state[i]);

        rpo_mds(state);
        for (uint i = 0; i < STATE_WIDTH; i++) state[i] = gl_add(state[i], RPO_ARK2[r][i]);
        for (uint i = 0; i < STATE_WIDTH; i++) state[i] = rpo_inv_sbox(state[i]);
    }
}

struct MatrixDesc {
    ulong offset;
    uint height;
    uint width;
    uint log_scaling;
    uint _pad;
};

inline uint reverse_bits_len(uint x, uint bits) {
    uint y = 0;
    for (uint i = 0; i < bits; i++) {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }
    return y;
}

kernel void rpo_lmcs_hash_leaves(
    const device u64 *data [[buffer(0)]],
    const device MatrixDesc *descs [[buffer(1)]],
    device u64 *digests [[buffer(2)]],
    constant uint *params [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    uint num_matrices = params[0];
    uint log_n = params[1];
    uint src = reverse_bits_len(tid, log_n);

    u64 state[STATE_WIDTH];
    for (uint i = 0; i < STATE_WIDTH; i++) state[i] = 0;

    for (uint m = 0; m < num_matrices; m++) {
        MatrixDesc desc = descs[m];
        uint row = src >> desc.log_scaling;
        ulong base = desc.offset + ((ulong)row) * ((ulong)desc.width);
        uint pos = 0;

        for (uint j = 0; j < desc.width; j++) {
            state[pos] = data[base + j];
            pos++;
            if (pos == RATE) {
                rpo_permute(state);
                pos = 0;
            }
        }

        if (pos != 0) {
            for (uint j = pos; j < RATE; j++) state[j] = 0;
            rpo_permute(state);
        }
    }

    uint out = tid * DIGEST_SIZE;
    for (uint i = 0; i < DIGEST_SIZE; i++) {
        digests[out + i] = state[i];
    }
}

kernel void rpo_lmcs_absorb_matrix(
    const device u64 *data [[buffer(0)]],
    const device MatrixDesc *descs [[buffer(1)]],
    device u64 *states [[buffer(2)]],
    constant uint *params [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    MatrixDesc desc = descs[params[0]];
    ulong base = desc.offset + ((ulong)tid) * ((ulong)desc.width);
    uint state_offset = tid * STATE_WIDTH;

    u64 state[STATE_WIDTH];
    for (uint i = 0; i < STATE_WIDTH; i++) {
        state[i] = states[state_offset + i];
    }

    uint pos = 0;
    for (uint j = 0; j < desc.width; j++) {
        state[pos] = data[base + j];
        pos++;
        if (pos == RATE) {
            rpo_permute(state);
            pos = 0;
        }
    }

    if (pos != 0) {
        for (uint j = pos; j < RATE; j++) state[j] = 0;
        rpo_permute(state);
    }

    for (uint i = 0; i < STATE_WIDTH; i++) {
        states[state_offset + i] = state[i];
    }
}

kernel void rpo_lmcs_absorb_matrix_expanded(
    const device u64 *data [[buffer(0)]],
    const device MatrixDesc *descs [[buffer(1)]],
    const device u64 *states_in [[buffer(2)]],
    device u64 *states_out [[buffer(3)]],
    constant uint *params [[buffer(4)]],
    uint tid [[thread_position_in_grid]]
) {
    uint matrix_idx = params[0];
    uint repeat_log = params[1];
    MatrixDesc desc = descs[matrix_idx];
    ulong base = desc.offset + ((ulong)tid) * ((ulong)desc.width);
    uint src_state_offset = (tid >> repeat_log) * STATE_WIDTH;
    uint dst_state_offset = tid * STATE_WIDTH;

    u64 state[STATE_WIDTH];
    for (uint i = 0; i < STATE_WIDTH; i++) {
        state[i] = states_in[src_state_offset + i];
    }

    uint pos = 0;
    for (uint j = 0; j < desc.width; j++) {
        state[pos] = data[base + j];
        pos++;
        if (pos == RATE) {
            rpo_permute(state);
            pos = 0;
        }
    }

    if (pos != 0) {
        for (uint j = pos; j < RATE; j++) state[j] = 0;
        rpo_permute(state);
    }

    for (uint i = 0; i < STATE_WIDTH; i++) {
        states_out[dst_state_offset + i] = state[i];
    }
}

kernel void rpo_lmcs_squeeze_leaves(
    const device u64 *states [[buffer(0)]],
    device u64 *digests [[buffer(1)]],
    constant uint *params [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    uint log_n = params[0];
    uint src = reverse_bits_len(tid, log_n);
    uint state_offset = src * STATE_WIDTH;
    uint out_offset = tid * DIGEST_SIZE;

    for (uint i = 0; i < DIGEST_SIZE; i++) {
        digests[out_offset + i] = states[state_offset + i];
    }
}

kernel void rpo_lmcs_compress_level(
    const device u64 *nodes_in [[buffer(0)]],
    device u64 *nodes_out [[buffer(1)]],
    uint tid [[thread_position_in_grid]]
) {
    uint left_offset = (2 * tid) * DIGEST_SIZE;
    uint right_offset = (2 * tid + 1) * DIGEST_SIZE;
    uint out_offset = tid * DIGEST_SIZE;

    u64 state[STATE_WIDTH];
    for (uint i = 0; i < DIGEST_SIZE; i++) state[i] = nodes_in[left_offset + i];
    for (uint i = 0; i < DIGEST_SIZE; i++) state[DIGEST_SIZE + i] = nodes_in[right_offset + i];
    for (uint i = RATE; i < STATE_WIDTH; i++) state[i] = 0;
    rpo_permute(state);

    for (uint i = 0; i < DIGEST_SIZE; i++) {
        nodes_out[out_offset + i] = state[i];
    }
}
