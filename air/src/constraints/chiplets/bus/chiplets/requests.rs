//! Request value computations for the chiplets bus.
//!
//! Each VM operation that communicates with a chiplet contributes a request message to the
//! chiplets bus. This module computes those message values, organized by operation group.

use core::array;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE, field::PrimeCharacteristicRing, operations::opcodes};

use super::{
    HASH_CYCLE_OFFSET, TRANSITION_LINEAR_HASH, TRANSITION_LINEAR_HASH_ABP, TRANSITION_MP_VERIFY,
    TRANSITION_MR_UPDATE_NEW, TRANSITION_MR_UPDATE_OLD, TRANSITION_RETURN_HASH,
    TRANSITION_RETURN_STATE,
};
use crate::{
    Felt, MainTraceRow, MidenAirBuilder,
    constraints::{constants::*, op_flags::OpFlags, utils::BoolNot},
    trace::{
        Challenges,
        bus_types::CHIPLETS_BUS,
        chiplets::{
            ace::ACE_INIT_LABEL,
            bitwise::{BITWISE_AND_LABEL, BITWISE_XOR_LABEL},
            kernel_rom::KERNEL_PROC_CALL_LABEL,
            memory::{
                MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL, MEMORY_WRITE_ELEMENT_LABEL,
                MEMORY_WRITE_WORD_LABEL,
            },
        },
        log_precompile::{
            HELPER_ADDR_IDX, HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE, STACK_COMM_RANGE,
            STACK_R0_RANGE, STACK_R1_RANGE, STACK_TAG_RANGE,
        },
    },
};

// HASHER MESSAGE ENCODING
// ================================================================================================

/// Encodes a hasher message with a full 12-lane sponge state.
///
/// Format: alpha + beta^0 * label + beta^1 * addr + beta^2 * node_index
///         + sum(beta^(3+i) * state[i]) for i in 0..12
pub(super) fn encode_hasher_state<AB: MidenAirBuilder>(
    challenges: &Challenges<AB::ExprEF>,
    label: AB::Expr,
    addr: AB::Expr,
    node_index: AB::Expr,
    state: [AB::Expr; 12],
) -> AB::ExprEF {
    let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11] = state;
    challenges.encode(
        CHIPLETS_BUS,
        [label, addr, node_index, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11],
    )
}

/// Encodes a hasher message with a 4-lane word (digest or leaf).
pub(super) fn encode_hasher_word<AB: MidenAirBuilder>(
    challenges: &Challenges<AB::ExprEF>,
    label: AB::Expr,
    addr: AB::Expr,
    node_index: AB::Expr,
    word: [AB::Expr; 4],
) -> AB::ExprEF {
    let [w0, w1, w2, w3] = word;
    challenges.encode(CHIPLETS_BUS, [label, addr, node_index, w0, w1, w2, w3])
}

/// Encodes a hasher message with an 8-lane rate.
pub(super) fn encode_hasher_rate<AB: MidenAirBuilder>(
    challenges: &Challenges<AB::ExprEF>,
    label: AB::Expr,
    addr: AB::Expr,
    node_index: AB::Expr,
    rate: [AB::Expr; 8],
) -> AB::ExprEF {
    let [r0, r1, r2, r3, r4, r5, r6, r7] = rate;
    challenges.encode(CHIPLETS_BUS, [label, addr, node_index, r0, r1, r2, r3, r4, r5, r6, r7])
}

// FULL REQUEST MULTIPLIER
// ================================================================================================

/// Computes the full request multiplier for the chiplets bus.
///
/// Returns `sum(flag_i * value_i) + (1 - sum(flag_i))` where each `(flag_i, value_i)` pair
/// corresponds to a VM operation that sends a message to a chiplet.
pub fn compute_request_multiplier<AB>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF
where
    AB: MidenAirBuilder,
{
    // --- Hasher operations (stack ops → hasher chiplet) ---

    let f_hperm = op_flags.hperm();
    let v_hperm = compute_hperm_request::<AB>(local, next, challenges);

    let f_mpverify = op_flags.mpverify();
    let v_mpverify = compute_mpverify_request::<AB>(local, challenges);

    let f_mrupdate = op_flags.mrupdate();
    let v_mrupdate = compute_mrupdate_request::<AB>(local, next, challenges);

    // --- Control flow operations (decoder → hasher chiplet, sometimes + memory/kernel ROM) ---

    let f_join = op_flags.join();
    let v_join = compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Join);

    let f_split = op_flags.split();
    let v_split =
        compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Split);

    let f_loop = op_flags.loop_op();
    let v_loop = compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Loop);

    // CALL: control block request + FMP initialization write
    let f_call = op_flags.call();
    let v_call = {
        let control =
            compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Call);
        let fmp = compute_fmp_write_request::<AB>(local, next, challenges);
        control * fmp
    };

    // DYN: control block (zeros, callee is dynamic) + callee hash word read from stack[0]
    let f_dyn = op_flags.dyn_op();
    let v_dyn = {
        let control = compute_control_block_request_zeros::<AB>(next, challenges, opcodes::DYN);
        let callee = compute_dyn_callee_hash_read::<AB>(local, challenges);
        control * callee
    };

    // DYNCALL: control block (zeros) + callee hash read + FMP initialization write
    let f_dyncall = op_flags.dyncall();
    let v_dyncall = {
        let control = compute_control_block_request_zeros::<AB>(next, challenges, opcodes::DYNCALL);
        let callee = compute_dyn_callee_hash_read::<AB>(local, challenges);
        let fmp = compute_fmp_write_request::<AB>(local, next, challenges);
        control * callee * fmp
    };

    // SYSCALL: control block request + kernel ROM lookup (digest from decoder hasher state)
    let f_syscall = op_flags.syscall();
    let v_syscall = {
        let control =
            compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Syscall);
        let hs = local.decoder.hasher_state;
        let label: AB::Expr = KERNEL_PROC_CALL_LABEL.into();
        let kernel = challenges
            .encode(CHIPLETS_BUS, [label, hs[0].into(), hs[1].into(), hs[2].into(), hs[3].into()]);
        control * kernel
    };

    // SPAN: full 12-lane sponge state (hasher state as rate, capacity zeroed)
    let f_span = op_flags.span();
    let v_span = compute_span_request::<AB>(local, next, challenges);

    // RESPAN: 8-lane rate absorption
    let f_respan = op_flags.respan();
    let v_respan = compute_respan_request::<AB>(local, next, challenges);

    // END: 4-lane digest output
    let f_end = op_flags.end();
    let v_end = {
        let addr: AB::Expr = local.decoder.addr + HASH_CYCLE_OFFSET;
        let digest: [AB::Expr; 4] = array::from_fn(|i| local.decoder.hasher_state[i].into());
        encode_hasher_word::<AB>(
            challenges,
            TRANSITION_RETURN_HASH.into(),
            addr,
            AB::Expr::ZERO,
            digest,
        )
    };

    // --- Memory operations (stack ops → memory chiplet) ---

    let f_mload = op_flags.mload();
    let v_mload = compute_memory_element_request::<AB>(local, next, challenges, true);

    let f_mstore = op_flags.mstore();
    let v_mstore = compute_memory_element_request::<AB>(local, next, challenges, false);

    let f_mloadw = op_flags.mloadw();
    let v_mloadw = compute_memory_word_request::<AB>(local, next, challenges, true);

    let f_mstorew = op_flags.mstorew();
    let v_mstorew = compute_memory_word_request::<AB>(local, next, challenges, false);

    // HORNERBASE: two element reads (eval_point_0 and eval_point_1 from helpers)
    let f_hornerbase = op_flags.hornerbase();
    let v_hornerbase = {
        let label: AB::Expr = Felt::from_u8(MEMORY_READ_ELEMENT_LABEL).into();
        let ctx = local.system.ctx;
        let clk = local.system.clk;
        let addr = local.stack.top[13];
        let helpers = local.decoder.user_op_helpers();
        let msg0 = challenges.encode(
            CHIPLETS_BUS,
            [label.clone(), ctx.into(), addr.into(), clk.into(), helpers[0].into()],
        );
        let addr2: AB::Expr = addr.into();
        let msg1 = challenges
            .encode(CHIPLETS_BUS, [label, ctx.into(), addr2 + F_1, clk.into(), helpers[1].into()]);
        msg0 * msg1
    };

    // HORNEREXT: one word read (helpers 0..3)
    let f_hornerext = op_flags.hornerext();
    let v_hornerext = {
        let label: AB::Expr = Felt::from_u8(MEMORY_READ_WORD_LABEL).into();
        let ctx: AB::Expr = local.system.ctx.into();
        let clk: AB::Expr = local.system.clk.into();
        let addr: AB::Expr = local.stack.top[13].into();
        let helpers = local.decoder.user_op_helpers();
        challenges.encode(
            CHIPLETS_BUS,
            [
                label,
                ctx,
                addr,
                clk,
                helpers[0].into(),
                helpers[1].into(),
                helpers[2].into(),
                helpers[3].into(),
            ],
        )
    };

    let f_mstream = op_flags.mstream();
    let v_mstream = compute_two_word_request::<AB>(local, next, challenges, true);

    let f_pipe = op_flags.pipe();
    let v_pipe = compute_two_word_request::<AB>(local, next, challenges, false);

    let f_cryptostream = op_flags.cryptostream();
    let v_cryptostream = compute_cryptostream_request::<AB>(local, next, challenges);

    // --- Bitwise operations (stack ops → bitwise chiplet) ---

    let f_u32and = op_flags.u32and();
    let v_u32and = compute_bitwise_request::<AB>(local, next, challenges, false);

    let f_u32xor = op_flags.u32xor();
    let v_u32xor = compute_bitwise_request::<AB>(local, next, challenges, true);

    // --- ACE operation (stack op → ACE chiplet) ---

    let f_evalcircuit = op_flags.evalcircuit();
    let v_evalcircuit = {
        let label: AB::Expr = ACE_INIT_LABEL.into();
        let ctx: AB::Expr = local.system.ctx.into();
        let clk: AB::Expr = local.system.clk.into();
        let ptr: AB::Expr = local.stack.top[0].into();
        let num_read_rows: AB::Expr = local.stack.top[1].into();
        let num_eval_rows: AB::Expr = local.stack.top[2].into();
        challenges.encode(CHIPLETS_BUS, [label, clk, ctx, ptr, num_read_rows, num_eval_rows])
    };

    // --- Log precompile (stack op → hasher chiplet) ---

    let f_logprecompile = op_flags.log_precompile();
    let v_logprecompile = compute_log_precompile_request::<AB>(local, next, challenges);

    // --- Weighted sum ---

    let flag_sum = f_hperm.clone()
        + f_mpverify.clone()
        + f_mrupdate.clone()
        + f_join.clone()
        + f_split.clone()
        + f_loop.clone()
        + f_call.clone()
        + f_dyn.clone()
        + f_dyncall.clone()
        + f_syscall.clone()
        + f_span.clone()
        + f_respan.clone()
        + f_end.clone()
        + f_mload.clone()
        + f_mstore.clone()
        + f_mloadw.clone()
        + f_mstorew.clone()
        + f_hornerbase.clone()
        + f_hornerext.clone()
        + f_mstream.clone()
        + f_pipe.clone()
        + f_cryptostream.clone()
        + f_u32and.clone()
        + f_u32xor.clone()
        + f_evalcircuit.clone()
        + f_logprecompile.clone();

    v_hperm * f_hperm
        + v_mpverify * f_mpverify
        + v_mrupdate * f_mrupdate
        + v_join * f_join
        + v_split * f_split
        + v_loop * f_loop
        + v_call * f_call
        + v_dyn * f_dyn
        + v_dyncall * f_dyncall
        + v_syscall * f_syscall
        + v_span * f_span
        + v_respan * f_respan
        + v_end * f_end
        + v_mload * f_mload
        + v_mstore * f_mstore
        + v_mloadw * f_mloadw
        + v_mstorew * f_mstorew
        + v_hornerbase * f_hornerbase
        + v_hornerext * f_hornerext
        + v_mstream * f_mstream
        + v_pipe * f_pipe
        + v_cryptostream * f_cryptostream
        + v_u32and * f_u32and
        + v_u32xor * f_u32xor
        + v_evalcircuit * f_evalcircuit
        + v_logprecompile * f_logprecompile
        + flag_sum.not()
}

// BITWISE REQUESTS
// ================================================================================================

/// Computes the bitwise request message value (used for both U32AND and U32XOR).
///
/// Format: alpha + beta^0*label + beta^1*a + beta^2*b + beta^3*z
fn compute_bitwise_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    is_xor: bool,
) -> AB::ExprEF {
    let label: AB::Expr = if is_xor { BITWISE_XOR_LABEL } else { BITWISE_AND_LABEL }.into();
    let a: AB::Expr = local.stack.top[0].into();
    let b: AB::Expr = local.stack.top[1].into();
    let z: AB::Expr = next.stack.top[0].into();

    challenges.encode(CHIPLETS_BUS, [label, a, b, z])
}

// MEMORY REQUESTS
// ================================================================================================

/// Computes a memory word request (MLOADW / MSTOREW).
///
/// Format: alpha + beta^0*label + beta^1*ctx + beta^2*addr + beta^3*clk + beta^4..7 * word
fn compute_memory_word_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    is_read: bool,
) -> AB::ExprEF {
    let label = if is_read { MEMORY_READ_WORD_LABEL } else { MEMORY_WRITE_WORD_LABEL };
    let label: AB::Expr = Felt::from_u8(label).into();
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let addr: AB::Expr = local.stack.top[0].into();

    let [w0, w1, w2, w3]: [AB::Expr; 4] = if is_read {
        array::from_fn(|i| next.stack.top[i].into())
    } else {
        array::from_fn(|i| local.stack.top[1 + i].into())
    };

    challenges.encode(CHIPLETS_BUS, [label, ctx, addr, clk, w0, w1, w2, w3])
}

/// Computes a memory element request (MLOAD / MSTORE).
///
/// Format: alpha + beta^0*label + beta^1*ctx + beta^2*addr + beta^3*clk + beta^4*element
fn compute_memory_element_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    is_read: bool,
) -> AB::ExprEF {
    let label = if is_read { MEMORY_READ_ELEMENT_LABEL } else { MEMORY_WRITE_ELEMENT_LABEL };
    let label: AB::Expr = Felt::from_u8(label).into();
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let addr: AB::Expr = local.stack.top[0].into();
    let element: AB::Expr =
        if is_read { next.stack.top[0].into() } else { local.stack.top[1].into() };

    challenges.encode(CHIPLETS_BUS, [label, ctx, addr, clk, element])
}

/// Computes a two-word transfer request at `stack[12]` and `stack[12]+4` (MSTREAM / PIPE).
///
/// Both words come from `next.stack[0..8]`. The label determines read (MSTREAM) vs write (PIPE).
fn compute_two_word_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    is_read: bool,
) -> AB::ExprEF {
    let label = if is_read {
        MEMORY_READ_WORD_LABEL
    } else {
        MEMORY_WRITE_WORD_LABEL
    };
    let label: AB::Expr = Felt::from_u8(label).into();
    let ctx = local.system.ctx;
    let clk = local.system.clk;
    let addr = local.stack.top[12];

    let [w0, w1, w2, w3]: [AB::Expr; 4] = array::from_fn(|i| next.stack.top[i].into());
    let [w4, w5, w6, w7]: [AB::Expr; 4] = array::from_fn(|i| next.stack.top[4 + i].into());

    let msg1 = challenges.encode(
        CHIPLETS_BUS,
        [label.clone(), ctx.into(), addr.into(), clk.into(), w0, w1, w2, w3],
    );
    let addr2: AB::Expr = addr.into();
    let msg2 = challenges.encode(
        CHIPLETS_BUS,
        [label, ctx.into(), addr2 + F_4, clk.into(), w4, w5, w6, w7],
    );

    msg1 * msg2
}

/// Computes the CRYPTOSTREAM request value (two word reads + two word writes).
fn compute_cryptostream_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let read_label: AB::Expr = Felt::from_u8(MEMORY_READ_WORD_LABEL).into();
    let write_label: AB::Expr = Felt::from_u8(MEMORY_WRITE_WORD_LABEL).into();
    let ctx = local.system.ctx;
    let clk = local.system.clk;
    let src = local.stack.top[12];
    let dst = local.stack.top[13];

    let rate = &local.stack.top[..8];
    let cipher: [AB::Expr; 8] = array::from_fn(|i| next.stack.top[i].into());
    let [p0, p1, p2, p3, p4, p5, p6, p7]: [AB::Expr; 8] =
        array::from_fn(|i| cipher[i].clone() - rate[i]);
    let [c0, c1, c2, c3, c4, c5, c6, c7] = cipher;

    let read_msg1 = challenges.encode(
        CHIPLETS_BUS,
        [read_label.clone(), ctx.into(), src.into(), clk.into(), p0, p1, p2, p3],
    );
    let src2: AB::Expr = src.into();
    let read_msg2 = challenges
        .encode(CHIPLETS_BUS, [read_label, ctx.into(), src2 + F_4, clk.into(), p4, p5, p6, p7]);
    let write_msg1 = challenges.encode(
        CHIPLETS_BUS,
        [write_label.clone(), ctx.into(), dst.into(), clk.into(), c0, c1, c2, c3],
    );
    let dst2: AB::Expr = dst.into();
    let write_msg2 = challenges
        .encode(CHIPLETS_BUS, [write_label, ctx.into(), dst2 + F_4, clk.into(), c4, c5, c6, c7]);

    read_msg1 * read_msg2 * write_msg1 * write_msg2
}

// CONTROL BLOCK REQUESTS
// ================================================================================================

/// Control block operation types.
#[derive(Clone, Copy)]
enum ControlBlockOp {
    Join,
    Split,
    Loop,
    Call,
    Syscall,
}

impl ControlBlockOp {
    fn opcode(&self) -> u8 {
        match self {
            ControlBlockOp::Join => opcodes::JOIN,
            ControlBlockOp::Split => opcodes::SPLIT,
            ControlBlockOp::Loop => opcodes::LOOP,
            ControlBlockOp::Call => opcodes::CALL,
            ControlBlockOp::Syscall => opcodes::SYSCALL,
        }
    }
}

/// Computes the control block request for JOIN, SPLIT, LOOP, CALL, and SYSCALL.
///
/// 12-lane sponge: decoder hasher_state as rate + opcode in capacity domain position.
fn compute_control_block_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    op: ControlBlockOp,
) -> AB::ExprEF {
    let hs = local.decoder.hasher_state;
    let op_code: AB::Expr = Felt::from_u8(op.opcode()).into();
    let state: [AB::Expr; 12] = [
        hs[0].into(),
        hs[1].into(),
        hs[2].into(),
        hs[3].into(),
        hs[4].into(),
        hs[5].into(),
        hs[6].into(),
        hs[7].into(),
        AB::Expr::ZERO,
        op_code,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];
    encode_hasher_state::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        next.decoder.addr.into(),
        AB::Expr::ZERO,
        state,
    )
}

/// Computes control block request with zeros for hasher state (DYN/DYNCALL).
fn compute_control_block_request_zeros<AB: MidenAirBuilder>(
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    opcode: u8,
) -> AB::ExprEF {
    let op_code: AB::Expr = Felt::from_u8(opcode).into();
    let state: [AB::Expr; 12] = [
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        op_code,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];
    encode_hasher_state::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        next.decoder.addr.into(),
        AB::Expr::ZERO,
        state,
    )
}

/// SPAN: full 12-lane sponge state (hasher state as rate, capacity zeroed).
fn compute_span_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let hs = local.decoder.hasher_state;
    let state: [AB::Expr; 12] = [
        hs[0].into(),
        hs[1].into(),
        hs[2].into(),
        hs[3].into(),
        hs[4].into(),
        hs[5].into(),
        hs[6].into(),
        hs[7].into(),
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];
    encode_hasher_state::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        next.decoder.addr.into(),
        AB::Expr::ZERO,
        state,
    )
}

/// RESPAN: 8-lane rate absorption.
fn compute_respan_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let addr_for_msg = next.decoder.addr - F_1;
    let rate: [AB::Expr; 8] = array::from_fn(|i| local.decoder.hasher_state[i].into());
    encode_hasher_rate::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH_ABP.into(),
        addr_for_msg,
        AB::Expr::ZERO,
        rate,
    )
}

/// FMP initialization write request (used by CALL and DYNCALL).
fn compute_fmp_write_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let label: AB::Expr = Felt::from_u8(MEMORY_WRITE_ELEMENT_LABEL).into();
    let ctx: AB::Expr = next.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    challenges.encode(CHIPLETS_BUS, [label, ctx, FMP_ADDR.into(), clk, FMP_INIT_VALUE.into()])
}

/// Callee hash word read from stack[0] address (used by DYN and DYNCALL).
fn compute_dyn_callee_hash_read<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let label: AB::Expr = Felt::from_u8(MEMORY_READ_WORD_LABEL).into();
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let addr: AB::Expr = local.stack.top[0].into();
    let hs = local.decoder.hasher_state;
    challenges.encode(
        CHIPLETS_BUS,
        [label, ctx, addr, clk, hs[0].into(), hs[1].into(), hs[2].into(), hs[3].into()],
    )
}

// HASHER STACK OPERATION REQUESTS
// ================================================================================================

/// HPERM: input state from stack[0..12] + output state from next stack[0..12].
fn compute_hperm_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let addr = local.decoder.user_op_helpers()[0];
    let input_msg = encode_hasher_state::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        addr.into(),
        AB::Expr::ZERO,
        array::from_fn(|i| local.stack.top[i].into()),
    );
    let addr2: AB::Expr = addr.into();
    let output_msg = encode_hasher_state::<AB>(
        challenges,
        TRANSITION_RETURN_STATE.into(),
        addr2 + HASH_CYCLE_OFFSET,
        AB::Expr::ZERO,
        array::from_fn(|i| next.stack.top[i].into()),
    );
    input_msg * output_msg
}

/// MPVERIFY: input node value + output root verification.
fn compute_mpverify_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let helper_0 = local.decoder.user_op_helpers()[0];
    let node_depth = local.stack.top[4];
    let node_index = local.stack.top[5];

    let input_msg = encode_hasher_word::<AB>(
        challenges,
        TRANSITION_MP_VERIFY.into(),
        helper_0.into(),
        node_index.into(),
        array::from_fn(|i| local.stack.top[i].into()),
    );
    let output_addr = helper_0 + node_depth * HASH_CYCLE_LEN_FELT - F_1;
    let output_msg = encode_hasher_word::<AB>(
        challenges,
        TRANSITION_RETURN_HASH.into(),
        output_addr,
        AB::Expr::ZERO,
        array::from_fn(|i| local.stack.top[6 + i].into()),
    );
    input_msg * output_msg
}

/// MRUPDATE: four messages for old/new path input/output.
fn compute_mrupdate_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let helper_0 = local.decoder.user_op_helpers()[0];
    let depth = local.stack.top[4];
    let index = local.stack.top[5];

    let input_old = encode_hasher_word::<AB>(
        challenges,
        TRANSITION_MR_UPDATE_OLD.into(),
        helper_0.into(),
        index.into(),
        array::from_fn(|i| local.stack.top[i].into()),
    );
    let output_old_addr = helper_0 + depth * HASH_CYCLE_LEN_FELT - F_1;
    let return_hash_label: AB::Expr = TRANSITION_RETURN_HASH.into();
    let output_old = encode_hasher_word::<AB>(
        challenges,
        return_hash_label.clone(),
        output_old_addr,
        AB::Expr::ZERO,
        array::from_fn(|i| local.stack.top[6 + i].into()),
    );
    let input_new_addr = helper_0 + depth * HASH_CYCLE_LEN_FELT;
    let input_new = encode_hasher_word::<AB>(
        challenges,
        TRANSITION_MR_UPDATE_NEW.into(),
        input_new_addr,
        index.into(),
        array::from_fn(|i| local.stack.top[10 + i].into()),
    );
    let two_merkle_cycles = HASH_CYCLE_LEN_FELT + HASH_CYCLE_LEN_FELT;
    let output_new_addr = helper_0 + depth * two_merkle_cycles - F_1;
    let output_new = encode_hasher_word::<AB>(
        challenges,
        return_hash_label,
        output_new_addr,
        AB::Expr::ZERO,
        array::from_fn(|i| next.stack.top[i].into()),
    );

    input_old * output_old * input_new * output_new
}

/// LOG_PRECOMPILE: absorbs [COMM, TAG] with capacity CAP_PREV, returns [R0, R1, CAP_NEXT].
fn compute_log_precompile_request<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let helpers = local.decoder.user_op_helpers();
    let addr = helpers[HELPER_ADDR_IDX];
    let cap_prev = &helpers[HELPER_CAP_PREV_RANGE];
    let comm = &local.stack.top[STACK_COMM_RANGE];
    let tag = &local.stack.top[STACK_TAG_RANGE];

    let state_input: [AB::Expr; 12] = [
        comm[0].into(),
        comm[1].into(),
        comm[2].into(),
        comm[3].into(),
        tag[0].into(),
        tag[1].into(),
        tag[2].into(),
        tag[3].into(),
        cap_prev[0].into(),
        cap_prev[1].into(),
        cap_prev[2].into(),
        cap_prev[3].into(),
    ];

    let r0 = &next.stack.top[STACK_R0_RANGE];
    let r1 = &next.stack.top[STACK_R1_RANGE];
    let cap_next = &next.stack.top[STACK_CAP_NEXT_RANGE];
    let state_output: [AB::Expr; 12] = [
        r0[0].into(),
        r0[1].into(),
        r0[2].into(),
        r0[3].into(),
        r1[0].into(),
        r1[1].into(),
        r1[2].into(),
        r1[3].into(),
        cap_next[0].into(),
        cap_next[1].into(),
        cap_next[2].into(),
        cap_next[3].into(),
    ];

    let input_msg = encode_hasher_state::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        addr.into(),
        AB::Expr::ZERO,
        state_input,
    );
    let addr2: AB::Expr = addr.into();
    let output_msg = encode_hasher_state::<AB>(
        challenges,
        TRANSITION_RETURN_STATE.into(),
        addr2 + HASH_CYCLE_OFFSET,
        AB::Expr::ZERO,
        state_output,
    );
    input_msg * output_msg
}
