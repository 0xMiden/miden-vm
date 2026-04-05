//! Chiplets bus constraint (b_chiplets).
//!
//! This module enforces the running product constraint for the main chiplets bus.
//! The chiplets bus handles communication between the VM components (stack, decoder)
//! and the specialized chiplets (hasher, bitwise, memory, ACE, kernel ROM).
//!
//! ## Running Product Protocol
//!
//! The bus accumulator uses a multiset running product:
//! - Boundary: b_chiplets[0] = 1, b_chiplets[last] = reduced_kernel_digests (via aux_finals)
//! - Transition: b_chiplets' * requests = b_chiplets * responses

use core::{array, borrow::Borrow};

use miden_core::{FMP_ADDR, FMP_INIT_VALUE, field::PrimeCharacteristicRing, operations::opcodes};
use miden_crypto::stark::air::{ExtensionBuilder, WindowAccess};

use crate::{
    Felt, MainCols, MidenAirBuilder,
    constraints::{
        bus::indices::B_CHIPLETS,
        chiplets::{columns::PeriodicCols, selectors::ChipletSelectors},
        constants::*,
        op_flags::OpFlags,
        utils::BoolNot,
    },
    trace::{
        Challenges,
        bus_types::CHIPLETS_BUS,
        chiplets::{
            ace::ACE_INIT_LABEL,
            bitwise::{BITWISE_AND_LABEL, BITWISE_XOR_LABEL},
            hasher::{
                HASH_CYCLE_LEN, LINEAR_HASH_LABEL, MP_VERIFY_LABEL, MR_UPDATE_NEW_LABEL,
                MR_UPDATE_OLD_LABEL, RETURN_HASH_LABEL, RETURN_STATE_LABEL,
            },
            kernel_rom::{KERNEL_PROC_CALL_LABEL, KERNEL_PROC_INIT_LABEL},
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

// LABEL CONSTANTS
// ================================================================================================

/// Transition label for linear hash init / control block requests.
const TRANSITION_LINEAR_HASH: Felt = Felt::new(LINEAR_HASH_LABEL as u64 + 16);
/// Transition label for absorb (respan).
const TRANSITION_LINEAR_HASH_ABP: Felt = Felt::new(LINEAR_HASH_LABEL as u64 + 32);
/// Transition label for Merkle path verification input.
const TRANSITION_MP_VERIFY: Felt = Felt::new(MP_VERIFY_LABEL as u64 + 16);
/// Transition label for Merkle root update (old path) input.
const TRANSITION_MR_UPDATE_OLD: Felt = Felt::new(MR_UPDATE_OLD_LABEL as u64 + 16);
/// Transition label for Merkle root update (new path) input.
const TRANSITION_MR_UPDATE_NEW: Felt = Felt::new(MR_UPDATE_NEW_LABEL as u64 + 16);
/// Transition label for return hash output.
const TRANSITION_RETURN_HASH: Felt = Felt::new(RETURN_HASH_LABEL as u64 + 32);
/// Transition label for return state output.
const TRANSITION_RETURN_STATE: Felt = Felt::new(RETURN_STATE_LABEL as u64 + 32);
/// Hasher cycle offset (HASH_CYCLE_LEN - 1 = 31).
const HASH_CYCLE_OFFSET: Felt = Felt::new((HASH_CYCLE_LEN - 1) as u64);

// ENTRY POINT
// ================================================================================================

/// Enforces the chiplets bus constraint: `b_chiplets' * requests = b_chiplets * responses`.
pub fn enforce_chiplets_bus_constraint<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    challenges: &Challenges<AB::ExprEF>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let (b_local_val, b_next_val) = {
        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();
        (aux_local[B_CHIPLETS], aux_next[B_CHIPLETS])
    };

    let requests = compute_request_multiplier::<AB>(local, next, op_flags, challenges);
    let responses = compute_response_multiplier::<AB>(builder, local, next, challenges, selectors);

    let lhs: AB::ExprEF = Into::<AB::ExprEF>::into(b_next_val) * requests;
    let rhs: AB::ExprEF = Into::<AB::ExprEF>::into(b_local_val) * responses;
    builder.when_transition().assert_eq_ext(lhs, rhs);
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use crate::{
        Felt,
        trace::chiplets::{
            ace::ACE_INIT_LABEL,
            bitwise::{BITWISE_AND_LABEL, BITWISE_XOR_LABEL},
            kernel_rom::{KERNEL_PROC_CALL_LABEL, KERNEL_PROC_INIT_LABEL},
            memory::{
                MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL, MEMORY_WRITE_ELEMENT_LABEL,
                MEMORY_WRITE_WORD_LABEL,
            },
        },
    };

    #[test]
    fn test_operation_labels() {
        assert_eq!(BITWISE_AND_LABEL, Felt::new(2));
        assert_eq!(BITWISE_XOR_LABEL, Felt::new(6));
        assert_eq!(MEMORY_WRITE_ELEMENT_LABEL, 4);
        assert_eq!(MEMORY_READ_ELEMENT_LABEL, 12);
        assert_eq!(MEMORY_WRITE_WORD_LABEL, 20);
        assert_eq!(MEMORY_READ_WORD_LABEL, 28);
    }

    #[test]
    fn test_memory_label_formula() {
        fn label(is_read: u64, is_word: u64) -> u64 {
            4 + 8 * is_read + 16 * is_word
        }
        assert_eq!(label(0, 0), MEMORY_WRITE_ELEMENT_LABEL as u64);
        assert_eq!(label(1, 0), MEMORY_READ_ELEMENT_LABEL as u64);
        assert_eq!(label(0, 1), MEMORY_WRITE_WORD_LABEL as u64);
        assert_eq!(label(1, 1), MEMORY_READ_WORD_LABEL as u64);
    }

    #[test]
    fn test_ace_label() {
        assert_eq!(ACE_INIT_LABEL, Felt::new(8));
    }

    #[test]
    fn test_kernel_rom_labels() {
        assert_eq!(KERNEL_PROC_CALL_LABEL, Felt::new(16));
        assert_eq!(KERNEL_PROC_INIT_LABEL, Felt::new(48));
    }
}

// HASHER MESSAGE HELPERS
// ================================================================================================

/// Encodes a hasher message with a full 12-lane sponge state.
///
/// Format: alpha + beta^0 * label + beta^1 * addr + beta^2 * node_index
///         + sum(beta^(3+i) * state[i]) for i in 0..12
fn compute_hasher_message<AB: MidenAirBuilder>(
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
fn compute_hasher_word_message<AB: MidenAirBuilder>(
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
fn compute_hasher_rate_message<AB: MidenAirBuilder>(
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
fn compute_request_multiplier<AB>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
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

    let f_call = op_flags.call();
    let v_call = compute_call_request::<AB>(local, next, challenges);

    let f_dyn = op_flags.dyn_op();
    let v_dyn = compute_dyn_request::<AB>(local, next, challenges);

    let f_dyncall = op_flags.dyncall();
    let v_dyncall = compute_dyncall_request::<AB>(local, next, challenges);

    let f_syscall = op_flags.syscall();
    let v_syscall = compute_syscall_request::<AB>(local, next, challenges);

    // SPAN: full 12-lane sponge state (hasher state as rate, capacity zeroed)
    let f_span = op_flags.span();
    let v_span = compute_span_request::<AB>(local, next, challenges);

    // RESPAN: 8-lane rate absorption
    let f_respan = op_flags.respan();
    let v_respan = compute_respan_request::<AB>(local, next, challenges);

    let f_end = op_flags.end();
    let v_end = compute_end_request::<AB>(local, challenges);

    // --- Memory operations (stack ops → memory chiplet) ---

    let f_mload = op_flags.mload();
    let v_mload = compute_memory_element_request::<AB>(local, next, challenges, true);

    let f_mstore = op_flags.mstore();
    let v_mstore = compute_memory_element_request::<AB>(local, next, challenges, false);

    let f_mloadw = op_flags.mloadw();
    let v_mloadw = compute_memory_word_request::<AB>(local, next, challenges, true);

    let f_mstorew = op_flags.mstorew();
    let v_mstorew = compute_memory_word_request::<AB>(local, next, challenges, false);

    let f_hornerbase = op_flags.hornerbase();
    let v_hornerbase = compute_hornerbase_request::<AB>(local, challenges);

    let f_hornerext = op_flags.hornerext();
    let v_hornerext = compute_hornerext_request::<AB>(local, challenges);

    let f_mstream = op_flags.mstream();
    let v_mstream = compute_mstream_request::<AB>(local, next, challenges);

    let f_pipe = op_flags.pipe();
    let v_pipe = compute_pipe_request::<AB>(local, next, challenges);

    let f_cryptostream = op_flags.cryptostream();
    let v_cryptostream = compute_cryptostream_request::<AB>(local, next, challenges);

    // --- Bitwise operations (stack ops → bitwise chiplet) ---

    let f_u32and = op_flags.u32and();
    let v_u32and = compute_bitwise_request::<AB>(local, next, challenges, false);

    let f_u32xor = op_flags.u32xor();
    let v_u32xor = compute_bitwise_request::<AB>(local, next, challenges, true);

    // --- ACE operation (stack op → ACE chiplet) ---

    let f_evalcircuit = op_flags.evalcircuit();
    let v_evalcircuit = compute_ace_request::<AB>(local, challenges);

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

// BITWISE MESSAGE HELPERS
// ================================================================================================

/// Computes the bitwise request message value (used for both U32AND and U32XOR).
///
/// Format: alpha + beta^0*label + beta^1*a + beta^2*b + beta^3*z
fn compute_bitwise_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    is_xor: bool,
) -> AB::ExprEF {
    let label: AB::Expr = if is_xor { BITWISE_XOR_LABEL } else { BITWISE_AND_LABEL }.into();
    let a: AB::Expr = local.stack.top[0].into();
    let b: AB::Expr = local.stack.top[1].into();
    let z: AB::Expr = next.stack.top[0].into();

    challenges.encode(CHIPLETS_BUS, [label, a, b, z])
}

// MEMORY MESSAGE HELPERS
// ================================================================================================

/// Computes a memory word request (MLOADW / MSTOREW).
///
/// Format: alpha + beta^0*label + beta^1*ctx + beta^2*addr + beta^3*clk + beta^4..7 * word
fn compute_memory_word_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    is_read: bool,
) -> AB::ExprEF {
    let label = if is_read {
        MEMORY_READ_WORD_LABEL
    } else {
        MEMORY_WRITE_WORD_LABEL
    };
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
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    is_read: bool,
) -> AB::ExprEF {
    let label = if is_read {
        MEMORY_READ_ELEMENT_LABEL
    } else {
        MEMORY_WRITE_ELEMENT_LABEL
    };
    let label: AB::Expr = Felt::from_u8(label).into();
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let addr: AB::Expr = local.stack.top[0].into();
    let element: AB::Expr = if is_read {
        next.stack.top[0].into()
    } else {
        local.stack.top[1].into()
    };

    challenges.encode(CHIPLETS_BUS, [label, ctx, addr, clk, element])
}

/// Computes a two-word transfer request at `stack[12]` and `stack[12]+4` (MSTREAM / PIPE).
///
/// Both words come from `next.stack[0..8]`. The label determines read (MSTREAM) vs write (PIPE).
fn compute_two_word_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
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
    let msg2 = challenges
        .encode(CHIPLETS_BUS, [label, ctx.into(), addr2 + F_4, clk.into(), w4, w5, w6, w7]);

    msg1 * msg2
}

/// Computes the CRYPTOSTREAM request value (two word reads + two word writes).
fn compute_cryptostream_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
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

// CONTROL BLOCK REQUEST HELPERS
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
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
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
    compute_hasher_message::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        next.decoder.addr.into(),
        AB::Expr::ZERO,
        state,
    )
}

/// Computes control block request with zeros for hasher state (DYN/DYNCALL).
fn compute_control_block_request_zeros<AB: MidenAirBuilder>(
    next: &MainCols<AB::Var>,
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
    compute_hasher_message::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        next.decoder.addr.into(),
        AB::Expr::ZERO,
        state,
    )
}

/// SPAN: full 12-lane sponge state (hasher state as rate, capacity zeroed).
fn compute_span_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
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
    compute_hasher_message::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        next.decoder.addr.into(),
        AB::Expr::ZERO,
        state,
    )
}

/// RESPAN: 8-lane rate absorption.
fn compute_respan_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let addr_for_msg = next.decoder.addr - F_1;
    let rate: [AB::Expr; 8] = array::from_fn(|i| local.decoder.hasher_state[i].into());
    compute_hasher_rate_message::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH_ABP.into(),
        addr_for_msg,
        AB::Expr::ZERO,
        rate,
    )
}

/// FMP initialization write request (used by CALL and DYNCALL).
fn compute_fmp_write_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let label: AB::Expr = Felt::from_u8(MEMORY_WRITE_ELEMENT_LABEL).into();
    let ctx: AB::Expr = next.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    challenges.encode(CHIPLETS_BUS, [label, ctx, FMP_ADDR.into(), clk, FMP_INIT_VALUE.into()])
}

/// Callee hash word read from stack[0] address (used by DYN and DYNCALL).
fn compute_dyn_callee_hash_read<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
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

// HASHER STACK OPERATION REQUEST HELPERS (compute_hperm_request, compute_log_precompile_request)
// ================================================================================================

/// HPERM: input state from stack[0..12] + output state from next stack[0..12].
fn compute_hperm_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let addr = local.decoder.user_op_helpers()[0];
    let input_msg = compute_hasher_message::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        addr.into(),
        AB::Expr::ZERO,
        array::from_fn(|i| local.stack.top[i].into()),
    );
    let addr2: AB::Expr = addr.into();
    let output_msg = compute_hasher_message::<AB>(
        challenges,
        TRANSITION_RETURN_STATE.into(),
        addr2 + HASH_CYCLE_OFFSET,
        AB::Expr::ZERO,
        array::from_fn(|i| next.stack.top[i].into()),
    );
    input_msg * output_msg
}

// MPVERIFY/MRUPDATE REQUEST HELPERS
// ================================================================================================

/// MPVERIFY: input node value + output root verification.
fn compute_mpverify_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let helper_0 = local.decoder.user_op_helpers()[0];
    let node_depth = local.stack.top[4];
    let node_index = local.stack.top[5];

    let input_msg = compute_hasher_word_message::<AB>(
        challenges,
        TRANSITION_MP_VERIFY.into(),
        helper_0.into(),
        node_index.into(),
        array::from_fn(|i| local.stack.top[i].into()),
    );
    let output_addr = helper_0 + node_depth * HASH_CYCLE_LEN_FELT - F_1;
    let output_msg = compute_hasher_word_message::<AB>(
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
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let helper_0 = local.decoder.user_op_helpers()[0];
    let depth = local.stack.top[4];
    let index = local.stack.top[5];

    let input_old = compute_hasher_word_message::<AB>(
        challenges,
        TRANSITION_MR_UPDATE_OLD.into(),
        helper_0.into(),
        index.into(),
        array::from_fn(|i| local.stack.top[i].into()),
    );
    let output_old_addr = helper_0 + depth * HASH_CYCLE_LEN_FELT - F_1;
    let return_hash_label: AB::Expr = TRANSITION_RETURN_HASH.into();
    let output_old = compute_hasher_word_message::<AB>(
        challenges,
        return_hash_label.clone(),
        output_old_addr,
        AB::Expr::ZERO,
        array::from_fn(|i| local.stack.top[6 + i].into()),
    );
    let input_new_addr = helper_0 + depth * HASH_CYCLE_LEN_FELT;
    let input_new = compute_hasher_word_message::<AB>(
        challenges,
        TRANSITION_MR_UPDATE_NEW.into(),
        input_new_addr,
        index.into(),
        array::from_fn(|i| local.stack.top[10 + i].into()),
    );
    let two_merkle_cycles = HASH_CYCLE_LEN_FELT + HASH_CYCLE_LEN_FELT;
    let output_new_addr = helper_0 + depth * two_merkle_cycles - F_1;
    let output_new = compute_hasher_word_message::<AB>(
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
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
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

    let input_msg = compute_hasher_message::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        addr.into(),
        AB::Expr::ZERO,
        state_input,
    );
    let addr2: AB::Expr = addr.into();
    let output_msg = compute_hasher_message::<AB>(
        challenges,
        TRANSITION_RETURN_STATE.into(),
        addr2 + HASH_CYCLE_OFFSET,
        AB::Expr::ZERO,
        state_output,
    );
    input_msg * output_msg
}

// FULL RESPONSE MULTIPLIER
// ================================================================================================

/// Computes the full response multiplier for the chiplets bus.
///
/// Returns `sum(flag_i * value_i) + (1 - sum(flag_i))` where each `(flag_i, value_i)` pair
/// corresponds to a chiplet row that sends a response message.
fn compute_response_multiplier<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    selectors: &ChipletSelectors<AB::Expr>,
) -> AB::ExprEF
where
    AB: MidenAirBuilder,
{
    // --- Periodic columns for hasher cycle detection and bitwise gating ---
    let periodic: &PeriodicCols<_> = builder.periodic_values().borrow();
    let cycle_row_0 = periodic.hasher.cycle_row_0.into();
    let cycle_row_31 = periodic.hasher.cycle_row_31.into();
    let k_transition = periodic.bitwise.k_transition.into();

    // --- Response flags ---
    let is_bitwise_responding: AB::Expr = selectors.bitwise.is_active.clone() * k_transition.not();
    let is_memory: AB::Expr = selectors.memory.is_active.clone();
    let ace_start: AB::Expr = local.ace().s_start.into();
    let is_ace: AB::Expr = selectors.ace.is_active.clone() * ace_start;
    let is_kernel_rom: AB::Expr = selectors.kernel_rom.is_active.clone();

    // --- Response values ---
    let hasher_response = compute_hasher_response::<AB>(
        local,
        next,
        challenges,
        selectors,
        cycle_row_0,
        cycle_row_31,
    );

    let v_bitwise = compute_bitwise_response::<AB>(local, challenges);

    // Memory response
    let v_memory = compute_memory_response::<AB>(local, challenges);

    let v_ace = compute_ace_response::<AB>(local, challenges);

    let v_kernel_rom = compute_kernel_rom_response::<AB>(local, challenges);

    // --- Weighted sum ---
    hasher_response.sum
        + v_bitwise * is_bitwise_responding.clone()
        + v_memory * is_memory.clone()
        + v_ace * is_ace.clone()
        + v_kernel_rom * is_kernel_rom.clone()
        + (AB::ExprEF::ONE
            - hasher_response.flag_sum
            - is_bitwise_responding
            - is_memory
            - is_ace
            - is_kernel_rom)
}

// HASHER RESPONSE HELPERS
// ================================================================================================

/// Hasher response contribution to the chiplets bus.
struct HasherResponse<EF, E> {
    sum: EF,
    flag_sum: E,
}

/// Computes the hasher chiplet response.
///
/// The hasher responds at two cycle positions:
/// - Row 0: Initialization (f_bp, f_mp, f_mv, f_mu)
/// - Row 31: Output/Absorption (f_hout, f_sout, f_abp)
fn compute_hasher_response<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    selectors: &ChipletSelectors<AB::Expr>,
    cycle_row_0: AB::Expr,
    cycle_row_31: AB::Expr,
) -> HasherResponse<AB::ExprEF, AB::Expr> {
    let h = local.hasher();
    let h_next = next.hasher();
    let hasher_active = selectors.hasher.is_active.clone();

    let [hs0, hs1, hs2] = h.selectors;
    let not_hs0 = hs0.into().not();
    let not_hs1 = hs1.into().not();
    let not_hs2 = hs2.into().not();

    // Row 0 flags
    let f_bp =
        hasher_active.clone() * cycle_row_0.clone() * hs0 * not_hs1.clone() * not_hs2.clone();
    let f_mp = hasher_active.clone() * cycle_row_0.clone() * hs0 * not_hs1.clone() * hs2;
    let f_mv = hasher_active.clone() * cycle_row_0.clone() * hs0 * hs1 * not_hs2.clone();
    let f_mu = hasher_active.clone() * cycle_row_0.clone() * hs0 * hs1 * hs2;

    // Row 31 flags
    let f_hout = hasher_active.clone()
        * cycle_row_31.clone()
        * not_hs0.clone()
        * not_hs1.clone()
        * not_hs2.clone();
    let f_sout =
        hasher_active.clone() * cycle_row_31.clone() * not_hs0.clone() * not_hs1.clone() * hs2;
    let f_abp =
        hasher_active.clone() * cycle_row_31.clone() * hs0 * not_hs1.clone() * not_hs2.clone();

    // Node index and addr
    let node_index = h.node_index;
    let node_index_next = h_next.node_index;
    let addr_next: AB::Expr = local.system.clk + AB::Expr::ONE;

    // v_bp: Full state message (linear hash / 2-to-1 hash init)
    let v_bp = compute_hasher_message::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        addr_next.clone(),
        node_index.into(),
        h.state.map(Into::into),
    );

    // v_sout: Full state message (return full state)
    let v_sout = compute_hasher_message::<AB>(
        challenges,
        TRANSITION_RETURN_STATE.into(),
        addr_next.clone(),
        node_index.into(),
        h.state.map(Into::into),
    );

    // Leaf node message (for f_mp, f_mv, f_mu)
    // bit = node_index - 2 * node_index_next selects RATE0 (bit=0) or RATE1 (bit=1)
    let bit = node_index - node_index_next * F_2;
    let not_bit = bit.not();
    let leaf_word: [AB::Expr; 4] = [
        not_bit.clone() * h.state[0] + bit.clone() * h.state[4],
        not_bit.clone() * h.state[1] + bit.clone() * h.state[5],
        not_bit.clone() * h.state[2] + bit.clone() * h.state[6],
        not_bit * h.state[3] + bit.clone() * h.state[7],
    ];
    let v_mp = compute_hasher_word_message::<AB>(
        challenges,
        TRANSITION_MP_VERIFY.into(),
        addr_next.clone(),
        node_index.into(),
        leaf_word.clone(),
    );
    let v_mv = compute_hasher_word_message::<AB>(
        challenges,
        TRANSITION_MR_UPDATE_OLD.into(),
        addr_next.clone(),
        node_index.into(),
        leaf_word.clone(),
    );
    let v_mu = compute_hasher_word_message::<AB>(
        challenges,
        TRANSITION_MR_UPDATE_NEW.into(),
        addr_next.clone(),
        node_index.into(),
        leaf_word,
    );

    // v_hout: Hash output (digest from RATE0)
    let v_hout = compute_hasher_word_message::<AB>(
        challenges,
        TRANSITION_RETURN_HASH.into(),
        addr_next.clone(),
        node_index.into(),
        array::from_fn(|i| h.state[i].into()),
    );

    // v_abp: Absorption (next row's rate)
    let v_abp = compute_hasher_rate_message::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH_ABP.into(),
        addr_next.clone(),
        node_index.into(),
        array::from_fn(|i| h_next.state[i].into()),
    );

    let flag_sum = f_bp.clone()
        + f_mp.clone()
        + f_mv.clone()
        + f_mu.clone()
        + f_hout.clone()
        + f_sout.clone()
        + f_abp.clone();

    let sum = v_bp * f_bp
        + v_mp * f_mp
        + v_mv * f_mv
        + v_mu * f_mu
        + v_hout * f_hout
        + v_sout * f_sout
        + v_abp * f_abp;

    HasherResponse { sum, flag_sum }
}

// MEMORY RESPONSE HELPERS
// ================================================================================================

/// Computes the memory chiplet response.
///
/// The memory chiplet uses different labels for read/write and element/word operations.
/// For element access, the correct element is selected based on idx0, idx1.
fn compute_memory_response<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let mem = local.memory();

    let is_read: AB::Expr = mem.is_read.into();
    let is_word: AB::Expr = mem.is_word.into();
    let idx0: AB::Expr = mem.idx0.into();
    let idx1: AB::Expr = mem.idx1.into();

    // addr = word + idx1 * 2 + idx0
    let word_addr: AB::Expr = mem.word_addr.into();
    let addr: AB::Expr = word_addr + idx1.clone() * F_2 + idx0.clone();

    let is_element = is_word.not();
    let is_write = is_read.not();

    // label = is_write * (is_element * WRITE_ELEMENT + is_word * WRITE_WORD)
    //       + is_read  * (is_element * READ_ELEMENT  + is_word * READ_WORD)
    let write_element_label: AB::Expr = Felt::from_u8(MEMORY_WRITE_ELEMENT_LABEL).into();
    let write_word_label: AB::Expr = Felt::from_u8(MEMORY_WRITE_WORD_LABEL).into();
    let read_element_label: AB::Expr = Felt::from_u8(MEMORY_READ_ELEMENT_LABEL).into();
    let read_word_label: AB::Expr = Felt::from_u8(MEMORY_READ_WORD_LABEL).into();
    let write_label = is_element.clone() * write_element_label + is_word.clone() * write_word_label;
    let read_label = is_element.clone() * read_element_label + is_word.clone() * read_word_label;
    let label = is_write * write_label + is_read * read_label;

    let v0: AB::Expr = mem.values[0].into();
    let v1: AB::Expr = mem.values[1].into();
    let v2: AB::Expr = mem.values[2].into();
    let v3: AB::Expr = mem.values[3].into();

    // Element selection: (0,0)→v0, (1,0)→v1, (0,1)→v2, (1,1)→v3
    let not_idx0 = idx0.not();
    let not_idx1 = idx1.not();
    let element: AB::Expr = v0.clone() * not_idx0.clone() * not_idx1.clone()
        + v1.clone() * idx0.clone() * not_idx1
        + v2.clone() * not_idx0 * idx1.clone()
        + v3.clone() * idx0.clone() * idx1.clone();

    let element_msg = challenges.encode(
        CHIPLETS_BUS,
        [label.clone(), mem.ctx.into(), addr.clone(), mem.clk.into(), element],
    );
    let word_msg = challenges
        .encode(CHIPLETS_BUS, [label, mem.ctx.into(), addr, mem.clk.into(), v0, v1, v2, v3]);

    element_msg * is_element + word_msg * is_word
}

// ACE MESSAGE HELPERS
// ================================================================================================

fn compute_ace_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let label: AB::Expr = ACE_INIT_LABEL.into();
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let ptr: AB::Expr = local.stack.top[0].into();
    let num_read_rows: AB::Expr = local.stack.top[1].into();
    let num_eval_rows: AB::Expr = local.stack.top[2].into();
    challenges.encode(CHIPLETS_BUS, [label, clk, ctx, ptr, num_read_rows, num_eval_rows])
}

fn compute_ace_response<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let ace = local.ace();
    let label: AB::Expr = ACE_INIT_LABEL.into();
    let clk: AB::Expr = ace.clk.into();
    let ctx: AB::Expr = ace.ctx.into();
    let ptr: AB::Expr = ace.ptr.into();
    let num_eval_rows: AB::Expr = ace.read().num_eval + F_1;
    let num_read_rows: AB::Expr = ace.id_0 + F_1 - num_eval_rows.clone();
    challenges.encode(CHIPLETS_BUS, [label, clk, ctx, ptr, num_read_rows, num_eval_rows])
}

// KERNEL ROM MESSAGE HELPERS
// ================================================================================================

fn compute_kernel_rom_response<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let krom = local.kernel_rom();
    let s_first = krom.s_first;
    let init_label: AB::Expr = KERNEL_PROC_INIT_LABEL.into();
    let call_label: AB::Expr = KERNEL_PROC_CALL_LABEL.into();
    let label: AB::Expr = s_first * init_label + s_first.into().not() * call_label;
    challenges.encode(
        CHIPLETS_BUS,
        [
            label,
            krom.root[0].into(),
            krom.root[1].into(),
            krom.root[2].into(),
            krom.root[3].into(),
        ],
    )
}

fn compute_bitwise_response<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let bw = local.bitwise();
    let sel: AB::Expr = bw.op_flag.into();
    let label = sel.not() * BITWISE_AND_LABEL + sel.clone() * BITWISE_XOR_LABEL;
    let a: AB::Expr = bw.a.into();
    let b: AB::Expr = bw.b.into();
    let z: AB::Expr = bw.output.into();
    challenges.encode(CHIPLETS_BUS, [label, a, b, z])
}

fn compute_call_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let control =
        compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Call);
    let fmp = compute_fmp_write_request::<AB>(local, next, challenges);
    control * fmp
}

fn compute_dyn_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let control = compute_control_block_request_zeros::<AB>(next, challenges, opcodes::DYN);
    let callee = compute_dyn_callee_hash_read::<AB>(local, challenges);
    control * callee
}

fn compute_dyncall_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let control = compute_control_block_request_zeros::<AB>(next, challenges, opcodes::DYNCALL);
    let callee = compute_dyn_callee_hash_read::<AB>(local, challenges);
    let fmp = compute_fmp_write_request::<AB>(local, next, challenges);
    control * callee * fmp
}

fn compute_syscall_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let control =
        compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Syscall);
    let hs = local.decoder.hasher_state;
    let label: AB::Expr = KERNEL_PROC_CALL_LABEL.into();
    let kernel = challenges
        .encode(CHIPLETS_BUS, [label, hs[0].into(), hs[1].into(), hs[2].into(), hs[3].into()]);
    control * kernel
}

fn compute_end_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let addr: AB::Expr = local.decoder.addr + HASH_CYCLE_OFFSET;
    let digest: [AB::Expr; 4] = array::from_fn(|i| local.decoder.hasher_state[i].into());
    compute_hasher_word_message::<AB>(
        challenges,
        TRANSITION_RETURN_HASH.into(),
        addr,
        AB::Expr::ZERO,
        digest,
    )
}

fn compute_hornerbase_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
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
}

fn compute_hornerext_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
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
}

fn compute_mstream_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    compute_two_word_request::<AB>(local, next, challenges, true)
}

fn compute_pipe_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    compute_two_word_request::<AB>(local, next, challenges, false)
}
