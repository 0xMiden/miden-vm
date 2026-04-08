//! Chiplets bus constraint (b_chiplets).
//!
//! This module enforces the running product constraint for the main chiplets bus
//! (bus_6_chiplets_bus). The chiplets bus handles communication between the VM components (stack,
//! decoder) and the specialized chiplets (hasher, bitwise, memory, ACE, kernel ROM).
//!
//! ## Running Product Protocol
//!
//! The bus accumulator b_chiplets uses a multiset running product:
//! - Boundary: b_chiplets[0] = 1, b_chiplets[last] = reduced_kernel_digests (via aux_finals)
//! - Transition: b_chiplets' * requests = b_chiplets * responses
//!
//! The bus starts at 1. Kernel ROM INIT_LABEL responses multiply in the kernel procedure hashes,
//! so aux_final[b_chiplets] = reduced_kernel_digests. The verifier checks this against the
//! expected value computed from kernel hashes provided as variable-length public inputs.
//!
//! ## Message Types
//!
//! ### Hasher Chiplet Messages (15 elements)
//! Format: header + state where:
//! - header = alpha + beta^0 * transition_label + beta^1 * addr + beta^2 * node_index
//! - state = sum(beta^(3+i) * hasher_state[i]) for i in 0..12
//!
//! ### Bitwise Chiplet Messages (5 elements)
//! Format: alpha + beta^0*label + beta^1*a + beta^2*b + beta^3*z
//!
//! ### Memory Chiplet Messages (6-9 elements)
//! Element format: alpha + beta^0*label + ... + beta^4*element
//! Word format: alpha + beta^0*label + ... + beta^7*word[3]
//!
//! ## References
//! - Processor: processor/src/chiplets/aux_trace/bus/

use core::borrow::Borrow;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE, field::PrimeCharacteristicRing, operations::opcodes};
use miden_crypto::stark::air::{ExtensionBuilder, WindowAccess};

use crate::{
    Felt, MainCols, MidenAirBuilder,
    constraints::{
        bus::indices::B_CHIPLETS,
        chiplets::{columns::PeriodicCols, selectors::ChipletSelectors},
        op_flags::OpFlags,
    },
    trace::{
        Challenges, bus_types,
        chiplets::{
            NUM_ACE_SELECTORS, NUM_KERNEL_ROM_SELECTORS,
            ace::{
                ACE_INIT_LABEL, CLK_IDX, CTX_IDX, ID_0_IDX, PTR_IDX, READ_NUM_EVAL_IDX,
                SELECTOR_START_IDX,
            },
            bitwise::{self, BITWISE_AND_LABEL, BITWISE_XOR_LABEL},
            hasher::{
                CONTROLLER_ROWS_PER_PERMUTATION, LINEAR_HASH_LABEL, MP_VERIFY_LABEL,
                MR_UPDATE_NEW_LABEL, MR_UPDATE_OLD_LABEL, RETURN_HASH_LABEL, RETURN_STATE_LABEL,
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

/// Label offset for input (start) messages on the chiplets bus.
const INPUT_LABEL_OFFSET: u16 = 16;
/// Label offset for output (end) messages on the chiplets bus.
const OUTPUT_LABEL_OFFSET: u16 = 32;

// ENTRY POINTS
// ================================================================================================

/// Enforces the chiplets bus constraint.
///
/// This is the main constraint for bus_6_chiplets_bus, which handles all communication
/// between VM components and specialized chiplets.
///
/// The constraint follows the running product protocol:
/// - `b_chiplets' * requests = b_chiplets * responses`
///
/// Where `requests` are messages inserted by VM operations (stack/decoder) and
/// `responses` are messages removed by chiplet operations.
pub fn enforce_chiplets_bus_constraint<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    challenges: &Challenges<AB::ExprEF>,
    _selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Auxiliary trace must be present.

    // Extract auxiliary trace values.
    let (b_local_val, b_next_val) = {
        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();
        (aux_local[B_CHIPLETS], aux_next[B_CHIPLETS])
    };

    // =========================================================================
    // COMPUTE REQUEST MULTIPLIER
    // =========================================================================

    // --- Hasher request flags ---
    let f_hperm: AB::Expr = op_flags.hperm();
    let f_mpverify: AB::Expr = op_flags.mpverify();
    let f_mrupdate: AB::Expr = op_flags.mrupdate();

    // --- Control block flags ---
    let f_join: AB::Expr = op_flags.join();
    let f_split: AB::Expr = op_flags.split();
    let f_loop: AB::Expr = op_flags.loop_op();
    let f_call: AB::Expr = op_flags.call();
    let f_dyn: AB::Expr = op_flags.dyn_op();
    let f_dyncall: AB::Expr = op_flags.dyncall();
    let f_syscall: AB::Expr = op_flags.syscall();
    let f_span: AB::Expr = op_flags.span();
    let f_respan: AB::Expr = op_flags.respan();
    let f_end: AB::Expr = op_flags.end();

    // --- Memory request flags ---
    let f_mload: AB::Expr = op_flags.mload();
    let f_mstore: AB::Expr = op_flags.mstore();
    let f_mloadw: AB::Expr = op_flags.mloadw();
    let f_mstorew: AB::Expr = op_flags.mstorew();
    let f_hornerbase: AB::Expr = op_flags.hornerbase();
    let f_hornerext: AB::Expr = op_flags.hornerext();
    let f_mstream: AB::Expr = op_flags.mstream();
    let f_pipe: AB::Expr = op_flags.pipe();
    let f_cryptostream: AB::Expr = op_flags.cryptostream();

    // --- Bitwise request flags ---
    let f_u32and: AB::Expr = op_flags.u32and();
    let f_u32xor: AB::Expr = op_flags.u32xor();

    // --- ACE and log_precompile request flags ---
    let f_evalcircuit: AB::Expr = op_flags.evalcircuit();
    let f_logprecompile: AB::Expr = op_flags.log_precompile();

    // --- Hasher request values ---
    let v_hperm = compute_hperm_request::<AB>(local, next, challenges);
    let v_mpverify = compute_mpverify_request::<AB>(local, challenges);
    let v_mrupdate = compute_mrupdate_request::<AB>(local, next, challenges);

    // --- Control block request values ---
    let v_join = compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Join);
    let v_split =
        compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Split);
    let v_loop = compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Loop);
    let v_call = compute_call_request::<AB>(local, next, challenges);
    let v_dyn = compute_dyn_request::<AB>(local, next, challenges);
    let v_dyncall = compute_dyncall_request::<AB>(local, next, challenges);
    let v_syscall = compute_syscall_request::<AB>(local, next, challenges);
    let v_span = compute_span_request::<AB>(local, next, challenges);
    let v_respan = compute_respan_request::<AB>(local, next, challenges);
    let v_end = compute_end_request::<AB>(local, challenges);

    // --- Memory request values ---
    let v_mload = compute_memory_element_request::<AB>(local, next, challenges, true); // is_read = true
    let v_mstore = compute_memory_element_request::<AB>(local, next, challenges, false); // is_read = false
    let v_mloadw = compute_memory_word_request::<AB>(local, next, challenges, true); // is_read = true
    let v_mstorew = compute_memory_word_request::<AB>(local, next, challenges, false); // is_read = false
    let v_hornerbase = compute_hornerbase_request::<AB>(local, challenges);
    let v_hornerext = compute_hornerext_request::<AB>(local, challenges);
    let v_mstream = compute_mstream_request::<AB>(local, next, challenges);
    let v_pipe = compute_pipe_request::<AB>(local, next, challenges);
    let v_cryptostream = compute_cryptostream_request::<AB>(local, next, challenges);

    // --- Bitwise request values ---
    let v_u32and = compute_bitwise_request::<AB>(local, next, challenges, false); // is_xor = false
    let v_u32xor = compute_bitwise_request::<AB>(local, next, challenges, true); // is_xor = true

    // --- ACE and log_precompile request values ---
    let v_evalcircuit = compute_ace_request::<AB>(local, challenges);
    let v_logprecompile = compute_log_precompile_request::<AB>(local, next, challenges);

    // Sum of request flags (hasher + control blocks + memory + bitwise + ACE + log_precompile)
    let request_flag_sum: AB::Expr = f_hperm.clone()
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

    let one_ef = AB::ExprEF::ONE;

    // Request multiplier = sum(flag * value) + (1 - sum(flags))
    let requests: AB::ExprEF = v_hperm * f_hperm.clone()
        + v_mpverify * f_mpverify.clone()
        + v_mrupdate * f_mrupdate.clone()
        + v_join * f_join.clone()
        + v_split * f_split.clone()
        + v_loop * f_loop.clone()
        + v_call * f_call.clone()
        + v_dyn * f_dyn.clone()
        + v_dyncall * f_dyncall.clone()
        + v_syscall * f_syscall.clone()
        + v_span * f_span.clone()
        + v_respan * f_respan.clone()
        + v_end * f_end.clone()
        + v_mload * f_mload.clone()
        + v_mstore * f_mstore.clone()
        + v_mloadw * f_mloadw.clone()
        + v_mstorew * f_mstorew.clone()
        + v_hornerbase * f_hornerbase.clone()
        + v_hornerext * f_hornerext.clone()
        + v_mstream * f_mstream.clone()
        + v_pipe * f_pipe.clone()
        + v_cryptostream * f_cryptostream.clone()
        + v_u32and * f_u32and.clone()
        + v_u32xor * f_u32xor.clone()
        + v_evalcircuit * f_evalcircuit.clone()
        + v_logprecompile * f_logprecompile.clone()
        + (one_ef.clone() - request_flag_sum);

    // =========================================================================
    // COMPUTE RESPONSE MULTIPLIER
    // =========================================================================
    // Responses come from chiplet rows. Chiplet selectors are mutually exclusive.

    // --- Get periodic columns for bitwise cycle gating ---
    let periodic: &PeriodicCols<AB::PeriodicVar> = builder.periodic_values().borrow();
    let k_transition: AB::Expr = periodic.bitwise.k_transition.into();

    // --- Chiplet selector flags (from chiplets columns) ---
    let chiplet_s0: AB::Expr = local.chiplet_selectors()[0].into();
    let chiplet_s1: AB::Expr = local.chiplet_selectors()[1].into();
    let chiplet_s2: AB::Expr = local.chiplet_selectors()[2].into();
    let chiplet_s3: AB::Expr = local.chiplet_selectors()[3].into();
    let chiplet_s4: AB::Expr = local.chiplet_selectors()[4].into();

    // Bitwise chiplet active: s0=1, s1=0
    // Bitwise responds only on last row of 8-row cycle (when k_transition=0)
    let is_bitwise_row: AB::Expr = chiplet_s0.clone() * (AB::Expr::ONE - chiplet_s1.clone());
    let is_bitwise_responding: AB::Expr = is_bitwise_row * (AB::Expr::ONE - k_transition);

    // Memory chiplet active: s0=1, s1=1, s2=0
    let is_memory: AB::Expr =
        chiplet_s0.clone() * chiplet_s1.clone() * (AB::Expr::ONE - chiplet_s2.clone());

    // ACE chiplet active: s0=1, s1=1, s2=1, s3=0
    // Response only on start rows (ace_start_selector = 1)
    let is_ace_row: AB::Expr = chiplet_s0.clone()
        * chiplet_s1.clone()
        * chiplet_s2.clone()
        * (AB::Expr::ONE - chiplet_s3.clone());
    let ace_start_selector: AB::Expr =
        local.chiplets[NUM_ACE_SELECTORS + SELECTOR_START_IDX].into();
    let is_ace: AB::Expr = is_ace_row * ace_start_selector;

    // Kernel ROM chiplet active: s0=1, s1=1, s2=1, s3=1, s4=0
    let is_kernel_rom: AB::Expr = chiplet_s0.clone()
        * chiplet_s1.clone()
        * chiplet_s2.clone()
        * chiplet_s3.clone()
        * (AB::Expr::ONE - chiplet_s4.clone());

    // --- Hasher response (complex, depends on cycle position and selectors) ---
    let hasher_response = compute_hasher_response::<AB>(local, next, challenges);

    // --- Bitwise response ---
    let v_bitwise = compute_bitwise_response::<AB>(local, challenges);

    // --- Memory response ---
    let v_memory = compute_memory_response::<AB>(local, challenges);

    // --- ACE response ---
    let v_ace = compute_ace_response::<AB>(local, challenges);

    // --- Kernel ROM response ---
    let v_kernel_rom = compute_kernel_rom_response::<AB>(local, challenges);

    // Convert flags to ExprEF
    // Responses: hasher + bitwise + memory + ACE + kernel ROM contributions, others return 1
    let responses: AB::ExprEF = hasher_response.sum
        + v_bitwise * is_bitwise_responding.clone()
        + v_memory * is_memory.clone()
        + v_ace * is_ace.clone()
        + v_kernel_rom * is_kernel_rom.clone()
        + (AB::ExprEF::ONE
            - hasher_response.flag_sum
            - is_bitwise_responding
            - is_memory
            - is_ace
            - is_kernel_rom);

    // =========================================================================
    // RUNNING PRODUCT TRANSITION CONSTRAINT
    // =========================================================================
    // b_chiplets' * requests = b_chiplets * responses

    let lhs: AB::ExprEF = Into::<AB::ExprEF>::into(b_next_val) * requests;
    let rhs: AB::ExprEF = Into::<AB::ExprEF>::into(b_local_val) * responses;
    builder.when_transition().assert_zero_ext(lhs - rhs);
}

// BITWISE MESSAGE HELPERS
// ================================================================================================

/// Computes the bitwise request message value.
///
/// Format: alpha + beta^0*label + beta^1*a + beta^2*b + beta^3*z
///
/// Stack layout for U32AND/U32XOR: [a, b, ...] -> [z, ...]
fn compute_bitwise_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    is_xor: bool,
) -> AB::ExprEF {
    let label: Felt = if is_xor { BITWISE_XOR_LABEL } else { BITWISE_AND_LABEL };
    let label: AB::Expr = AB::Expr::from(label);

    // Stack values
    let a: AB::Expr = local.stack.get(0).into();
    let b: AB::Expr = local.stack.get(1).into();
    let z: AB::Expr = next.stack.get(0).into();

    challenges.encode(bus_types::CHIPLETS_BUS, [label, a, b, z])
}

/// Computes the bitwise chiplet response message value.
///
/// Format: alpha + beta^0*label + beta^1*a + beta^2*b + beta^3*z
fn compute_bitwise_response<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    use crate::trace::chiplets::NUM_BITWISE_SELECTORS;

    // Bitwise chiplet columns start at NUM_BITWISE_SELECTORS=2 in local.chiplets
    let bw_offset = NUM_BITWISE_SELECTORS;

    // Get bitwise operation selector and compute label
    // The AND/XOR selector is at bitwise[0] = local.chiplets[bw_offset]
    // label = (1 - sel) * AND_LABEL + sel * XOR_LABEL
    let sel: AB::Expr = local.chiplets[bw_offset].into();
    let one_minus_sel = AB::Expr::ONE - sel.clone();
    let label = one_minus_sel * AB::Expr::from(BITWISE_AND_LABEL)
        + sel.clone() * AB::Expr::from(BITWISE_XOR_LABEL);

    // Bitwise chiplet data columns (offset by bw_offset + bitwise internal indices)
    let a: AB::Expr = local.chiplets[bw_offset + bitwise::A_COL_IDX].into();
    let b: AB::Expr = local.chiplets[bw_offset + bitwise::B_COL_IDX].into();
    let z: AB::Expr = local.chiplets[bw_offset + bitwise::OUTPUT_COL_IDX].into();

    challenges.encode(bus_types::CHIPLETS_BUS, [label, a, b, z])
}

// MEMORY MESSAGE HELPERS
// ================================================================================================

/// Computes the memory word request message value.
///
/// Format: alpha + beta^0*label + beta^1*ctx + beta^2*addr + beta^3*clk +
/// beta^4..beta^7 * word
///
/// Stack layout for MLOADW: [addr, ...] -> [word[0], word[1], word[2], word[3], ...]
/// Stack layout for MSTOREW: [addr, word[0], word[1], word[2], word[3], ...]
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
    let label: AB::Expr = AB::Expr::from_u16(label as u16);

    // Context and clock from system columns
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();

    // Address is at stack[0]
    let addr: AB::Expr = local.stack.get(0).into();

    // Word values depend on read vs write
    let (w0, w1, w2, w3) = if is_read {
        // MLOADW: word comes from next stack state
        (
            next.stack.get(0).into(),
            next.stack.get(1).into(),
            next.stack.get(2).into(),
            next.stack.get(3).into(),
        )
    } else {
        // MSTOREW: word comes from current stack[1..5]
        (
            local.stack.get(1).into(),
            local.stack.get(2).into(),
            local.stack.get(3).into(),
            local.stack.get(4).into(),
        )
    };

    challenges.encode(bus_types::CHIPLETS_BUS, [label, ctx, addr, clk, w0, w1, w2, w3])
}

/// Computes the memory element request message value.
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
    let label: AB::Expr = AB::Expr::from_u16(label as u16);

    // Context and clock from system columns
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();

    // Address is at stack[0]
    let addr: AB::Expr = local.stack.get(0).into();

    // Element value
    let element = if is_read {
        // MLOAD: element comes from next stack[0]
        next.stack.get(0).into()
    } else {
        // MSTORE: element comes from current stack[1]
        local.stack.get(1).into()
    };

    challenges.encode(bus_types::CHIPLETS_BUS, [label, ctx, addr, clk, element])
}

/// Computes the MSTREAM request message value (two word reads).
fn compute_mstream_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let addr: AB::Expr = local.stack.get(12).into();
    let four: AB::Expr = AB::Expr::from_u16(4);

    // First word: next.stack[0..4] at addr
    let word1 = [
        next.stack.get(0).into(),
        next.stack.get(1).into(),
        next.stack.get(2).into(),
        next.stack.get(3).into(),
    ];

    // Second word: next.stack[4..8] at addr + 4
    let word2 = [
        next.stack.get(4).into(),
        next.stack.get(5).into(),
        next.stack.get(6).into(),
        next.stack.get(7).into(),
    ];

    let msg1 = challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            label.clone(),
            ctx.clone(),
            addr.clone(),
            clk.clone(),
            word1[0].clone(),
            word1[1].clone(),
            word1[2].clone(),
            word1[3].clone(),
        ],
    );

    let msg2 = challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            label,
            ctx,
            addr + four.clone(),
            clk,
            word2[0].clone(),
            word2[1].clone(),
            word2[2].clone(),
            word2[3].clone(),
        ],
    );

    msg1 * msg2
}

/// Computes the PIPE request message value (two word writes).
fn compute_pipe_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_WRITE_WORD_LABEL as u16);
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let addr: AB::Expr = local.stack.get(12).into();
    let four: AB::Expr = AB::Expr::from_u16(4);

    // First word to addr: next.stack[0..4]
    let word1 = [
        next.stack.get(0).into(),
        next.stack.get(1).into(),
        next.stack.get(2).into(),
        next.stack.get(3).into(),
    ];

    // Second word to addr + 4: next.stack[4..8]
    let word2 = [
        next.stack.get(4).into(),
        next.stack.get(5).into(),
        next.stack.get(6).into(),
        next.stack.get(7).into(),
    ];

    let msg1 = challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            label.clone(),
            ctx.clone(),
            addr.clone(),
            clk.clone(),
            word1[0].clone(),
            word1[1].clone(),
            word1[2].clone(),
            word1[3].clone(),
        ],
    );

    let msg2 = challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            label,
            ctx,
            addr + four.clone(),
            clk,
            word2[0].clone(),
            word2[1].clone(),
            word2[2].clone(),
            word2[3].clone(),
        ],
    );

    msg1 * msg2
}

/// Computes the CRYPTOSTREAM request value (two word reads + two word writes).
fn compute_cryptostream_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let read_label: AB::Expr = AB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);
    let write_label: AB::Expr = AB::Expr::from_u16(MEMORY_WRITE_WORD_LABEL as u16);
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let src: AB::Expr = local.stack.get(12).into();
    let dst: AB::Expr = local.stack.get(13).into();
    let four: AB::Expr = AB::Expr::from_u16(4);

    let rate: [AB::Expr; 8] = core::array::from_fn(|i| local.stack.get(i).into());
    let cipher: [AB::Expr; 8] = core::array::from_fn(|i| next.stack.get(i).into());
    let plain: [AB::Expr; 8] = core::array::from_fn(|i| cipher[i].clone() - rate[i].clone());

    let read_msg1 = challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            read_label.clone(),
            ctx.clone(),
            src.clone(),
            clk.clone(),
            plain[0].clone(),
            plain[1].clone(),
            plain[2].clone(),
            plain[3].clone(),
        ],
    );

    let read_msg2 = challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            read_label,
            ctx.clone(),
            src + four.clone(),
            clk.clone(),
            plain[4].clone(),
            plain[5].clone(),
            plain[6].clone(),
            plain[7].clone(),
        ],
    );

    let write_msg1 = challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            write_label.clone(),
            ctx.clone(),
            dst.clone(),
            clk.clone(),
            cipher[0].clone(),
            cipher[1].clone(),
            cipher[2].clone(),
            cipher[3].clone(),
        ],
    );

    let write_msg2 = challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            write_label,
            ctx,
            dst + four,
            clk,
            cipher[4].clone(),
            cipher[5].clone(),
            cipher[6].clone(),
            cipher[7].clone(),
        ],
    );

    read_msg1 * read_msg2 * write_msg1 * write_msg2
}

/// Computes the HORNERBASE request value (two element reads).
fn compute_hornerbase_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_READ_ELEMENT_LABEL as u16);
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let addr: AB::Expr = local.stack.get(13).into();
    let one: AB::Expr = AB::Expr::ONE;

    // Helper registers hold eval_point_0 and eval_point_1
    let eval0: AB::Expr = local.decoder.hasher_state[2].into();
    let eval1: AB::Expr = local.decoder.hasher_state[3].into();

    let msg0 = challenges.encode(
        bus_types::CHIPLETS_BUS,
        [label.clone(), ctx.clone(), addr.clone(), clk.clone(), eval0],
    );

    let msg1 = challenges.encode(bus_types::CHIPLETS_BUS, [label, ctx, addr + one, clk, eval1]);

    msg0 * msg1
}

/// Computes the HORNEREXT request value (one word read).
fn compute_hornerext_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let addr: AB::Expr = local.stack.get(13).into();

    // Helpers 0..3 hold eval_point_0, eval_point_1, mem_junk_0, mem_junk_1
    let word = [
        local.decoder.hasher_state[2].into(),
        local.decoder.hasher_state[3].into(),
        local.decoder.hasher_state[4].into(),
        local.decoder.hasher_state[5].into(),
    ];

    challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            label,
            ctx,
            addr,
            clk,
            word[0].clone(),
            word[1].clone(),
            word[2].clone(),
            word[3].clone(),
        ],
    )
}

/// Computes the memory chiplet response message value.
///
/// The memory chiplet uses different labels for read/write and element/word operations.
/// Address is computed as: word + 2*idx1 + idx0
/// For element access, the correct element is selected based on idx0, idx1.
fn compute_memory_response<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    use crate::trace::chiplets::{NUM_MEMORY_SELECTORS, memory};

    // Memory chiplet columns (offset by NUM_MEMORY_SELECTORS=3 for s0, s1, s2 selectors)
    // local.chiplets is relative to CHIPLETS_OFFSET, memory columns start at index 3
    let mem_offset = NUM_MEMORY_SELECTORS;
    let is_read: AB::Expr = local.chiplets[mem_offset + memory::IS_READ_COL_IDX].into();
    let is_word: AB::Expr = local.chiplets[mem_offset + memory::IS_WORD_ACCESS_COL_IDX].into();
    let ctx: AB::Expr = local.chiplets[mem_offset + memory::CTX_COL_IDX].into();
    let word: AB::Expr = local.chiplets[mem_offset + memory::WORD_COL_IDX].into();
    let idx0: AB::Expr = local.chiplets[mem_offset + memory::IDX0_COL_IDX].into();
    let idx1: AB::Expr = local.chiplets[mem_offset + memory::IDX1_COL_IDX].into();
    let clk: AB::Expr = local.chiplets[mem_offset + memory::CLK_COL_IDX].into();

    // Compute address: addr = word + 2*idx1 + idx0
    let addr: AB::Expr = word + idx1.clone() * AB::Expr::from_u16(2) + idx0.clone();

    // Compute label from flags using the canonical constants.
    let one = AB::Expr::ONE;
    let write_element_label = AB::Expr::from_u16(MEMORY_WRITE_ELEMENT_LABEL as u16);
    let write_word_label = AB::Expr::from_u16(MEMORY_WRITE_WORD_LABEL as u16);
    let read_element_label = AB::Expr::from_u16(MEMORY_READ_ELEMENT_LABEL as u16);
    let read_word_label = AB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);
    let write_label =
        (one.clone() - is_word.clone()) * write_element_label + is_word.clone() * write_word_label;
    let read_label =
        (one.clone() - is_word.clone()) * read_element_label + is_word.clone() * read_word_label;
    let label = (one.clone() - is_read.clone()) * write_label + is_read.clone() * read_label;

    // Get value columns (v0, v1, v2, v3)
    let v0: AB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start].into();
    let v1: AB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 1].into();
    let v2: AB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 2].into();
    let v3: AB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 3].into();

    // For element access, select the correct element based on idx0, idx1:
    // - (0,0) -> v0, (1,0) -> v1, (0,1) -> v2, (1,1) -> v3
    // element = v0*(1-idx0)*(1-idx1) + v1*idx0*(1-idx1) + v2*(1-idx0)*idx1 + v3*idx0*idx1
    let element: AB::Expr =
        v0.clone() * (one.clone() - idx0.clone()) * (one.clone() - idx1.clone())
            + v1.clone() * idx0.clone() * (one.clone() - idx1.clone())
            + v2.clone() * (one.clone() - idx0.clone()) * idx1.clone()
            + v3.clone() * idx0.clone() * idx1.clone();

    // For word access, all v0..v3 are used
    let is_element = one.clone() - is_word.clone();

    // Element access: include the selected element in the last slot.
    let element_msg = challenges.encode(
        bus_types::CHIPLETS_BUS,
        [label.clone(), ctx.clone(), addr.clone(), clk.clone(), element],
    );

    // Word access: include all 4 values.
    let word_msg =
        challenges.encode(bus_types::CHIPLETS_BUS, [label, ctx, addr, clk, v0, v1, v2, v3]);

    // Select based on is_word
    element_msg * is_element + word_msg * is_word
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
/// Only hasher controller rows (dispatch, perm_seg=0) produce bus responses.
/// Hasher permutation segment rows (compute, perm_seg=1) do not contribute.
///
/// **Controller input rows** (s0=1, perm_seg=0):
/// - Sponge start (is_boundary=1, s1=0, s2=0): full 12-element state
/// - Sponge continuation (is_boundary=0, s1=0, s2=0): rate-only 8 elements (RESPAN)
/// - Tree start (is_boundary=1, s1=1 or s2=1): leaf word
///
/// **Controller output rows** (s0=0, s1=0, perm_seg=0):
/// - HOUT (s2=0): digest
/// - SOUT (s2=1) + is_boundary=1: full 12-element state
///
/// No response on: hasher permutation segment rows, padding rows ([0,1,0]),
/// tree continuations (is_boundary=0), or intermediate SOUT (is_boundary=0).
fn compute_hasher_response<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> HasherResponse<AB::ExprEF, AB::Expr> {
    use crate::trace::{
        CHIPLETS_OFFSET,
        chiplets::{
            HASHER_IS_BOUNDARY_COL_IDX, HASHER_NODE_INDEX_COL_IDX, HASHER_PERM_SEG_COL_IDX,
            HASHER_STATE_COL_RANGE,
        },
    };

    let one = AB::Expr::ONE;

    // Controller flag: hasher active AND not in perm segment
    let hasher_active: AB::Expr = one.clone() - local.chiplets[0].into();
    let perm_seg: AB::Expr = local.chiplets[HASHER_PERM_SEG_COL_IDX - CHIPLETS_OFFSET].into();
    let controller_flag = hasher_active * (one.clone() - perm_seg);

    // Hasher internal selectors
    let hs0: AB::Expr = local.chiplets[1].into();
    let hs1: AB::Expr = local.chiplets[2].into();
    let hs2: AB::Expr = local.chiplets[3].into();

    // Lifecycle columns
    let is_boundary: AB::Expr = local.chiplets[HASHER_IS_BOUNDARY_COL_IDX - CHIPLETS_OFFSET].into();
    // State and node_index
    let state: [AB::Expr; 12] = core::array::from_fn(|i| {
        let col_idx = HASHER_STATE_COL_RANGE.start - CHIPLETS_OFFSET + i;
        local.chiplets[col_idx].into()
    });
    let node_index: AB::Expr = local.chiplets[HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET].into();

    // Address
    let addr_next: AB::Expr = local.system.clk.into() + one.clone();

    // --- Response flags (inner, without controller_flag to keep degree low) ---
    //
    // controller_flag (degree 2) is factored out and applied to the entire response sum,
    // keeping the max flag*message degree at 6 instead of 8.

    // Sponge start: input, s1=0, s2=0, is_boundary=1
    let f_sponge_start = hs0.clone()
        * (one.clone() - hs1.clone())
        * (one.clone() - hs2.clone())
        * is_boundary.clone();

    // Sponge continuation (RESPAN): input, s1=0, s2=0, is_boundary=0
    let f_sponge_respan = hs0.clone()
        * (one.clone() - hs1.clone())
        * (one.clone() - hs2.clone())
        * (one.clone() - is_boundary.clone());

    // Merkle tree op start inputs (only is_boundary=1 produces response)
    let f_mp_start = hs0.clone() * (one.clone() - hs1.clone()) * hs2.clone() * is_boundary.clone();
    let f_mv_start = hs0.clone() * hs1.clone() * (one.clone() - hs2.clone()) * is_boundary.clone();
    let f_mu_start = hs0.clone() * hs1.clone() * hs2.clone() * is_boundary.clone();

    // HOUT output (always responds)
    let f_hout =
        (one.clone() - hs0.clone()) * (one.clone() - hs1.clone()) * (one.clone() - hs2.clone());

    // SOUT output with is_boundary=1 only (HPERM return)
    let f_sout_final =
        (one.clone() - hs0.clone()) * (one.clone() - hs1.clone()) * hs2.clone() * is_boundary;

    // --- Message values ---

    let label_sponge_start = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + INPUT_LABEL_OFFSET);
    let label_sponge_respan = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + OUTPUT_LABEL_OFFSET);
    let label_mp = AB::Expr::from_u16(MP_VERIFY_LABEL as u16 + INPUT_LABEL_OFFSET);
    let label_mv = AB::Expr::from_u16(MR_UPDATE_OLD_LABEL as u16 + INPUT_LABEL_OFFSET);
    let label_mu = AB::Expr::from_u16(MR_UPDATE_NEW_LABEL as u16 + INPUT_LABEL_OFFSET);
    let label_hout = AB::Expr::from_u16(RETURN_HASH_LABEL as u16 + OUTPUT_LABEL_OFFSET);
    let label_sout = AB::Expr::from_u16(RETURN_STATE_LABEL as u16 + OUTPUT_LABEL_OFFSET);

    // Sponge start: full 12-element state, node_index=0 (sponge doesn't use index)
    let v_sponge_start = compute_hasher_message::<AB>(
        challenges,
        label_sponge_start,
        addr_next.clone(),
        AB::Expr::ZERO,
        &state,
    );

    // Sponge continuation (RESPAN): rate-only 8 elements, addr_next directly
    let rate: [AB::Expr; 8] = core::array::from_fn(|i| state[i].clone());
    let v_sponge_respan = compute_hasher_rate_message::<AB>(
        challenges,
        label_sponge_respan,
        addr_next.clone(),
        AB::Expr::ZERO,
        &rate,
    );

    // Merkle tree inputs: leaf word selected by direction bit
    let two = AB::Expr::from_u16(2);
    let node_index_next: AB::Expr =
        next.chiplets[HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET].into();
    let bit = node_index.clone() - two * node_index_next;
    let leaf_word: [AB::Expr; 4] = [
        (one.clone() - bit.clone()) * state[0].clone() + bit.clone() * state[4].clone(),
        (one.clone() - bit.clone()) * state[1].clone() + bit.clone() * state[5].clone(),
        (one.clone() - bit.clone()) * state[2].clone() + bit.clone() * state[6].clone(),
        (one.clone() - bit.clone()) * state[3].clone() + bit.clone() * state[7].clone(),
    ];
    let v_mp = compute_hasher_word_message::<AB>(
        challenges,
        label_mp,
        addr_next.clone(),
        node_index.clone(),
        &leaf_word,
    );
    let v_mv = compute_hasher_word_message::<AB>(
        challenges,
        label_mv,
        addr_next.clone(),
        node_index.clone(),
        &leaf_word,
    );
    let v_mu = compute_hasher_word_message::<AB>(
        challenges,
        label_mu,
        addr_next.clone(),
        node_index.clone(),
        &leaf_word,
    );

    // HOUT: digest from RATE0 (state[0..4])
    let digest: [AB::Expr; 4] = core::array::from_fn(|i| state[i].clone());
    let v_hout = compute_hasher_word_message::<AB>(
        challenges,
        label_hout,
        addr_next.clone(),
        node_index.clone(),
        &digest,
    );

    // SOUT: full 12-element state (HPERM return), node_index=0
    let v_sout =
        compute_hasher_message::<AB>(challenges, label_sout, addr_next, AB::Expr::ZERO, &state);

    // --- Additive OR combination ---
    //
    // The inner flag_sum and sum are computed without controller_flag. The controller_flag
    // is applied as a multiplicative factor to the entire sum, keeping the degree within
    // budget: inner_flag(4) * message(2) = 6, * controller_flag(2) = 8.

    let inner_flag_sum = f_sponge_start.clone()
        + f_sponge_respan.clone()
        + f_mp_start.clone()
        + f_mv_start.clone()
        + f_mu_start.clone()
        + f_hout.clone()
        + f_sout_final.clone();

    let inner_sum = v_sponge_start * f_sponge_start
        + v_sponge_respan * f_sponge_respan
        + v_mp * f_mp_start
        + v_mv * f_mv_start
        + v_mu * f_mu_start
        + v_hout * f_hout
        + v_sout * f_sout_final;

    // Apply controller_flag to the entire response. On perm segment and non-hasher rows,
    // controller_flag=0 so the hasher contributes nothing (identity via the outer 1-flag_sum).
    let flag_sum = controller_flag.clone() * inner_flag_sum;
    let sum = inner_sum * controller_flag;

    HasherResponse { sum, flag_sum }
}

// HASHER MESSAGE HELPERS
// ================================================================================================

/// Computes the HPERM request message value.
///
/// HPERM sends two messages to the hasher chiplet:
/// 1. Input message: LINEAR_HASH_LABEL + 16, with input state from stack[0..12]
/// 2. Output message: RETURN_STATE_LABEL + 32, with output state from next stack[0..12]
///
/// The combined request is the product of these two message values.
///
/// Stack layout: [s0, s1, ..., s11, ...] -> [s0', s1', ..., s11', ...]
fn compute_hperm_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // Hasher address from helper register 0
    let addr: AB::Expr = local.decoder.hasher_state[2].into();

    // Input state from current stack[0..12]
    let input_state: [AB::Expr; 12] = core::array::from_fn(|i| local.stack.get(i).into());

    // Output state from next stack[0..12]
    let output_state: [AB::Expr; 12] = core::array::from_fn(|i| next.stack.get(i).into());

    // Input message: transition_label = LINEAR_HASH_LABEL + 16 = 3 + 16 = 19
    let input_label: AB::Expr = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + INPUT_LABEL_OFFSET);
    let node_index_zero: AB::Expr = AB::Expr::ZERO;

    let input_msg = compute_hasher_message::<AB>(
        challenges,
        input_label,
        addr.clone(),
        node_index_zero.clone(),
        &input_state,
    );

    // Output message: transition_label = RETURN_STATE_LABEL + 32
    // addr_next = addr + (CONTROLLER_ROWS_PER_PERMUTATION - 1) = addr + 1
    let output_label: AB::Expr =
        AB::Expr::from_u16(RETURN_STATE_LABEL as u16 + OUTPUT_LABEL_OFFSET);
    let addr_offset: AB::Expr = AB::Expr::from_u16((CONTROLLER_ROWS_PER_PERMUTATION - 1) as u16);
    let addr_next = addr + addr_offset;

    let output_msg = compute_hasher_message::<AB>(
        challenges,
        output_label,
        addr_next,
        node_index_zero,
        &output_state,
    );

    // Combined request is product of input and output messages
    input_msg * output_msg
}

/// Computes the LOG_PRECOMPILE request message value.
///
/// LOG_PRECOMPILE absorbs `[COMM, TAG]` with capacity `CAP_PREV` and returns `[R0, R1, CAP_NEXT]`.
/// The request is the product of input (LINEAR_HASH + 16) and output (RETURN_STATE + 32) messages.
fn compute_log_precompile_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // Helper registers (user op helpers start at hasher_state[2])
    let addr: AB::Expr = local.decoder.hasher_state[2 + HELPER_ADDR_IDX].into();

    // CAP_PREV from helper registers (4 lanes)
    let cap_prev: [AB::Expr; 4] = core::array::from_fn(|i| {
        local.decoder.hasher_state[2 + HELPER_CAP_PREV_RANGE.start + i].into()
    });

    // COMM and TAG from the current stack
    let comm: [AB::Expr; 4] =
        core::array::from_fn(|i| local.stack.get(STACK_COMM_RANGE.start + i).into());
    let tag: [AB::Expr; 4] =
        core::array::from_fn(|i| local.stack.get(STACK_TAG_RANGE.start + i).into());

    // Input state [COMM, TAG, CAP_PREV]
    let state_input: [AB::Expr; 12] = [
        comm[0].clone(),
        comm[1].clone(),
        comm[2].clone(),
        comm[3].clone(),
        tag[0].clone(),
        tag[1].clone(),
        tag[2].clone(),
        tag[3].clone(),
        cap_prev[0].clone(),
        cap_prev[1].clone(),
        cap_prev[2].clone(),
        cap_prev[3].clone(),
    ];

    // Output state from next stack [R0, R1, CAP_NEXT]
    let r0: [AB::Expr; 4] =
        core::array::from_fn(|i| next.stack.get(STACK_R0_RANGE.start + i).into());
    let r1: [AB::Expr; 4] =
        core::array::from_fn(|i| next.stack.get(STACK_R1_RANGE.start + i).into());
    let cap_next: [AB::Expr; 4] =
        core::array::from_fn(|i| next.stack.get(STACK_CAP_NEXT_RANGE.start + i).into());
    let state_output: [AB::Expr; 12] = [
        r0[0].clone(),
        r0[1].clone(),
        r0[2].clone(),
        r0[3].clone(),
        r1[0].clone(),
        r1[1].clone(),
        r1[2].clone(),
        r1[3].clone(),
        cap_next[0].clone(),
        cap_next[1].clone(),
        cap_next[2].clone(),
        cap_next[3].clone(),
    ];

    // Input message: LINEAR_HASH_LABEL + 16
    let input_label: AB::Expr = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + INPUT_LABEL_OFFSET);
    let input_msg = compute_hasher_message::<AB>(
        challenges,
        input_label,
        addr.clone(),
        AB::Expr::ZERO,
        &state_input,
    );

    // Output message: RETURN_STATE_LABEL + 32 with addr offset by CONTROLLER_ROWS_PER_PERMUTATION -
    // 1
    let output_label: AB::Expr =
        AB::Expr::from_u16(RETURN_STATE_LABEL as u16 + OUTPUT_LABEL_OFFSET);
    let addr_offset: AB::Expr = AB::Expr::from_u16((CONTROLLER_ROWS_PER_PERMUTATION - 1) as u16);
    let output_msg = compute_hasher_message::<AB>(
        challenges,
        output_label,
        addr + addr_offset,
        AB::Expr::ZERO,
        &state_output,
    );

    input_msg * output_msg
}

/// Computes a hasher message value.
///
/// Format: header + state where:
/// - header = alpha + beta^0 * transition_label + beta^1 * addr + beta^2 * node_index
/// - state = sum(beta^(3+i) * hasher_state[i]) for i in 0..12
fn compute_hasher_message<AB: MidenAirBuilder>(
    challenges: &Challenges<AB::ExprEF>,
    transition_label: AB::Expr,
    addr: AB::Expr,
    node_index: AB::Expr,
    state: &[AB::Expr; 12],
) -> AB::ExprEF {
    challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            transition_label,
            addr,
            node_index,
            state[0].clone(),
            state[1].clone(),
            state[2].clone(),
            state[3].clone(),
            state[4].clone(),
            state[5].clone(),
            state[6].clone(),
            state[7].clone(),
            state[8].clone(),
            state[9].clone(),
            state[10].clone(),
            state[11].clone(),
        ],
    )
}

/// Computes a hasher message for a 4-lane word.
fn compute_hasher_word_message<AB: MidenAirBuilder>(
    challenges: &Challenges<AB::ExprEF>,
    transition_label: AB::Expr,
    addr: AB::Expr,
    node_index: AB::Expr,
    word: &[AB::Expr; 4],
) -> AB::ExprEF {
    challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            transition_label,
            addr,
            node_index,
            word[0].clone(),
            word[1].clone(),
            word[2].clone(),
            word[3].clone(),
        ],
    )
}

/// Computes a hasher message for an 8-lane rate.
fn compute_hasher_rate_message<AB: MidenAirBuilder>(
    challenges: &Challenges<AB::ExprEF>,
    transition_label: AB::Expr,
    addr: AB::Expr,
    node_index: AB::Expr,
    rate: &[AB::Expr; 8],
) -> AB::ExprEF {
    challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            transition_label,
            addr,
            node_index,
            rate[0].clone(),
            rate[1].clone(),
            rate[2].clone(),
            rate[3].clone(),
            rate[4].clone(),
            rate[5].clone(),
            rate[6].clone(),
            rate[7].clone(),
        ],
    )
}

// ACE MESSAGE HELPERS
// ================================================================================================

/// Computes the ACE request message value.
///
/// Format: alpha + beta^0*label + beta^1*clk + beta^2*ctx + beta^3*ptr
///         + beta^4*num_read_rows + beta^5*num_eval_rows
///
/// Stack layout for EVALCIRCUIT: [ptr, num_read_rows, num_eval_rows, ...]
fn compute_ace_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // Label is ACE_INIT_LABEL
    let label: AB::Expr = AB::Expr::from(ACE_INIT_LABEL);

    // Context and clock from system columns
    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();

    // Stack values
    let ptr: AB::Expr = local.stack.get(0).into();
    let num_read_rows: AB::Expr = local.stack.get(1).into();
    let num_eval_rows: AB::Expr = local.stack.get(2).into();

    challenges.encode(bus_types::CHIPLETS_BUS, [label, clk, ctx, ptr, num_read_rows, num_eval_rows])
}

/// Computes the ACE chiplet response message value.
///
/// Format: alpha + beta^0*label + beta^1*clk + beta^2*ctx + beta^3*ptr
///         + beta^4*num_read_rows + beta^5*num_eval_rows
///
/// The chiplet reads from its internal columns:
/// - clk from CLK_IDX
/// - ctx from CTX_IDX
/// - ptr from PTR_IDX
/// - num_eval_rows computed from READ_NUM_EVAL_IDX + 1
/// - num_read_rows = id_0 + 1 - num_eval_rows
fn compute_ace_response<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // Label is ACE_INIT_LABEL
    let label: AB::Expr = AB::Expr::from(ACE_INIT_LABEL);

    // Read values from ACE chiplet columns (offset by NUM_ACE_SELECTORS)
    let clk: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + CLK_IDX].into();
    let ctx: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + CTX_IDX].into();
    let ptr: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + PTR_IDX].into();

    // num_eval_rows = READ_NUM_EVAL_IDX value + 1
    let read_num_eval: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + READ_NUM_EVAL_IDX].into();
    let num_eval_rows: AB::Expr = read_num_eval + AB::Expr::ONE;

    // id_0 from ID_0_IDX
    let id_0: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + ID_0_IDX].into();

    // num_read_rows = id_0 + 1 - num_eval_rows
    let num_read_rows: AB::Expr = id_0 + AB::Expr::ONE - num_eval_rows.clone();

    challenges.encode(bus_types::CHIPLETS_BUS, [label, clk, ctx, ptr, num_read_rows, num_eval_rows])
}

// KERNEL ROM MESSAGE HELPERS
// ================================================================================================

/// Computes the kernel ROM chiplet response message value.
///
/// Format: alpha + beta^0*label + beta^1*digest[0] + beta^2*digest[1]
///         + beta^3*digest[2] + beta^4*digest[3]
///
/// The label depends on s_first flag:
/// - s_first=1: KERNEL_PROC_INIT_LABEL (responding to verifier/public input init request)
/// - s_first=0: KERNEL_PROC_CALL_LABEL (responding to decoder SYSCALL request)
fn compute_kernel_rom_response<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // s_first flag is at CHIPLETS_OFFSET + 5 (after 5 selectors), which is chiplets[5]
    let s_first: AB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS].into();

    // Label depends on s_first:
    // label = s_first * INIT_LABEL + (1 - s_first) * CALL_LABEL
    let init_label: AB::Expr = AB::Expr::from(KERNEL_PROC_INIT_LABEL);
    let call_label: AB::Expr = AB::Expr::from(KERNEL_PROC_CALL_LABEL);
    let label: AB::Expr = s_first.clone() * init_label + (AB::Expr::ONE - s_first) * call_label;

    // Kernel procedure digest (root0..root3) at columns 6, 7, 8, 9 relative to chiplets
    // These are at NUM_KERNEL_ROM_SELECTORS + 1..5 (after s_first which is at +0)
    let root0: AB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS + 1].into();
    let root1: AB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS + 2].into();
    let root2: AB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS + 3].into();
    let root3: AB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS + 4].into();

    challenges.encode(bus_types::CHIPLETS_BUS, [label, root0, root1, root2, root3])
}

// CONTROL BLOCK REQUEST HELPERS
// ================================================================================================

/// Control block operation types for request message construction.
#[derive(Clone, Copy)]
enum ControlBlockOp {
    Join,
    Split,
    Loop,
    Call,
    Syscall,
}

impl ControlBlockOp {
    /// Returns the opcode value for this control block operation.
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

/// Computes the control block request message value for JOIN, SPLIT, LOOP, CALL, and SYSCALL.
///
/// Format follows ControlBlockRequestMessage from processor:
/// - header = alpha + beta^0 * transition_label + beta^1 * addr_next
/// - state = 12-lane sponge with 8-element decoder hasher state as rate + opcode as domain
///
/// The message reconstructs:
/// - transition_label = LINEAR_HASH_LABEL + 16
/// - addr_next = decoder address at next row (from next row's addr column)
/// - hasher_state = rate lanes from decoder hasher columns + opcode in capacity domain position
fn compute_control_block_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    op: ControlBlockOp,
) -> AB::ExprEF {
    // transition_label = LINEAR_HASH_LABEL +
    let transition_label: AB::Expr =
        AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + INPUT_LABEL_OFFSET);

    // addr_next = next row's decoder address
    let addr_next: AB::Expr = next.decoder.addr.into();

    // Get decoder hasher state (8 elements)
    let hasher_state: [AB::Expr; 8] =
        core::array::from_fn(|i| local.decoder.hasher_state[i].into());

    // op_code as domain in capacity position
    let op_code: AB::Expr = AB::Expr::from_u16(op.opcode() as u16);

    // Build 12-lane sponge state:
    // [RATE0: h[0..4], RATE1: h[4..8], CAPACITY: [0, domain, 0, 0]]
    // LE layout: RATE0 at 0..4, RATE1 at 4..8, CAPACITY at 8..12
    let state: [AB::Expr; 12] = [
        hasher_state[0].clone(),
        hasher_state[1].clone(),
        hasher_state[2].clone(),
        hasher_state[3].clone(),
        hasher_state[4].clone(),
        hasher_state[5].clone(),
        hasher_state[6].clone(),
        hasher_state[7].clone(),
        AB::Expr::ZERO,
        op_code, // domain at CAPACITY_DOMAIN_IDX = 9
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];

    compute_hasher_message::<AB>(challenges, transition_label, addr_next, AB::Expr::ZERO, &state)
}

/// Computes the CALL request message value.
///
/// CALL sends:
/// 1. Control block request (with decoder hasher state)
/// 2. FMP initialization write request (to set up new execution context)
fn compute_call_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // Control block request
    let control_req =
        compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Call);

    // FMP initialization write request
    let fmp_req = compute_fmp_write_request::<AB>(local, next, challenges);

    control_req * fmp_req
}

/// Computes the DYN request message value.
///
/// DYN sends:
/// 1. Control block request (with zeros for hasher state since callee is dynamic)
/// 2. Memory read request for callee hash from stack[0]
fn compute_dyn_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // Control block request with zeros for hasher state (callee is dynamic)
    let control_req =
        compute_control_block_request_zeros::<AB>(local, next, challenges, opcodes::DYN);

    // Memory read for callee hash (word read from stack[0] address)
    let callee_hash_req = compute_dyn_callee_hash_read::<AB>(local, challenges);

    control_req * callee_hash_req
}

/// Computes the DYNCALL request message value.
///
/// DYNCALL sends:
/// 1. Control block request (with zeros for hasher state since callee is dynamic)
/// 2. Memory read request for callee hash from stack[0]
/// 3. FMP initialization write request
fn compute_dyncall_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // Control block request with zeros for hasher state (callee is dynamic)
    let control_req =
        compute_control_block_request_zeros::<AB>(local, next, challenges, opcodes::DYNCALL);

    // Memory read for callee hash (word read from stack[0] address)
    let callee_hash_req = compute_dyn_callee_hash_read::<AB>(local, challenges);

    // FMP initialization write request
    let fmp_req = compute_fmp_write_request::<AB>(local, next, challenges);

    control_req * callee_hash_req * fmp_req
}

/// Computes the SYSCALL request message value.
///
/// SYSCALL sends:
/// 1. Control block request (with decoder hasher state)
/// 2. Kernel ROM lookup request (to verify kernel procedure)
fn compute_syscall_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // Control block request
    let control_req =
        compute_control_block_request::<AB>(local, next, challenges, ControlBlockOp::Syscall);

    // Kernel ROM lookup request (digest from first 4 elements of decoder hasher state)
    let root0: AB::Expr = local.decoder.hasher_state[0].into();
    let root1: AB::Expr = local.decoder.hasher_state[1].into();
    let root2: AB::Expr = local.decoder.hasher_state[2].into();
    let root3: AB::Expr = local.decoder.hasher_state[3].into();

    let label: AB::Expr = AB::Expr::from(KERNEL_PROC_CALL_LABEL);
    let kernel_req =
        challenges.encode(bus_types::CHIPLETS_BUS, [label, root0, root1, root2, root3]);

    control_req * kernel_req
}

/// Computes the SPAN block request message value.
///
/// Format: header + full 12-lane sponge state (8 rate lanes + 4 capacity lanes zeroed)
fn compute_span_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // transition_label = LINEAR_HASH_LABEL + 16
    let transition_label: AB::Expr =
        AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + INPUT_LABEL_OFFSET);

    // addr_next = next row's decoder address
    let addr_next: AB::Expr = next.decoder.addr.into();

    // Get decoder hasher state (8 elements)
    let hasher_state: [AB::Expr; 8] =
        core::array::from_fn(|i| local.decoder.hasher_state[i].into());

    // Build full 12-lane state with capacity zeroed
    let state: [AB::Expr; 12] = [
        hasher_state[0].clone(),
        hasher_state[1].clone(),
        hasher_state[2].clone(),
        hasher_state[3].clone(),
        hasher_state[4].clone(),
        hasher_state[5].clone(),
        hasher_state[6].clone(),
        hasher_state[7].clone(),
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];

    compute_hasher_message::<AB>(challenges, transition_label, addr_next, AB::Expr::ZERO, &state)
}

/// Computes the RESPAN block request message value.
///
/// Rate occupies message positions 3..10 (after label/addr/node_index).
fn compute_respan_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // transition_label = LINEAR_HASH_LABEL + 32
    let transition_label: AB::Expr =
        AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + OUTPUT_LABEL_OFFSET);

    // RESPAN message uses addr_next directly (the next row's decoder address).
    // In the controller/perm split, addr_next points directly to the continuation
    // input row -- no offset needed.
    let addr_next: AB::Expr = next.decoder.addr.into();
    let addr_for_msg = addr_next;

    // Get decoder hasher state (8 elements)
    let hasher_state: [AB::Expr; 8] =
        core::array::from_fn(|i| local.decoder.hasher_state[i].into());

    compute_hasher_rate_message::<AB>(
        challenges,
        transition_label,
        addr_for_msg,
        AB::Expr::ZERO,
        &hasher_state,
    )
}

/// Computes the END block request message value.
///
/// Digest occupies message positions 3..6 (after label/addr/node_index).
fn compute_end_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    // transition_label = RETURN_HASH_LABEL + 32 = 1 + 32
    let transition_label: AB::Expr =
        AB::Expr::from_u16(RETURN_HASH_LABEL as u16 + OUTPUT_LABEL_OFFSET);

    // addr = decoder.addr + (CONTROLLER_ROWS_PER_PERMUTATION - 1) = addr + 1
    let addr: AB::Expr = local.decoder.addr.into()
        + AB::Expr::from_u16((CONTROLLER_ROWS_PER_PERMUTATION - 1) as u16);

    // Get digest from decoder hasher state (first 4 elements)
    let digest: [AB::Expr; 4] = core::array::from_fn(|i| local.decoder.hasher_state[i].into());

    compute_hasher_word_message::<AB>(challenges, transition_label, addr, AB::Expr::ZERO, &digest)
}

/// Computes control block request with zeros for hasher state (for DYN/DYNCALL).
fn compute_control_block_request_zeros<AB: MidenAirBuilder>(
    _local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    opcode: u8,
) -> AB::ExprEF {
    // transition_label = LINEAR_HASH_LABEL + 16
    let transition_label: AB::Expr =
        AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + INPUT_LABEL_OFFSET);

    // addr_next = next row's decoder address
    let addr_next: AB::Expr = next.decoder.addr.into();

    // op_code as domain
    let op_code: AB::Expr = AB::Expr::from_u16(opcode as u16);

    // State with zeros for rate lanes, opcode in capacity domain
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
        op_code, // domain at CAPACITY_DOMAIN_IDX = 9
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];

    compute_hasher_message::<AB>(challenges, transition_label, addr_next, AB::Expr::ZERO, &state)
}

/// Computes the FMP initialization write request.
///
/// This writes FMP_INIT_VALUE to FMP_ADDR in the new context.
fn compute_fmp_write_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_WRITE_ELEMENT_LABEL as u16);

    // ctx from next row (new execution context)
    let ctx: AB::Expr = next.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let addr: AB::Expr = AB::Expr::from(FMP_ADDR);
    let element: AB::Expr = AB::Expr::from(FMP_INIT_VALUE);

    challenges.encode(bus_types::CHIPLETS_BUS, [label, ctx, addr, clk, element])
}

/// Computes the callee hash read request for DYN/DYNCALL.
///
/// Reads a word from the address at stack[0] containing the callee hash.
fn compute_dyn_callee_hash_read<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);

    let ctx: AB::Expr = local.system.ctx.into();
    let clk: AB::Expr = local.system.clk.into();
    let addr: AB::Expr = local.stack.get(0).into();

    // The callee hash is read into decoder hasher state first half
    let w0: AB::Expr = local.decoder.hasher_state[0].into();
    let w1: AB::Expr = local.decoder.hasher_state[1].into();
    let w2: AB::Expr = local.decoder.hasher_state[2].into();
    let w3: AB::Expr = local.decoder.hasher_state[3].into();

    challenges.encode(bus_types::CHIPLETS_BUS, [label, ctx, addr, clk, w0, w1, w2, w3])
}

// MPVERIFY/MRUPDATE REQUEST HELPERS
// ================================================================================================

/// Computes the MPVERIFY request message value.
///
/// MPVERIFY sends two messages as a product:
/// 1. Input: node value (stack[0..4]) with node_index
/// 2. Output: root digest (stack[6..10]) at the computed output address
fn compute_mpverify_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let helper_0: AB::Expr = local.decoder.hasher_state[2].into();
    let rows_per_perm: AB::Expr = AB::Expr::from_u16(CONTROLLER_ROWS_PER_PERMUTATION as u16);

    // Stack layout: [node_value0..3, node_depth, node_index, root0..3, ...]
    let node_value: [AB::Expr; 4] = core::array::from_fn(|i| local.stack.get(i).into());
    let node_depth: AB::Expr = local.stack.get(4).into();
    let node_index: AB::Expr = local.stack.get(5).into();
    let root: [AB::Expr; 4] = core::array::from_fn(|i| local.stack.get(6 + i).into());

    let input_label: AB::Expr = AB::Expr::from_u16(MP_VERIFY_LABEL as u16 + INPUT_LABEL_OFFSET);
    let input_msg = compute_hasher_word_message::<AB>(
        challenges,
        input_label,
        helper_0.clone(),
        node_index.clone(),
        &node_value,
    );

    // Output address = start + depth * rows_per_perm - 1 (last output row of the path)
    let output_addr = helper_0 + node_depth * rows_per_perm - AB::Expr::ONE;
    let output_label: AB::Expr = AB::Expr::from_u16(RETURN_HASH_LABEL as u16 + OUTPUT_LABEL_OFFSET);
    let output_msg = compute_hasher_word_message::<AB>(
        challenges,
        output_label,
        output_addr,
        AB::Expr::ZERO,
        &root,
    );

    input_msg * output_msg
}

/// Computes the MRUPDATE request message value.
///
/// MRUPDATE sends four messages as a product:
/// 1. Input old: old node value (stack[0..4]) with node_index
/// 2. Output old: old root digest (stack[6..10]) at computed output address
/// 3. Input new: new node value (stack[10..14]) with node_index
/// 4. Output new: new root digest (next.stack[0..4]) at computed output address
fn compute_mrupdate_request<AB: MidenAirBuilder>(
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF {
    let helper_0: AB::Expr = local.decoder.hasher_state[2].into();
    let rows_per_perm: AB::Expr = AB::Expr::from_u16(CONTROLLER_ROWS_PER_PERMUTATION as u16);
    let two_legs_rows: AB::Expr = rows_per_perm.clone() + rows_per_perm.clone();

    // Stack layout: [old_node0..3, depth, index, old_root0..3, new_node0..3, ...]
    let old_node: [AB::Expr; 4] = core::array::from_fn(|i| local.stack.get(i).into());
    let depth: AB::Expr = local.stack.get(4).into();
    let index: AB::Expr = local.stack.get(5).into();
    let old_root: [AB::Expr; 4] = core::array::from_fn(|i| local.stack.get(6 + i).into());
    let new_node: [AB::Expr; 4] = core::array::from_fn(|i| local.stack.get(10 + i).into());
    // New root is at next.stack[0..4]
    let new_root: [AB::Expr; 4] = core::array::from_fn(|i| next.stack.get(i).into());

    let input_old_label: AB::Expr =
        AB::Expr::from_u16(MR_UPDATE_OLD_LABEL as u16 + INPUT_LABEL_OFFSET);
    let input_old_msg = compute_hasher_word_message::<AB>(
        challenges,
        input_old_label,
        helper_0.clone(),
        index.clone(),
        &old_node,
    );

    let output_old_addr = helper_0.clone() + depth.clone() * rows_per_perm.clone() - AB::Expr::ONE;
    let output_old_label: AB::Expr =
        AB::Expr::from_u16(RETURN_HASH_LABEL as u16 + OUTPUT_LABEL_OFFSET);
    let output_old_msg = compute_hasher_word_message::<AB>(
        challenges,
        output_old_label.clone(),
        output_old_addr,
        AB::Expr::ZERO,
        &old_root,
    );

    let input_new_addr = helper_0.clone() + depth.clone() * rows_per_perm;
    let input_new_label: AB::Expr =
        AB::Expr::from_u16(MR_UPDATE_NEW_LABEL as u16 + INPUT_LABEL_OFFSET);
    let input_new_msg = compute_hasher_word_message::<AB>(
        challenges,
        input_new_label,
        input_new_addr,
        index,
        &new_node,
    );

    let output_new_addr = helper_0 + depth * two_legs_rows - AB::Expr::ONE;
    let output_new_msg = compute_hasher_word_message::<AB>(
        challenges,
        output_old_label,
        output_new_addr,
        AB::Expr::ZERO,
        &new_root,
    );

    input_old_msg * output_old_msg * input_new_msg * output_new_msg
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
        // Verify operation labels match expected values
        assert_eq!(BITWISE_AND_LABEL, Felt::new(2));
        assert_eq!(BITWISE_XOR_LABEL, Felt::new(6));
        assert_eq!(MEMORY_WRITE_ELEMENT_LABEL, 4);
        assert_eq!(MEMORY_READ_ELEMENT_LABEL, 12);
        assert_eq!(MEMORY_WRITE_WORD_LABEL, 20);
        assert_eq!(MEMORY_READ_WORD_LABEL, 28);
    }

    #[test]
    fn test_memory_label_formula() {
        // Verify: label = 4 + 8*is_read + 16*is_word
        fn label(is_read: u64, is_word: u64) -> u64 {
            4 + 8 * is_read + 16 * is_word
        }

        assert_eq!(label(0, 0), MEMORY_WRITE_ELEMENT_LABEL as u64); // 4
        assert_eq!(label(1, 0), MEMORY_READ_ELEMENT_LABEL as u64); // 12
        assert_eq!(label(0, 1), MEMORY_WRITE_WORD_LABEL as u64); // 20
        assert_eq!(label(1, 1), MEMORY_READ_WORD_LABEL as u64); // 28
    }

    #[test]
    fn test_ace_label() {
        // ACE label: selector = [1, 1, 1, 0], reversed = [0, 1, 1, 1] = 7, +1 = 8
        assert_eq!(ACE_INIT_LABEL, Felt::new(8));
    }

    #[test]
    fn test_kernel_rom_labels() {
        // Kernel ROM call label: selector = [1, 1, 1, 1, 0 | 0], reversed = [0, 0, 1, 1, 1, 1] =
        // 15, +1 = 16
        assert_eq!(KERNEL_PROC_CALL_LABEL, Felt::new(16));

        // Kernel ROM init label: selector = [1, 1, 1, 1, 0 | 1], reversed = [1, 0, 1, 1, 1, 1] =
        // 47, +1 = 48
        assert_eq!(KERNEL_PROC_INIT_LABEL, Felt::new(48));
    }
}
