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
//! ### Hasher Chiplet Messages (16 alphas)
//! Format: header + state where:
//! - header = alphas[0] + alphas[1] * transition_label + alphas[2] * addr + alphas[3] * node_index
//! - state = sum(alphas[4..16] * hasher_state[0..12])
//!
//! ### Bitwise Chiplet Messages (5 alphas)
//! Format: alphas[0] + alphas[1]*label + alphas[2]*a + alphas[3]*b + alphas[4]*z
//!
//! ### Memory Chiplet Messages (6-9 alphas)
//! Element format: alphas[0] + alphas[1]*label + ... + alphas[5]*element
//! Word format: alphas[0] + alphas[1]*label + ... + alphas[8]*word[3]
//!
//! ## References
//! - Air-script: ~/air-script/constraints/chiplets.air
//! - Processor: processor/src/chiplets/aux_trace/bus/
//!
//! TODO(Al): Fix once we switch to all buses starting from 1/0 and ending with aux_finals.

use miden_core::{FMP_ADDR, FMP_INIT_VALUE, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::MidenAirBuilder;
use p3_matrix::Matrix;

use crate::{
    Felt, MainTraceRow,
    constraints::{bus::indices::B_CHIPLETS, chiplets::hasher, stack::op_flags::OpFlags},
    trace::{
        chiplets::{
            NUM_ACE_SELECTORS, NUM_KERNEL_ROM_SELECTORS,
            ace::{
                ACE_INIT_LABEL, CLK_IDX, CTX_IDX, ID_0_IDX, PTR_IDX, READ_NUM_EVAL_IDX,
                SELECTOR_START_IDX,
            },
            bitwise::{self, BITWISE_AND_LABEL, BITWISE_XOR_LABEL},
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
        decoder::{ADDR_COL_IDX, HASHER_STATE_RANGE, USER_OP_HELPERS_OFFSET},
        log_precompile::{
            HELPER_ADDR_IDX, HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE, STACK_COMM_RANGE,
            STACK_R0_RANGE, STACK_R1_RANGE, STACK_TAG_RANGE,
        },
    },
};

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
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Auxiliary trace must be present.
    debug_assert!(
        builder.permutation().height() > 0,
        "Auxiliary trace must be present for chiplets bus constraint"
    );

    // Extract auxiliary trace values.
    let (b_local_val, b_next_val) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        (aux_local[B_CHIPLETS], aux_next[B_CHIPLETS])
    };

    // =========================================================================
    // BOUNDARY CONSTRAINTS
    // =========================================================================
    //
    // The chiplets bus starts at 1. Kernel ROM INIT_LABEL responses multiply in the kernel
    // procedure hashes, so the final value equals reduced_kernel_digests.
    //
    // - FIRST ROW: b_chiplets[0] = 1
    // - LAST ROW: b_chiplets[last] = reduced_kernel_digests (verified via aux_finals)
    //
    // The verifier checks aux_final[b_chiplets] against the expected value computed from
    // kernel hashes provided as variable-length public inputs.
    //
    // =========================================================================

    let one_ef = AB::ExprEF::ONE;
    builder.when_first_row().assert_eq_ext(b_local_val.into(), one_ef.clone());
    // Last row constraint removed - verified via aux_finals against reduced_kernel_digests

    // Get challenges for message encoding and convert to ExprEF
    let challenges = builder.permutation_randomness();
    // We need 16 alphas for hasher messages (4 header + 12 state)
    let alphas: [AB::ExprEF; 16] = [
        challenges[0].into(),
        challenges[1].into(),
        challenges[2].into(),
        challenges[3].into(),
        challenges[4].into(),
        challenges[5].into(),
        challenges[6].into(),
        challenges[7].into(),
        challenges[8].into(),
        challenges[9].into(),
        challenges[10].into(),
        challenges[11].into(),
        challenges[12].into(),
        challenges[13].into(),
        challenges[14].into(),
        challenges[15].into(),
    ];

    // =========================================================================
    // COMPUTE REQUEST MULTIPLIER
    // =========================================================================

    // --- Hasher request flags ---
    let f_hperm: AB::Expr = op_flags.hperm();
    let f_mpverify: AB::Expr = op_flags.mpverify();
    let f_mrupdate: AB::Expr = op_flags.mrupdate();

    // --- Control block flags (all use hasher) ---
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
    let v_hperm = compute_hperm_request::<AB>(local, next, &alphas);
    let v_mpverify = compute_mpverify_request::<AB>(local, &alphas);
    let v_mrupdate = compute_mrupdate_request::<AB>(local, next, &alphas);

    // --- Control block request values ---
    let v_join = compute_control_block_request::<AB>(local, next, &alphas, ControlBlockOp::Join);
    let v_split = compute_control_block_request::<AB>(local, next, &alphas, ControlBlockOp::Split);
    let v_loop = compute_control_block_request::<AB>(local, next, &alphas, ControlBlockOp::Loop);
    let v_call = compute_call_request::<AB>(local, next, &alphas);
    let v_dyn = compute_dyn_request::<AB>(local, next, &alphas);
    let v_dyncall = compute_dyncall_request::<AB>(local, next, &alphas);
    let v_syscall = compute_syscall_request::<AB>(local, next, &alphas);
    let v_span = compute_span_request::<AB>(local, next, &alphas);
    let v_respan = compute_respan_request::<AB>(local, next, &alphas);
    let v_end = compute_end_request::<AB>(local, &alphas);

    // --- Memory request values ---
    let v_mload = compute_memory_element_request::<AB>(local, next, &alphas, true); // is_read = true
    let v_mstore = compute_memory_element_request::<AB>(local, next, &alphas, false); // is_read = false
    let v_mloadw = compute_memory_word_request::<AB>(local, next, &alphas, true); // is_read = true
    let v_mstorew = compute_memory_word_request::<AB>(local, next, &alphas, false); // is_read = false
    let v_hornerbase = compute_hornerbase_request::<AB>(local, &alphas);
    let v_hornerext = compute_hornerext_request::<AB>(local, &alphas);
    let v_mstream = compute_mstream_request::<AB>(local, next, &alphas);
    let v_pipe = compute_pipe_request::<AB>(local, next, &alphas);
    let v_cryptostream = compute_cryptostream_request::<AB>(local, next, &alphas);

    // --- Bitwise request values ---
    let v_u32and = compute_bitwise_request::<AB>(local, next, &alphas, false); // is_xor = false
    let v_u32xor = compute_bitwise_request::<AB>(local, next, &alphas, true); // is_xor = true

    // --- ACE and log_precompile request values ---
    let v_evalcircuit = compute_ace_request::<AB>(local, &alphas);
    let v_logprecompile = compute_log_precompile_request::<AB>(local, next, &alphas);

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

    // --- Get periodic columns we need for hasher cycle detection and bitwise cycle gating ---
    let (cycle_row_0, cycle_row_31, k_transition) = {
        let p = builder.periodic_evals();
        let cycle_row_0: AB::Expr = p[hasher::periodic::P_CYCLE_ROW_0].into();
        let cycle_row_31: AB::Expr = p[hasher::periodic::P_CYCLE_ROW_31].into();
        let k_transition: AB::Expr = p[hasher::periodic::NUM_PERIODIC_COLUMNS + 1].into();
        (cycle_row_0, cycle_row_31, k_transition)
    };

    // --- Chiplet selector flags (from chiplets columns) ---
    let chiplet_s0: AB::Expr = local.chiplets[0].clone().into();
    let chiplet_s1: AB::Expr = local.chiplets[1].clone().into();
    let chiplet_s2: AB::Expr = local.chiplets[2].clone().into();
    let chiplet_s3: AB::Expr = local.chiplets[3].clone().into();
    let chiplet_s4: AB::Expr = local.chiplets[4].clone().into();

    // Hasher chiplet active: chiplet_s0=0
    let is_hasher: AB::Expr = AB::Expr::ONE - chiplet_s0.clone();

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
        local.chiplets[NUM_ACE_SELECTORS + SELECTOR_START_IDX].clone().into();
    let is_ace: AB::Expr = is_ace_row * ace_start_selector;

    // Kernel ROM chiplet active: s0=1, s1=1, s2=1, s3=1, s4=0
    let is_kernel_rom: AB::Expr = chiplet_s0.clone()
        * chiplet_s1.clone()
        * chiplet_s2.clone()
        * chiplet_s3.clone()
        * (AB::Expr::ONE - chiplet_s4.clone());

    // --- Hasher response (complex, depends on cycle position and selectors) ---
    let v_hasher = compute_hasher_response::<AB>(local, next, &alphas, cycle_row_0, cycle_row_31);

    // --- Bitwise response ---
    let v_bitwise = compute_bitwise_response::<AB>(local, &alphas);

    // --- Memory response ---
    let v_memory = compute_memory_response::<AB>(local, &alphas);

    // --- ACE response ---
    let v_ace = compute_ace_response::<AB>(local, &alphas);

    // --- Kernel ROM response ---
    let v_kernel_rom = compute_kernel_rom_response::<AB>(local, &alphas);

    // Convert flags to ExprEF
    // Responses: hasher + bitwise + memory + ACE + kernel ROM contributions, others return 1
    let responses: AB::ExprEF = v_hasher * is_hasher.clone()
        + v_bitwise * is_bitwise_responding.clone()
        + v_memory * is_memory.clone()
        + v_ace * is_ace.clone()
        + v_kernel_rom * is_kernel_rom.clone()
        + (AB::ExprEF::ONE
            - is_hasher
            - is_bitwise_responding
            - is_memory
            - is_ace
            - is_kernel_rom);

    // =========================================================================
    // RUNNING PRODUCT TRANSITION CONSTRAINT
    // =========================================================================
    // b_chiplets' * requests = b_chiplets * responses

    let lhs: AB::ExprEF = b_next_val.into() * requests;
    let rhs: AB::ExprEF = b_local_val.into() * responses;
    builder.when_transition().assert_zero_ext(lhs - rhs);
}

// MESSAGE HELPERS
// ================================================================================================

// BITWISE MESSAGE HELPERS
// ================================================================================================

/// Computes the bitwise request message value.
///
/// Format: alphas[0] + alphas[1]*label + alphas[2]*a + alphas[3]*b + alphas[4]*z
///
/// Stack layout for U32AND/U32XOR: [a, b, ...] -> [z, ...]
fn compute_bitwise_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
    is_xor: bool,
) -> AB::ExprEF {
    let label: Felt = if is_xor { BITWISE_XOR_LABEL } else { BITWISE_AND_LABEL };
    let label: AB::Expr = AB::Expr::from(label);

    // Stack values
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = local.stack[1].clone().into();
    let z: AB::Expr = next.stack[0].clone().into();

    alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * a
        + alphas[3].clone() * b
        + alphas[4].clone() * z
}

/// Computes the bitwise chiplet response message value.
///
/// Format: alphas[0] + alphas[1]*label + alphas[2]*a + alphas[3]*b + alphas[4]*z
fn compute_bitwise_response<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    use crate::trace::chiplets::NUM_BITWISE_SELECTORS;

    // Bitwise chiplet columns start at NUM_BITWISE_SELECTORS=2 in local.chiplets
    let bw_offset = NUM_BITWISE_SELECTORS;

    // Get bitwise operation selector and compute label
    // The AND/XOR selector is at bitwise[0] = local.chiplets[bw_offset]
    // label = (1 - sel) * AND_LABEL + sel * XOR_LABEL
    let sel: AB::Expr = local.chiplets[bw_offset].clone().into();
    let one_minus_sel = AB::Expr::ONE - sel.clone();
    let label = one_minus_sel * AB::Expr::from(BITWISE_AND_LABEL)
        + sel.clone() * AB::Expr::from(BITWISE_XOR_LABEL);

    // Bitwise chiplet data columns (offset by bw_offset + bitwise internal indices)
    let a: AB::Expr = local.chiplets[bw_offset + bitwise::A_COL_IDX].clone().into();
    let b: AB::Expr = local.chiplets[bw_offset + bitwise::B_COL_IDX].clone().into();
    let z: AB::Expr = local.chiplets[bw_offset + bitwise::OUTPUT_COL_IDX].clone().into();

    alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * a
        + alphas[3].clone() * b
        + alphas[4].clone() * z
}

// MEMORY MESSAGE HELPERS
// ================================================================================================

/// Computes the memory word request message value.
///
/// Format: alphas[0] + alphas[1]*label + alphas[2]*ctx + alphas[3]*addr + alphas[4]*clk +
/// alphas[5..9]*word
///
/// Stack layout for MLOADW: [addr, ...] -> [word[0], word[1], word[2], word[3], ...]
/// Stack layout for MSTOREW: [addr, word[0], word[1], word[2], word[3], ...]
fn compute_memory_word_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
    is_read: bool,
) -> AB::ExprEF {
    let label = if is_read {
        MEMORY_READ_WORD_LABEL
    } else {
        MEMORY_WRITE_WORD_LABEL
    };
    let label: AB::Expr = AB::Expr::from_u16(label as u16);

    // Context and clock from system columns
    let ctx: AB::Expr = local.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();

    // Address is at stack[0]
    let addr: AB::Expr = local.stack[0].clone().into();

    // Word values depend on read vs write
    let (w0, w1, w2, w3) = if is_read {
        // MLOADW: word comes from next stack state
        (
            next.stack[0].clone().into(),
            next.stack[1].clone().into(),
            next.stack[2].clone().into(),
            next.stack[3].clone().into(),
        )
    } else {
        // MSTOREW: word comes from current stack[1..5]
        (
            local.stack[1].clone().into(),
            local.stack[2].clone().into(),
            local.stack[3].clone().into(),
            local.stack[4].clone().into(),
        )
    };

    alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * ctx
        + alphas[3].clone() * addr
        + alphas[4].clone() * clk
        + alphas[5].clone() * w0
        + alphas[6].clone() * w1
        + alphas[7].clone() * w2
        + alphas[8].clone() * w3
}

/// Computes the memory element request message value.
///
/// Format: alphas[0] + alphas[1]*label + alphas[2]*ctx + alphas[3]*addr + alphas[4]*clk +
/// alphas[5]*element
fn compute_memory_element_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
    is_read: bool,
) -> AB::ExprEF {
    let label = if is_read {
        MEMORY_READ_ELEMENT_LABEL
    } else {
        MEMORY_WRITE_ELEMENT_LABEL
    };
    let label: AB::Expr = AB::Expr::from_u16(label as u16);

    // Context and clock from system columns
    let ctx: AB::Expr = local.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();

    // Address is at stack[0]
    let addr: AB::Expr = local.stack[0].clone().into();

    // Element value
    let element = if is_read {
        // MLOAD: element comes from next stack[0]
        next.stack[0].clone().into()
    } else {
        // MSTORE: element comes from current stack[1]
        local.stack[1].clone().into()
    };

    alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * ctx
        + alphas[3].clone() * addr
        + alphas[4].clone() * clk
        + alphas[5].clone() * element
}

/// Computes the MSTREAM request message value (two word reads).
fn compute_mstream_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);
    let ctx: AB::Expr = local.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();
    let addr: AB::Expr = local.stack[12].clone().into();
    let four: AB::Expr = AB::Expr::from_u16(4);

    // First word: next.stack[0..4] at addr
    let word1 = [
        next.stack[0].clone().into(),
        next.stack[1].clone().into(),
        next.stack[2].clone().into(),
        next.stack[3].clone().into(),
    ];

    // Second word: next.stack[4..8] at addr + 4
    let word2 = [
        next.stack[4].clone().into(),
        next.stack[5].clone().into(),
        next.stack[6].clone().into(),
        next.stack[7].clone().into(),
    ];

    let msg1 = alphas[0].clone()
        + alphas[1].clone() * label.clone()
        + alphas[2].clone() * ctx.clone()
        + alphas[3].clone() * addr.clone()
        + alphas[4].clone() * clk.clone()
        + alphas[5].clone() * word1[0].clone()
        + alphas[6].clone() * word1[1].clone()
        + alphas[7].clone() * word1[2].clone()
        + alphas[8].clone() * word1[3].clone();

    let msg2 = alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * ctx
        + alphas[3].clone() * (addr + four.clone())
        + alphas[4].clone() * clk
        + alphas[5].clone() * word2[0].clone()
        + alphas[6].clone() * word2[1].clone()
        + alphas[7].clone() * word2[2].clone()
        + alphas[8].clone() * word2[3].clone();

    msg1 * msg2
}

/// Computes the PIPE request message value (two word writes).
fn compute_pipe_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_WRITE_WORD_LABEL as u16);
    let ctx: AB::Expr = local.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();
    let addr: AB::Expr = local.stack[12].clone().into();
    let four: AB::Expr = AB::Expr::from_u16(4);

    // First word to addr: next.stack[0..4]
    let word1 = [
        next.stack[0].clone().into(),
        next.stack[1].clone().into(),
        next.stack[2].clone().into(),
        next.stack[3].clone().into(),
    ];

    // Second word to addr + 4: next.stack[4..8]
    let word2 = [
        next.stack[4].clone().into(),
        next.stack[5].clone().into(),
        next.stack[6].clone().into(),
        next.stack[7].clone().into(),
    ];

    let msg1 = alphas[0].clone()
        + alphas[1].clone() * label.clone()
        + alphas[2].clone() * ctx.clone()
        + alphas[3].clone() * addr.clone()
        + alphas[4].clone() * clk.clone()
        + alphas[5].clone() * word1[0].clone()
        + alphas[6].clone() * word1[1].clone()
        + alphas[7].clone() * word1[2].clone()
        + alphas[8].clone() * word1[3].clone();

    let msg2 = alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * ctx
        + alphas[3].clone() * (addr + four.clone())
        + alphas[4].clone() * clk
        + alphas[5].clone() * word2[0].clone()
        + alphas[6].clone() * word2[1].clone()
        + alphas[7].clone() * word2[2].clone()
        + alphas[8].clone() * word2[3].clone();

    msg1 * msg2
}

/// Computes the CRYPTOSTREAM request value (two word reads + two word writes).
fn compute_cryptostream_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    let read_label: AB::Expr = AB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);
    let write_label: AB::Expr = AB::Expr::from_u16(MEMORY_WRITE_WORD_LABEL as u16);
    let ctx: AB::Expr = local.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();
    let src: AB::Expr = local.stack[12].clone().into();
    let dst: AB::Expr = local.stack[13].clone().into();
    let four: AB::Expr = AB::Expr::from_u16(4);

    let rate: [AB::Expr; 8] = core::array::from_fn(|i| local.stack[i].clone().into());
    let cipher: [AB::Expr; 8] = core::array::from_fn(|i| next.stack[i].clone().into());
    let plain: [AB::Expr; 8] = core::array::from_fn(|i| cipher[i].clone() - rate[i].clone());

    let read_msg1 = alphas[0].clone()
        + alphas[1].clone() * read_label.clone()
        + alphas[2].clone() * ctx.clone()
        + alphas[3].clone() * src.clone()
        + alphas[4].clone() * clk.clone()
        + alphas[5].clone() * plain[0].clone()
        + alphas[6].clone() * plain[1].clone()
        + alphas[7].clone() * plain[2].clone()
        + alphas[8].clone() * plain[3].clone();

    let read_msg2 = alphas[0].clone()
        + alphas[1].clone() * read_label
        + alphas[2].clone() * ctx.clone()
        + alphas[3].clone() * (src + four.clone())
        + alphas[4].clone() * clk.clone()
        + alphas[5].clone() * plain[4].clone()
        + alphas[6].clone() * plain[5].clone()
        + alphas[7].clone() * plain[6].clone()
        + alphas[8].clone() * plain[7].clone();

    let write_msg1 = alphas[0].clone()
        + alphas[1].clone() * write_label.clone()
        + alphas[2].clone() * ctx.clone()
        + alphas[3].clone() * dst.clone()
        + alphas[4].clone() * clk.clone()
        + alphas[5].clone() * cipher[0].clone()
        + alphas[6].clone() * cipher[1].clone()
        + alphas[7].clone() * cipher[2].clone()
        + alphas[8].clone() * cipher[3].clone();

    let write_msg2 = alphas[0].clone()
        + alphas[1].clone() * write_label
        + alphas[2].clone() * ctx
        + alphas[3].clone() * (dst + four)
        + alphas[4].clone() * clk
        + alphas[5].clone() * cipher[4].clone()
        + alphas[6].clone() * cipher[5].clone()
        + alphas[7].clone() * cipher[6].clone()
        + alphas[8].clone() * cipher[7].clone();

    read_msg1 * read_msg2 * write_msg1 * write_msg2
}

/// Computes the HORNERBASE request value (two element reads).
fn compute_hornerbase_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_READ_ELEMENT_LABEL as u16);
    let ctx: AB::Expr = local.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();
    let addr: AB::Expr = local.stack[13].clone().into();
    let one: AB::Expr = AB::Expr::ONE;

    // Helper registers hold eval_point_0 and eval_point_1
    let helper0_idx = USER_OP_HELPERS_OFFSET;
    let helper1_idx = helper0_idx + 1;
    let eval0: AB::Expr = local.decoder[helper0_idx].clone().into();
    let eval1: AB::Expr = local.decoder[helper1_idx].clone().into();

    let msg0 = alphas[0].clone()
        + alphas[1].clone() * label.clone()
        + alphas[2].clone() * ctx.clone()
        + alphas[3].clone() * addr.clone()
        + alphas[4].clone() * clk.clone()
        + alphas[5].clone() * eval0;

    let msg1 = alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * ctx
        + alphas[3].clone() * (addr + one)
        + alphas[4].clone() * clk
        + alphas[5].clone() * eval1;

    msg0 * msg1
}

/// Computes the HORNEREXT request value (one word read).
fn compute_hornerext_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);
    let ctx: AB::Expr = local.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();
    let addr: AB::Expr = local.stack[13].clone().into();

    // Helpers 0..3 hold eval_point_0, eval_point_1, mem_junk_0, mem_junk_1
    let base = USER_OP_HELPERS_OFFSET;
    let word = [
        local.decoder[base].clone().into(),
        local.decoder[base + 1].clone().into(),
        local.decoder[base + 2].clone().into(),
        local.decoder[base + 3].clone().into(),
    ];

    alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * ctx
        + alphas[3].clone() * addr
        + alphas[4].clone() * clk
        + alphas[5].clone() * word[0].clone()
        + alphas[6].clone() * word[1].clone()
        + alphas[7].clone() * word[2].clone()
        + alphas[8].clone() * word[3].clone()
}

/// Computes the memory chiplet response message value.
///
/// The memory chiplet uses different labels for read/write and element/word operations.
/// Address is computed as: word + 2*idx1 + idx0
/// For element access, the correct element is selected based on idx0, idx1.
fn compute_memory_response<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    use crate::trace::chiplets::{NUM_MEMORY_SELECTORS, memory};

    // Memory chiplet columns (offset by NUM_MEMORY_SELECTORS=3 for s0, s1, s2 selectors)
    // local.chiplets is relative to CHIPLETS_OFFSET, memory columns start at index 3
    let mem_offset = NUM_MEMORY_SELECTORS;
    let is_read: AB::Expr = local.chiplets[mem_offset + memory::IS_READ_COL_IDX].clone().into();
    let is_word: AB::Expr =
        local.chiplets[mem_offset + memory::IS_WORD_ACCESS_COL_IDX].clone().into();
    let ctx: AB::Expr = local.chiplets[mem_offset + memory::CTX_COL_IDX].clone().into();
    let word: AB::Expr = local.chiplets[mem_offset + memory::WORD_COL_IDX].clone().into();
    let idx0: AB::Expr = local.chiplets[mem_offset + memory::IDX0_COL_IDX].clone().into();
    let idx1: AB::Expr = local.chiplets[mem_offset + memory::IDX1_COL_IDX].clone().into();
    let clk: AB::Expr = local.chiplets[mem_offset + memory::CLK_COL_IDX].clone().into();

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
    let v0: AB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start].clone().into();
    let v1: AB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 1].clone().into();
    let v2: AB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 2].clone().into();
    let v3: AB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 3].clone().into();

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

    // Element access message: base + element
    // Word access message: base + v0 + v1 + v2 + v3 (with appropriate alphas)
    let base = alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * ctx
        + alphas[3].clone() * addr
        + alphas[4].clone() * clk;

    // Element access: only include the selected element in alpha[5]
    let element_msg = base.clone() + alphas[5].clone() * element;

    // Word access: include all 4 values in alpha[5..9]
    let word_msg = base
        + alphas[5].clone() * v0
        + alphas[6].clone() * v1
        + alphas[7].clone() * v2
        + alphas[8].clone() * v3;

    // Select based on is_word
    element_msg * is_element + word_msg * is_word
}

// HASHER RESPONSE HELPERS
// ================================================================================================

/// Computes the hasher chiplet response message value.
///
/// The hasher responds at two cycle positions:
/// - Row 0: Initialization (f_bp, f_mp, f_mv, f_mu)
/// - Row 31: Output/Absorption (f_hout, f_sout, f_abp)
fn compute_hasher_response<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
    cycle_row_0: AB::Expr,
    cycle_row_31: AB::Expr,
) -> AB::ExprEF {
    use crate::trace::{
        CHIPLETS_OFFSET,
        chiplets::{HASHER_NODE_INDEX_COL_IDX, HASHER_STATE_COL_RANGE},
    };

    let one = AB::Expr::ONE;
    let zero = AB::Expr::ZERO;
    let one_ef = AB::ExprEF::ONE;

    // Hasher is active when chiplets[0] == 0
    let hasher_active: AB::Expr = one.clone() - local.chiplets[0].clone().into();

    // Hasher selectors (when hasher is active, chiplets[0]=0)
    // chiplets[1..4] are the hasher's internal selectors s0, s1, s2
    let hs0: AB::Expr = local.chiplets[1].clone().into();
    let hs1: AB::Expr = local.chiplets[2].clone().into();
    let hs2: AB::Expr = local.chiplets[3].clone().into();

    // Compute operation flags (each flag is active at most once)
    // All hasher flags require hasher_active (chiplets[0] == 0)
    // Row 0 flags:
    // f_bp = hasher_active * cycle_row_0 * s0 * !s1 * !s2
    let f_bp = hasher_active.clone()
        * cycle_row_0.clone()
        * hs0.clone()
        * (one.clone() - hs1.clone())
        * (one.clone() - hs2.clone());
    // f_mp = hasher_active * cycle_row_0 * s0 * !s1 * s2
    let f_mp = hasher_active.clone()
        * cycle_row_0.clone()
        * hs0.clone()
        * (one.clone() - hs1.clone())
        * hs2.clone();
    // f_mv = hasher_active * cycle_row_0 * s0 * s1 * !s2
    let f_mv = hasher_active.clone()
        * cycle_row_0.clone()
        * hs0.clone()
        * hs1.clone()
        * (one.clone() - hs2.clone());
    // f_mu = hasher_active * cycle_row_0 * s0 * s1 * s2
    let f_mu =
        hasher_active.clone() * cycle_row_0.clone() * hs0.clone() * hs1.clone() * hs2.clone();

    // Row 31 flags:
    // f_hout = hasher_active * cycle_row_31 * !s0 * !s1 * !s2
    let f_hout = hasher_active.clone()
        * cycle_row_31.clone()
        * (one.clone() - hs0.clone())
        * (one.clone() - hs1.clone())
        * (one.clone() - hs2.clone());
    // f_sout = hasher_active * cycle_row_31 * !s0 * !s1 * s2
    let f_sout = hasher_active.clone()
        * cycle_row_31.clone()
        * (one.clone() - hs0.clone())
        * (one.clone() - hs1.clone())
        * hs2.clone();
    // f_abp = hasher_active * cycle_row_31 * s0 * !s1 * !s2
    let f_abp = hasher_active.clone()
        * cycle_row_31.clone()
        * hs0.clone()
        * (one.clone() - hs1.clone())
        * (one.clone() - hs2.clone());

    // Get current hasher state (12 elements) and node index
    let state: [AB::Expr; 12] = core::array::from_fn(|i| {
        let col_idx = HASHER_STATE_COL_RANGE.start - CHIPLETS_OFFSET + i;
        local.chiplets[col_idx].clone().into()
    });
    let node_index: AB::Expr =
        local.chiplets[HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET].clone().into();

    // Get next row's hasher state (for f_abp)
    let state_next: [AB::Expr; 12] = core::array::from_fn(|i| {
        let col_idx = HASHER_STATE_COL_RANGE.start - CHIPLETS_OFFSET + i;
        next.chiplets[col_idx].clone().into()
    });

    // Get next row's node_index for computing the node_index bit
    let node_index_next: AB::Expr =
        next.chiplets[HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET].clone().into();

    // addr_next = row + 1 (using clk as proxy since clk = row in the trace)
    let addr_next: AB::Expr = local.clk.clone().into() + one.clone();

    // Build message values for each operation type using canonical labels.
    let label_bp = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + 16);
    let label_mp = AB::Expr::from_u16(MP_VERIFY_LABEL as u16 + 16);
    let label_mv = AB::Expr::from_u16(MR_UPDATE_OLD_LABEL as u16 + 16);
    let label_mu = AB::Expr::from_u16(MR_UPDATE_NEW_LABEL as u16 + 16);
    let label_hout = AB::Expr::from_u16(RETURN_HASH_LABEL as u16 + 32);
    let label_sout = AB::Expr::from_u16(RETURN_STATE_LABEL as u16 + 32);
    let label_abp = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + 32);

    // v_bp: Full state message for f_bp (linear hash / 2-to-1 hash init)
    let v_bp = compute_hasher_message::<AB>(
        alphas,
        label_bp,
        addr_next.clone(),
        node_index.clone(),
        &state,
    );

    // v_sout: Full state message for f_sout (return full state)
    let v_sout = compute_hasher_message::<AB>(
        alphas,
        label_sout,
        addr_next.clone(),
        node_index.clone(),
        &state,
    );

    // v_leaf: Leaf node message (for f_mp, f_mv, f_mu)
    // For Merkle path operations, the leaf is always placed at message positions 4-7.
    // The bit determines which part of the trace state to use:
    // - bit=0: use RATE0 (state[0..4])
    // - bit=1: use RATE1 (state[4..8])
    // The bit can be computed as: bit = node_index - 2 * node_index_next
    let two = AB::Expr::from_u16(2);
    let bit = node_index.clone() - two * node_index_next.clone();

    // Leaf always goes to positions 4-7, but the source depends on bit:
    // bit=0: use state[0..4] (RATE0)
    // bit=1: use state[4..8] (RATE1)
    let leaf_state: [AB::Expr; 12] = [
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        // Positions 4..8: RATE0 when bit=0, RATE1 when bit=1
        (one.clone() - bit.clone()) * state[0].clone() + bit.clone() * state[4].clone(),
        (one.clone() - bit.clone()) * state[1].clone() + bit.clone() * state[5].clone(),
        (one.clone() - bit.clone()) * state[2].clone() + bit.clone() * state[6].clone(),
        (one.clone() - bit.clone()) * state[3].clone() + bit.clone() * state[7].clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
    ];
    let v_mp = compute_hasher_message::<AB>(
        alphas,
        label_mp,
        addr_next.clone(),
        node_index.clone(),
        &leaf_state,
    );
    let v_mv = compute_hasher_message::<AB>(
        alphas,
        label_mv,
        addr_next.clone(),
        node_index.clone(),
        &leaf_state,
    );
    let v_mu = compute_hasher_message::<AB>(
        alphas,
        label_mu,
        addr_next.clone(),
        node_index.clone(),
        &leaf_state,
    );

    // v_hout: Hash output message (for f_hout)
    // Digest from RATE0 (state[0..4]) goes to message positions 4-7
    let result_state: [AB::Expr; 12] = [
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        state[0].clone(),
        state[1].clone(),
        state[2].clone(),
        state[3].clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
    ];
    let v_hout = compute_hasher_message::<AB>(
        alphas,
        label_hout,
        addr_next.clone(),
        node_index.clone(),
        &result_state,
    );

    // v_abp: Absorption message (for f_abp) - uses NEXT row's rate (8 elements)
    // Rate from state_next[0..8] goes to message positions 4-11
    let abp_state: [AB::Expr; 12] = [
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        state_next[0].clone(),
        state_next[1].clone(),
        state_next[2].clone(),
        state_next[3].clone(),
        state_next[4].clone(),
        state_next[5].clone(),
        state_next[6].clone(),
        state_next[7].clone(),
    ];
    let v_abp = compute_hasher_message::<AB>(
        alphas,
        label_abp,
        addr_next.clone(),
        node_index.clone(),
        &abp_state,
    );

    // Sum of all hasher response flags
    let flag_sum = f_bp.clone()
        + f_mp.clone()
        + f_mv.clone()
        + f_mu.clone()
        + f_hout.clone()
        + f_sout.clone()
        + f_abp.clone();

    // Response multiplier from flagged values
    v_bp * f_bp
        + v_mp * f_mp
        + v_mv * f_mv
        + v_mu * f_mu
        + v_hout * f_hout
        + v_sout * f_sout
        + v_abp * f_abp
        + (one_ef - flag_sum)
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
fn compute_hperm_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    use crate::trace::decoder::USER_OP_HELPERS_OFFSET;

    // Hasher address from helper register 0
    let addr: AB::Expr = local.decoder[USER_OP_HELPERS_OFFSET].clone().into();

    // Input state from current stack[0..12]
    let input_state: [AB::Expr; 12] = core::array::from_fn(|i| local.stack[i].clone().into());

    // Output state from next stack[0..12]
    let output_state: [AB::Expr; 12] = core::array::from_fn(|i| next.stack[i].clone().into());

    // Input message: transition_label = LINEAR_HASH_LABEL + 16 = 3 + 16 = 19
    let input_label: AB::Expr = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + 16);
    let node_index_zero: AB::Expr = AB::Expr::ZERO;

    let input_msg = compute_hasher_message::<AB>(
        alphas,
        input_label,
        addr.clone(),
        node_index_zero.clone(),
        &input_state,
    );

    // Output message: transition_label = RETURN_STATE_LABEL + 32 = 9 + 32 = 41
    // addr_next = addr + (HASH_CYCLE_LEN - 1) = addr + 31
    let output_label: AB::Expr = AB::Expr::from_u16(RETURN_STATE_LABEL as u16 + 32);
    let addr_offset: AB::Expr = AB::Expr::from_u16((HASH_CYCLE_LEN - 1) as u16);
    let addr_next = addr + addr_offset;

    let output_msg = compute_hasher_message::<AB>(
        alphas,
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
fn compute_log_precompile_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    // Helper registers
    let helper_base = USER_OP_HELPERS_OFFSET;
    let addr: AB::Expr = local.decoder[helper_base + HELPER_ADDR_IDX].clone().into();

    // CAP_PREV from helper registers (4 lanes)
    let cap_prev: [AB::Expr; 4] = core::array::from_fn(|i| {
        local.decoder[helper_base + HELPER_CAP_PREV_RANGE.start + i].clone().into()
    });

    // COMM and TAG from the current stack
    let comm: [AB::Expr; 4] =
        core::array::from_fn(|i| local.stack[STACK_COMM_RANGE.start + i].clone().into());
    let tag: [AB::Expr; 4] =
        core::array::from_fn(|i| local.stack[STACK_TAG_RANGE.start + i].clone().into());

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
        core::array::from_fn(|i| next.stack[STACK_R0_RANGE.start + i].clone().into());
    let r1: [AB::Expr; 4] =
        core::array::from_fn(|i| next.stack[STACK_R1_RANGE.start + i].clone().into());
    let cap_next: [AB::Expr; 4] =
        core::array::from_fn(|i| next.stack[STACK_CAP_NEXT_RANGE.start + i].clone().into());
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
    let input_label: AB::Expr = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + 16);
    let input_msg = compute_hasher_message::<AB>(
        alphas,
        input_label,
        addr.clone(),
        AB::Expr::ZERO,
        &state_input,
    );

    // Output message: RETURN_STATE_LABEL + 32 with addr offset by HASH_CYCLE_LEN - 1
    let output_label: AB::Expr = AB::Expr::from_u16(RETURN_STATE_LABEL as u16 + 32);
    let addr_offset: AB::Expr = AB::Expr::from_u16((HASH_CYCLE_LEN - 1) as u16);
    let output_msg = compute_hasher_message::<AB>(
        alphas,
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
/// - header = alphas[0] + alphas[1] * transition_label + alphas[2] * addr + alphas[3] * node_index
/// - state = sum(alphas[4..16] * hasher_state[0..12])
fn compute_hasher_message<AB: MidenAirBuilder<F = Felt>>(
    alphas: &[AB::ExprEF],
    transition_label: AB::Expr,
    addr: AB::Expr,
    node_index: AB::Expr,
    state: &[AB::Expr; 12],
) -> AB::ExprEF {
    // Header
    let header = alphas[0].clone()
        + alphas[1].clone() * transition_label
        + alphas[2].clone() * addr
        + alphas[3].clone() * node_index;

    // State contribution
    let mut state_sum = AB::ExprEF::ZERO;
    for i in 0..12 {
        state_sum += alphas[4 + i].clone() * state[i].clone();
    }

    header + state_sum
}

// ACE MESSAGE HELPERS
// ================================================================================================

/// Computes the ACE request message value.
///
/// Format: alphas[0] + alphas[1]*label + alphas[2]*clk + alphas[3]*ctx + alphas[4]*ptr
///         + alphas[5]*num_read_rows + alphas[6]*num_eval_rows
///
/// Stack layout for EVALCIRCUIT: [ptr, num_read_rows, num_eval_rows, ...]
fn compute_ace_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    // Label is ACE_INIT_LABEL
    let label: AB::Expr = AB::Expr::from(ACE_INIT_LABEL);

    // Context and clock from system columns
    let ctx: AB::Expr = local.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();

    // Stack values
    let ptr: AB::Expr = local.stack[0].clone().into();
    let num_read_rows: AB::Expr = local.stack[1].clone().into();
    let num_eval_rows: AB::Expr = local.stack[2].clone().into();

    alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * clk
        + alphas[3].clone() * ctx
        + alphas[4].clone() * ptr
        + alphas[5].clone() * num_read_rows
        + alphas[6].clone() * num_eval_rows
}

/// Computes the ACE chiplet response message value.
///
/// Format: alphas[0] + alphas[1]*label + alphas[2]*clk + alphas[3]*ctx + alphas[4]*ptr
///         + alphas[5]*num_read_rows + alphas[6]*num_eval_rows
///
/// The chiplet reads from its internal columns:
/// - clk from CLK_IDX
/// - ctx from CTX_IDX
/// - ptr from PTR_IDX
/// - num_eval_rows computed from READ_NUM_EVAL_IDX + 1
/// - num_read_rows = id_0 + 1 - num_eval_rows
fn compute_ace_response<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    // Label is ACE_INIT_LABEL
    let label: AB::Expr = AB::Expr::from(ACE_INIT_LABEL);

    // Read values from ACE chiplet columns (offset by NUM_ACE_SELECTORS)
    let clk: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + CLK_IDX].clone().into();
    let ctx: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + CTX_IDX].clone().into();
    let ptr: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + PTR_IDX].clone().into();

    // num_eval_rows = READ_NUM_EVAL_IDX value + 1
    let read_num_eval: AB::Expr =
        local.chiplets[NUM_ACE_SELECTORS + READ_NUM_EVAL_IDX].clone().into();
    let num_eval_rows: AB::Expr = read_num_eval + AB::Expr::ONE;

    // id_0 from ID_0_IDX
    let id_0: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + ID_0_IDX].clone().into();

    // num_read_rows = id_0 + 1 - num_eval_rows
    let num_read_rows: AB::Expr = id_0 + AB::Expr::ONE - num_eval_rows.clone();

    alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * clk
        + alphas[3].clone() * ctx
        + alphas[4].clone() * ptr
        + alphas[5].clone() * num_read_rows
        + alphas[6].clone() * num_eval_rows
}

// KERNEL ROM MESSAGE HELPERS
// ================================================================================================

/// Computes the kernel ROM chiplet response message value.
///
/// Format: alphas[0] + alphas[1]*label + alphas[2]*digest[0] + alphas[3]*digest[1]
///         + alphas[4]*digest[2] + alphas[5]*digest[3]
///
/// The label depends on s_first flag:
/// - s_first=1: KERNEL_PROC_INIT_LABEL (responding to verifier/public input init request)
/// - s_first=0: KERNEL_PROC_CALL_LABEL (responding to decoder SYSCALL request)
fn compute_kernel_rom_response<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    // s_first flag is at CHIPLETS_OFFSET + 5 (after 5 selectors), which is chiplets[5]
    let s_first: AB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS].clone().into();

    // Label depends on s_first:
    // label = s_first * INIT_LABEL + (1 - s_first) * CALL_LABEL
    let init_label: AB::Expr = AB::Expr::from(KERNEL_PROC_INIT_LABEL);
    let call_label: AB::Expr = AB::Expr::from(KERNEL_PROC_CALL_LABEL);
    let label: AB::Expr = s_first.clone() * init_label + (AB::Expr::ONE - s_first) * call_label;

    // Kernel procedure digest (root0..root3) at columns 6, 7, 8, 9 relative to chiplets
    // These are at NUM_KERNEL_ROM_SELECTORS + 1..5 (after s_first which is at +0)
    let root0: AB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS + 1].clone().into();
    let root1: AB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS + 2].clone().into();
    let root2: AB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS + 3].clone().into();
    let root3: AB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS + 4].clone().into();

    alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * root0
        + alphas[3].clone() * root1
        + alphas[4].clone() * root2
        + alphas[5].clone() * root3
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
            ControlBlockOp::Join => miden_core::OPCODE_JOIN,
            ControlBlockOp::Split => miden_core::OPCODE_SPLIT,
            ControlBlockOp::Loop => miden_core::OPCODE_LOOP,
            ControlBlockOp::Call => miden_core::OPCODE_CALL,
            ControlBlockOp::Syscall => miden_core::OPCODE_SYSCALL,
        }
    }
}

/// Computes the control block request message value for JOIN, SPLIT, LOOP operations.
///
/// Format follows ControlBlockRequestMessage from processor:
/// - header = alphas[0] + alphas[1] * transition_label + alphas[2] * addr_next
/// - state = 12-lane sponge with 8-element decoder hasher state as rate + opcode as domain
///
/// The message reconstructs:
/// - transition_label = LINEAR_HASH_LABEL + 16 = 3 + 16 = 19
/// - addr_next = decoder address at next row (from next row's addr column)
/// - hasher_state = rate lanes from decoder hasher columns + opcode in capacity domain position
fn compute_control_block_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
    op: ControlBlockOp,
) -> AB::ExprEF {
    // transition_label = LINEAR_HASH_LABEL + 16 = 19
    let transition_label: AB::Expr = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + 16);

    // addr_next = next row's decoder address
    let addr_next: AB::Expr = next.decoder[ADDR_COL_IDX].clone().into();

    // Get decoder hasher state (8 elements)
    let hasher_state: [AB::Expr; 8] =
        core::array::from_fn(|i| local.decoder[HASHER_STATE_RANGE.start + i].clone().into());

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

    compute_hasher_message::<AB>(alphas, transition_label, addr_next, AB::Expr::ZERO, &state)
}

/// Computes the CALL request message value.
///
/// CALL sends:
/// 1. Control block request (with decoder hasher state)
/// 2. FMP initialization write request (to set up new execution context)
fn compute_call_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    // Control block request
    let control_req =
        compute_control_block_request::<AB>(local, next, alphas, ControlBlockOp::Call);

    // FMP initialization write request
    let fmp_req = compute_fmp_write_request::<AB>(local, next, alphas);

    control_req * fmp_req
}

/// Computes the DYN request message value.
///
/// DYN sends:
/// 1. Control block request (with zeros for hasher state since callee is dynamic)
/// 2. Memory read request for callee hash from stack[0]
fn compute_dyn_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    // Control block request with zeros for hasher state (callee is dynamic)
    let control_req =
        compute_control_block_request_zeros::<AB>(local, next, alphas, miden_core::OPCODE_DYN);

    // Memory read for callee hash (word read from stack[0] address)
    let callee_hash_req = compute_dyn_callee_hash_read::<AB>(local, alphas);

    control_req * callee_hash_req
}

/// Computes the DYNCALL request message value.
///
/// DYNCALL sends:
/// 1. Control block request (with zeros for hasher state since callee is dynamic)
/// 2. Memory read request for callee hash from stack[0]
/// 3. FMP initialization write request
fn compute_dyncall_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    // Control block request with zeros for hasher state (callee is dynamic)
    let control_req =
        compute_control_block_request_zeros::<AB>(local, next, alphas, miden_core::OPCODE_DYNCALL);

    // Memory read for callee hash (word read from stack[0] address)
    let callee_hash_req = compute_dyn_callee_hash_read::<AB>(local, alphas);

    // FMP initialization write request
    let fmp_req = compute_fmp_write_request::<AB>(local, next, alphas);

    control_req * callee_hash_req * fmp_req
}

/// Computes the SYSCALL request message value.
///
/// SYSCALL sends:
/// 1. Control block request (with decoder hasher state)
/// 2. Kernel ROM lookup request (to verify kernel procedure)
fn compute_syscall_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    // Control block request
    let control_req =
        compute_control_block_request::<AB>(local, next, alphas, ControlBlockOp::Syscall);

    // Kernel ROM lookup request (digest from first 4 elements of decoder hasher state)
    let root0: AB::Expr = local.decoder[HASHER_STATE_RANGE.start].clone().into();
    let root1: AB::Expr = local.decoder[HASHER_STATE_RANGE.start + 1].clone().into();
    let root2: AB::Expr = local.decoder[HASHER_STATE_RANGE.start + 2].clone().into();
    let root3: AB::Expr = local.decoder[HASHER_STATE_RANGE.start + 3].clone().into();

    let kernel_req = alphas[0].clone()
        + alphas[1].clone() * AB::Expr::from(KERNEL_PROC_CALL_LABEL)
        + alphas[2].clone() * root0
        + alphas[3].clone() * root1
        + alphas[4].clone() * root2
        + alphas[5].clone() * root3;

    control_req * kernel_req
}

/// Computes the SPAN block request message value.
///
/// Format: header + full 12-lane sponge state (8 rate lanes + 4 capacity lanes zeroed)
fn compute_span_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    // transition_label = LINEAR_HASH_LABEL + 16 = 19
    let transition_label: AB::Expr = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + 16);

    // addr_next = next row's decoder address
    let addr_next: AB::Expr = next.decoder[ADDR_COL_IDX].clone().into();

    // Get decoder hasher state (8 elements)
    let hasher_state: [AB::Expr; 8] =
        core::array::from_fn(|i| local.decoder[HASHER_STATE_RANGE.start + i].clone().into());

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

    compute_hasher_message::<AB>(alphas, transition_label, addr_next, AB::Expr::ZERO, &state)
}

/// Computes the RESPAN block request message value.
///
/// Rate goes to message positions 4-11, which uses alphas[8..16].
fn compute_respan_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    // transition_label = LINEAR_HASH_LABEL + 32 = 35
    let transition_label: AB::Expr = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + 32);

    // RESPAN message uses addr_next - 1, where addr_next is the next row's decoder address
    let addr_next: AB::Expr = next.decoder[ADDR_COL_IDX].clone().into();
    let addr_for_msg = addr_next - AB::Expr::ONE;

    // Get decoder hasher state (8 elements)
    let hasher_state: [AB::Expr; 8] =
        core::array::from_fn(|i| local.decoder[HASHER_STATE_RANGE.start + i].clone().into());

    // Header: alphas[0] + alphas[1] * transition_label + alphas[2] * (addr_next - 1)
    let header =
        alphas[0].clone() + alphas[1].clone() * transition_label + alphas[2].clone() * addr_for_msg;

    // Rate goes to message positions 4-11, uses alphas[8..16]
    let mut state_sum = AB::ExprEF::ZERO;
    for i in 0..8 {
        state_sum += alphas[8 + i].clone() * hasher_state[i].clone();
    }

    header + state_sum
}

/// Computes the END block request message value.
///
/// Digest goes to message positions 4-7, which uses alphas[8..12].
fn compute_end_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    // transition_label = RETURN_HASH_LABEL + 32 = 1 + 32 = 33
    let transition_label: AB::Expr = AB::Expr::from_u16(RETURN_HASH_LABEL as u16 + 32);

    // addr = decoder.addr + (HASH_CYCLE_LEN - 1) = addr + 31
    let addr: AB::Expr = local.decoder[ADDR_COL_IDX].clone().into()
        + AB::Expr::from_u16((HASH_CYCLE_LEN - 1) as u16);

    // Get digest from decoder hasher state (first 4 elements)
    let digest: [AB::Expr; 4] =
        core::array::from_fn(|i| local.decoder[HASHER_STATE_RANGE.start + i].clone().into());

    // Header
    let header =
        alphas[0].clone() + alphas[1].clone() * transition_label + alphas[2].clone() * addr;

    // Digest goes to message positions 4-7, uses alphas[8..12]
    header
        + alphas[8].clone() * digest[0].clone()
        + alphas[9].clone() * digest[1].clone()
        + alphas[10].clone() * digest[2].clone()
        + alphas[11].clone() * digest[3].clone()
}

/// Computes control block request with zeros for hasher state (for DYN/DYNCALL).
fn compute_control_block_request_zeros<AB: MidenAirBuilder<F = Felt>>(
    _local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
    opcode: u8,
) -> AB::ExprEF {
    // transition_label = LINEAR_HASH_LABEL + 16 = 19
    let transition_label: AB::Expr = AB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + 16);

    // addr_next = next row's decoder address
    let addr_next: AB::Expr = next.decoder[ADDR_COL_IDX].clone().into();

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

    compute_hasher_message::<AB>(alphas, transition_label, addr_next, AB::Expr::ZERO, &state)
}

/// Computes the FMP initialization write request.
///
/// This writes FMP_INIT_VALUE to FMP_ADDR in the new context.
fn compute_fmp_write_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_WRITE_ELEMENT_LABEL as u16);

    // ctx from next row (new execution context)
    let ctx: AB::Expr = next.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();
    let addr: AB::Expr = AB::Expr::from(FMP_ADDR);
    let element: AB::Expr = AB::Expr::from(FMP_INIT_VALUE);

    alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * ctx
        + alphas[3].clone() * addr
        + alphas[4].clone() * clk
        + alphas[5].clone() * element
}

/// Computes the callee hash read request for DYN/DYNCALL.
///
/// Reads a word from the address at stack[0] containing the callee hash.
fn compute_dyn_callee_hash_read<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    let label: AB::Expr = AB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);

    let ctx: AB::Expr = local.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();
    let addr: AB::Expr = local.stack[0].clone().into();

    // The callee hash is read into decoder hasher state first half
    let w0: AB::Expr = local.decoder[HASHER_STATE_RANGE.start].clone().into();
    let w1: AB::Expr = local.decoder[HASHER_STATE_RANGE.start + 1].clone().into();
    let w2: AB::Expr = local.decoder[HASHER_STATE_RANGE.start + 2].clone().into();
    let w3: AB::Expr = local.decoder[HASHER_STATE_RANGE.start + 3].clone().into();

    alphas[0].clone()
        + alphas[1].clone() * label
        + alphas[2].clone() * ctx
        + alphas[3].clone() * addr
        + alphas[4].clone() * clk
        + alphas[5].clone() * w0
        + alphas[6].clone() * w1
        + alphas[7].clone() * w2
        + alphas[8].clone() * w3
}

// MPVERIFY/MRUPDATE REQUEST HELPERS
// ================================================================================================

/// Computes the MPVERIFY request message value.
///
/// MPVERIFY sends two messages:
/// 1. Input: node value at RATE1 (indices 4..8)
/// 2. Output: root value at RATE1 (indices 4..8)
fn compute_mpverify_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    use crate::trace::decoder::USER_OP_HELPERS_OFFSET;

    let helper_0: AB::Expr = local.decoder[USER_OP_HELPERS_OFFSET].clone().into();
    let merkle_cycle_len: AB::Expr = AB::Expr::from_u16(HASH_CYCLE_LEN as u16);

    // Stack layout: [node_value0..3, node_depth, node_index, root0..3, ...]
    let node_value: [AB::Expr; 4] = core::array::from_fn(|i| local.stack[i].clone().into());
    let node_depth: AB::Expr = local.stack[4].clone().into();
    let node_index: AB::Expr = local.stack[5].clone().into();
    let root: [AB::Expr; 4] = core::array::from_fn(|i| local.stack[6 + i].clone().into());

    // Node value goes to message positions 4-7 (maps to alphas[8..12])
    let input_state: [AB::Expr; 12] = [
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        node_value[0].clone(),
        node_value[1].clone(),
        node_value[2].clone(),
        node_value[3].clone(),
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];

    let input_label: AB::Expr = AB::Expr::from_u16(MP_VERIFY_LABEL as u16 + 16);
    let input_msg = compute_hasher_message::<AB>(
        alphas,
        input_label,
        helper_0.clone(),
        node_index.clone(),
        &input_state,
    );

    // Root value goes to message positions 4-7 (maps to alphas[8..12])
    let output_state: [AB::Expr; 12] = [
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        root[0].clone(),
        root[1].clone(),
        root[2].clone(),
        root[3].clone(),
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];

    // addr_next = helper_0 + node_depth * merkle_cycle_len - 1
    let output_addr = helper_0 + node_depth * merkle_cycle_len - AB::Expr::ONE;
    let output_label: AB::Expr = AB::Expr::from_u16(RETURN_HASH_LABEL as u16 + 32);
    let output_msg = compute_hasher_message::<AB>(
        alphas,
        output_label,
        output_addr,
        AB::Expr::ZERO,
        &output_state,
    );

    input_msg * output_msg
}

/// Computes the MRUPDATE request message value.
///
/// MRUPDATE sends four messages:
/// 1. Input old: old node value at RATE0 (positions 0-3 in LE layout)
/// 2. Output old: old root at RATE0
/// 3. Input new: new node value at RATE0
/// 4. Output new: new root at RATE0
fn compute_mrupdate_request<AB: MidenAirBuilder<F = Felt>>(
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    alphas: &[AB::ExprEF],
) -> AB::ExprEF {
    use crate::trace::decoder::USER_OP_HELPERS_OFFSET;

    let helper_0: AB::Expr = local.decoder[USER_OP_HELPERS_OFFSET].clone().into();
    let merkle_cycle_len: AB::Expr = AB::Expr::from_u16(HASH_CYCLE_LEN as u16);
    let two_merkle_cycles: AB::Expr = merkle_cycle_len.clone() + merkle_cycle_len.clone();

    // Stack layout: [old_node0..3, depth, index, old_root0..3, new_node0..3, ...]
    let old_node: [AB::Expr; 4] = core::array::from_fn(|i| local.stack[i].clone().into());
    let depth: AB::Expr = local.stack[4].clone().into();
    let index: AB::Expr = local.stack[5].clone().into();
    let old_root: [AB::Expr; 4] = core::array::from_fn(|i| local.stack[6 + i].clone().into());
    let new_node: [AB::Expr; 4] = core::array::from_fn(|i| local.stack[10 + i].clone().into());
    // New root is at next.stack[0..4]
    let new_root: [AB::Expr; 4] = core::array::from_fn(|i| next.stack[i].clone().into());

    // Old node goes to message positions 4-7
    let old_node_state: [AB::Expr; 12] = [
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        old_node[0].clone(),
        old_node[1].clone(),
        old_node[2].clone(),
        old_node[3].clone(),
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];
    let input_old_label: AB::Expr = AB::Expr::from_u16(MR_UPDATE_OLD_LABEL as u16 + 16);
    let input_old_msg = compute_hasher_message::<AB>(
        alphas,
        input_old_label,
        helper_0.clone(),
        index.clone(),
        &old_node_state,
    );

    // Old root goes to message positions 4-7
    let old_root_state: [AB::Expr; 12] = [
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        old_root[0].clone(),
        old_root[1].clone(),
        old_root[2].clone(),
        old_root[3].clone(),
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];
    let output_old_addr =
        helper_0.clone() + depth.clone() * merkle_cycle_len.clone() - AB::Expr::ONE;
    let output_old_label: AB::Expr = AB::Expr::from_u16(RETURN_HASH_LABEL as u16 + 32);
    let output_old_msg = compute_hasher_message::<AB>(
        alphas,
        output_old_label.clone(),
        output_old_addr,
        AB::Expr::ZERO,
        &old_root_state,
    );

    // New node goes to message positions 4-7
    let new_node_state: [AB::Expr; 12] = [
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        new_node[0].clone(),
        new_node[1].clone(),
        new_node[2].clone(),
        new_node[3].clone(),
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];
    let input_new_addr = helper_0.clone() + depth.clone() * merkle_cycle_len.clone();
    let input_new_label: AB::Expr = AB::Expr::from_u16(MR_UPDATE_NEW_LABEL as u16 + 16);
    let input_new_msg = compute_hasher_message::<AB>(
        alphas,
        input_new_label,
        input_new_addr,
        index,
        &new_node_state,
    );

    // New root goes to message positions 4-7
    let new_root_state: [AB::Expr; 12] = [
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        new_root[0].clone(),
        new_root[1].clone(),
        new_root[2].clone(),
        new_root[3].clone(),
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];
    let output_new_addr = helper_0 + depth * two_merkle_cycles - AB::Expr::ONE;
    let output_new_msg = compute_hasher_message::<AB>(
        alphas,
        output_old_label,
        output_new_addr,
        AB::Expr::ZERO,
        &new_root_state,
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
