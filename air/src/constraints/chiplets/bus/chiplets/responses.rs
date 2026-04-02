//! Response value computations for the chiplets bus.
//!
//! Each chiplet row contributes a response message to the chiplets bus. This module computes
//! those message values, organized by chiplet type.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use super::{
    TRANSITION_LINEAR_HASH, TRANSITION_LINEAR_HASH_ABP, TRANSITION_MP_VERIFY,
    TRANSITION_MR_UPDATE_NEW, TRANSITION_MR_UPDATE_OLD, TRANSITION_RETURN_HASH,
    TRANSITION_RETURN_STATE,
    requests::{encode_hasher_rate, encode_hasher_state, encode_hasher_word},
};
use crate::{
    Felt, MainTraceRow, MidenAirBuilder,
    constraints::{
        chiplets::{bitwise::P_BITWISE_K_TRANSITION, hasher, selectors::ChipletSelectors},
        constants::*,
        utils::BoolNot,
    },
    trace::{
        Challenges,
        bus_types::CHIPLETS_BUS,
        chiplets::{
            ace::ACE_INIT_LABEL,
            bitwise::{BITWISE_AND_LABEL, BITWISE_XOR_LABEL},
            kernel_rom::{KERNEL_PROC_CALL_LABEL, KERNEL_PROC_INIT_LABEL},
            memory::{
                MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL, MEMORY_WRITE_ELEMENT_LABEL,
                MEMORY_WRITE_WORD_LABEL,
            },
        },
    },
};

// FULL RESPONSE MULTIPLIER
// ================================================================================================

/// Computes the full response multiplier for the chiplets bus.
///
/// Returns `sum(flag_i * value_i) + (1 - sum(flag_i))` where each `(flag_i, value_i)` pair
/// corresponds to a chiplet row that sends a response message.
pub fn compute_response_multiplier<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    selectors: &ChipletSelectors<AB::Expr>,
) -> AB::ExprEF
where
    AB: MidenAirBuilder,
{
    // --- Periodic columns for hasher cycle detection and bitwise gating ---
    let (cycle_row_0, cycle_row_31, k_transition) = {
        let p = builder.periodic_values();
        let cycle_row_0 = p[hasher::periodic::P_CYCLE_ROW_0];
        let cycle_row_31 = p[hasher::periodic::P_CYCLE_ROW_31];
        let k_transition = p[P_BITWISE_K_TRANSITION];
        (cycle_row_0, cycle_row_31, k_transition)
    };

    // --- Response flags ---
    let is_bitwise_responding: AB::Expr =
        selectors.bitwise.is_active.clone() * k_transition.into().not();
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
        cycle_row_0.into(),
        cycle_row_31.into(),
    );

    // Bitwise response
    let v_bitwise = {
        let bw = local.bitwise();
        let sel: AB::Expr = bw.op_flag.into();
        let label = sel.not() * BITWISE_AND_LABEL + sel.clone() * BITWISE_XOR_LABEL;
        let a: AB::Expr = bw.a.into();
        let b: AB::Expr = bw.b.into();
        let z: AB::Expr = bw.output.into();
        challenges.encode(CHIPLETS_BUS, [label, a, b, z])
    };

    // Memory response
    let v_memory = compute_memory_response::<AB>(local, challenges);

    // ACE response
    let v_ace = {
        let ace = local.ace();
        let label: AB::Expr = ACE_INIT_LABEL.into();
        let clk: AB::Expr = ace.clk.into();
        let ctx: AB::Expr = ace.ctx.into();
        let ptr: AB::Expr = ace.ptr.into();
        let num_eval_rows: AB::Expr = ace.read().num_eval + F_1;
        let num_read_rows: AB::Expr = ace.read().id_0 + F_1 - num_eval_rows.clone();
        challenges.encode(CHIPLETS_BUS, [label, clk, ctx, ptr, num_read_rows, num_eval_rows])
    };

    // Kernel ROM response
    let v_kernel_rom = {
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
    };

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

// HASHER RESPONSE
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
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
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
    let v_bp = encode_hasher_state::<AB>(
        challenges,
        TRANSITION_LINEAR_HASH.into(),
        addr_next.clone(),
        node_index.into(),
        h.state.map(Into::into),
    );

    // v_sout: Full state message (return full state)
    let v_sout = encode_hasher_state::<AB>(
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
    let v_mp = encode_hasher_word::<AB>(
        challenges,
        TRANSITION_MP_VERIFY.into(),
        addr_next.clone(),
        node_index.into(),
        leaf_word.clone(),
    );
    let v_mv = encode_hasher_word::<AB>(
        challenges,
        TRANSITION_MR_UPDATE_OLD.into(),
        addr_next.clone(),
        node_index.into(),
        leaf_word.clone(),
    );
    let v_mu = encode_hasher_word::<AB>(
        challenges,
        TRANSITION_MR_UPDATE_NEW.into(),
        addr_next.clone(),
        node_index.into(),
        leaf_word,
    );

    // v_hout: Hash output (digest from RATE0)
    let v_hout = encode_hasher_word::<AB>(
        challenges,
        TRANSITION_RETURN_HASH.into(),
        addr_next.clone(),
        node_index.into(),
        array::from_fn(|i| h.state[i].into()),
    );

    // v_abp: Absorption (next row's rate)
    let v_abp = encode_hasher_rate::<AB>(
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

// MEMORY RESPONSE
// ================================================================================================

/// Computes the memory chiplet response.
///
/// The memory chiplet uses different labels for read/write and element/word operations.
/// For element access, the correct element is selected based on idx0, idx1.
fn compute_memory_response<AB: MidenAirBuilder>(
    local: &MainTraceRow<AB::Var>,
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
