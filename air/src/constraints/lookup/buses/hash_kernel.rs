//! Hash-kernel virtual table bus (C2 / `BUS_SIBLING_TABLE` + `BUS_CHIPLETS` on the same
//! column).
//!
//! The sibling Merkle-path table plus two ACE memory reads.
//!
//! Sibling-table handling: the bit-selected β layout is split into [`SiblingMsgBitZero`] /
//! [`SiblingMsgBitOne`], each with its own sparse β layout. The single bit-muxed
//! insert/remove pair becomes four gated interactions:
//!
//! - `add(f_mv·(1-bit), SiblingMsgBitZero)` and `add(f_mv·bit, SiblingMsgBitOne)` for the
//!   insertion side,
//! - `remove(f_mu·(1-bit), SiblingMsgBitZero)` and `remove(f_mu·bit, SiblingMsgBitOne)` for
//!   the removal side.
//!
//! These four interactions sum to the same `(U_g, V_g)` as the original bit-muxed pair.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt, MainTraceRow,
    constraints::{
        chiplets::hasher,
        logup_msg::{MemoryHeader, MemoryMsg, SiblingMsgBitOne, SiblingMsgBitZero},
        lookup::{LookupBuilder, LookupColumn, LookupGroup},
    },
    trace::{
        CHIPLETS_OFFSET,
        chiplets::{
            HASHER_NODE_INDEX_COL_IDX, HASHER_SELECTOR_COL_RANGE, HASHER_STATE_COL_RANGE,
            NUM_ACE_SELECTORS,
            ace::{
                ACE_INSTRUCTION_ID1_OFFSET, ACE_INSTRUCTION_ID2_OFFSET, CLK_IDX, CTX_IDX,
                EVAL_OP_IDX, ID_1_IDX, ID_2_IDX, PTR_IDX, SELECTOR_BLOCK_IDX, V_0_0_IDX, V_0_1_IDX,
                V_1_0_IDX, V_1_1_IDX,
            },
            memory::{MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL},
        },
    },
};

// Chiplet-local column offsets (relative to `local.chiplets[]`).
const S_START: usize = HASHER_SELECTOR_COL_RANGE.start - CHIPLETS_OFFSET;
const H_START: usize = HASHER_STATE_COL_RANGE.start - CHIPLETS_OFFSET;
const IDX_COL: usize = HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET;

/// Emit the hash-kernel virtual table bus (C2).
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_hash_kernel_table<LB>(
    builder: &mut LB,
    local: &MainTraceRow<LB::Var>,
    next: &MainTraceRow<LB::Var>,
) where
    LB: LookupBuilder<F = Felt>,
{
    // Periodic values (same indices as the legacy `enforce_chiplet`).
    let (cycle_row_0, cycle_row_31) = {
        let p = builder.periodic_values();
        let cycle_row_0: LB::Expr = p[hasher::periodic::P_CYCLE_ROW_0].into();
        let cycle_row_31: LB::Expr = p[hasher::periodic::P_CYCLE_ROW_31].into();
        (cycle_row_0, cycle_row_31)
    };

    // Chiplet selectors.
    let s0: LB::Expr = local.chiplets[0].into();
    let s1: LB::Expr = local.chiplets[1].into();
    let s2: LB::Expr = local.chiplets[2].into();
    let s3: LB::Expr = local.chiplets[3].into();

    let is_hasher: LB::Expr = LB::Expr::ONE - s0.clone();

    // Hasher internal selectors.
    let hs0: LB::Expr = local.chiplets[S_START].into();
    let hs1: LB::Expr = local.chiplets[S_START + 1].into();
    let hs2: LB::Expr = local.chiplets[S_START + 2].into();

    // Hasher state and node index.
    let h: [LB::Expr; 12] = array::from_fn(|i| local.chiplets[H_START + i].into());
    let h_next: [LB::Expr; 12] = array::from_fn(|i| next.chiplets[H_START + i].into());
    let node_index: LB::Expr = local.chiplets[IDX_COL].into();
    let node_index_next: LB::Expr = next.chiplets[IDX_COL].into();

    // bit = node_index - 2 * node_index_next (mirrors `g_hash_kernel`).
    let bit: LB::Expr = node_index.clone() - node_index_next.double();
    let one_minus_bit: LB::Expr = LB::Expr::ONE - bit.clone();

    // Sibling-table flags.
    let f_mv: LB::Expr = is_hasher.clone()
        * hasher::flags::f_mv(cycle_row_0.clone(), hs0.clone(), hs1.clone(), hs2.clone());
    let f_mu: LB::Expr = is_hasher.clone()
        * hasher::flags::f_mu(cycle_row_0.clone(), hs0.clone(), hs1.clone(), hs2.clone());
    let f_mva: LB::Expr = is_hasher.clone()
        * hasher::flags::f_mva(cycle_row_31.clone(), hs0.clone(), hs1.clone(), hs2.clone());
    let f_mua: LB::Expr = is_hasher * hasher::flags::f_mua(cycle_row_31, hs0, hs1, hs2);

    // SiblingMsg's two bit-variants use the current-row hasher state for (f_mv, f_mu) and
    // the next-row hasher state for (f_mva, f_mua). See the legacy `g_hash_kernel`.
    let sib_lo_curr: [LB::Expr; 4] = array::from_fn(|i| h[i].clone());
    let sib_hi_curr: [LB::Expr; 4] = array::from_fn(|i| h[4 + i].clone());
    let sib_lo_next: [LB::Expr; 4] = array::from_fn(|i| h_next[i].clone());
    let sib_hi_next: [LB::Expr; 4] = array::from_fn(|i| h_next[4 + i].clone());

    // ACE flags and ace memory read payloads.
    let is_ace_row: LB::Expr = s0 * s1 * s2 * (LB::Expr::ONE - s3);
    let block_sel: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + SELECTOR_BLOCK_IDX].into();
    let f_ace_read: LB::Expr = is_ace_row.clone() * (LB::Expr::ONE - block_sel.clone());
    let f_ace_eval: LB::Expr = is_ace_row * block_sel;

    let ace_clk: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + CLK_IDX].into();
    let ace_ctx: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + CTX_IDX].into();
    let ace_ptr: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + PTR_IDX].into();

    // ACE read rows expose a 4-element word pulled from the V_*_* cells.
    let ace_read_word: [LB::Expr; 4] = [
        local.chiplets[NUM_ACE_SELECTORS + V_0_0_IDX].into(),
        local.chiplets[NUM_ACE_SELECTORS + V_0_1_IDX].into(),
        local.chiplets[NUM_ACE_SELECTORS + V_1_0_IDX].into(),
        local.chiplets[NUM_ACE_SELECTORS + V_1_1_IDX].into(),
    ];

    // ACE eval rows combine id_1 / id_2 / eval_op into a single element.
    let id_1: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + ID_1_IDX].into();
    let id_2: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + ID_2_IDX].into();
    let eval_op: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + EVAL_OP_IDX].into();
    let ace_eval_element: LB::Expr = id_1
        + id_2 * LB::Expr::from(ACE_INSTRUCTION_ID1_OFFSET)
        + (eval_op + LB::Expr::ONE) * LB::Expr::from(ACE_INSTRUCTION_ID2_OFFSET);

    builder.column(|col| {
        col.group(|g| {
            // MV (+1) and MU (-1) share `sibling_curr` — split by bit into two ME halves.
            let node_curr = node_index.clone();
            let sib_lo = sib_lo_curr.clone();
            let sib_hi = sib_hi_curr.clone();
            let one_minus_bit_mv = one_minus_bit.clone();
            g.add(f_mv.clone() * one_minus_bit_mv, move || SiblingMsgBitZero {
                node_index: node_curr,
                h_hi: sib_hi,
            });
            let node_curr = node_index.clone();
            let sib_lo_b1 = sib_lo.clone();
            let bit_mv = bit.clone();
            g.add(f_mv * bit_mv, move || SiblingMsgBitOne {
                node_index: node_curr,
                h_lo: sib_lo_b1,
            });
            let node_curr = node_index.clone();
            let sib_hi_2 = sib_hi_curr;
            let one_minus_bit_mu = one_minus_bit.clone();
            g.remove(f_mu.clone() * one_minus_bit_mu, move || SiblingMsgBitZero {
                node_index: node_curr,
                h_hi: sib_hi_2,
            });
            let node_curr = node_index.clone();
            let sib_lo_b1_2 = sib_lo_curr;
            let bit_mu = bit.clone();
            g.remove(f_mu * bit_mu, move || SiblingMsgBitOne {
                node_index: node_curr,
                h_lo: sib_lo_b1_2,
            });

            // MVA (+1) and MUA (-1) share `sibling_next` — same pattern against the next
            // row's hasher state.
            let node_next = node_index.clone();
            let sib_hi_n = sib_hi_next.clone();
            let one_minus_bit_mva = one_minus_bit.clone();
            g.add(f_mva.clone() * one_minus_bit_mva, move || SiblingMsgBitZero {
                node_index: node_next,
                h_hi: sib_hi_n,
            });
            let node_next = node_index.clone();
            let sib_lo_n = sib_lo_next.clone();
            let bit_mva = bit.clone();
            g.add(f_mva * bit_mva, move || SiblingMsgBitOne {
                node_index: node_next,
                h_lo: sib_lo_n,
            });
            let node_next = node_index.clone();
            let sib_hi_n2 = sib_hi_next;
            let one_minus_bit_mua = one_minus_bit;
            g.remove(f_mua.clone() * one_minus_bit_mua, move || SiblingMsgBitZero {
                node_index: node_next,
                h_hi: sib_hi_n2,
            });
            let node_next = node_index;
            let sib_lo_n2 = sib_lo_next;
            g.remove(f_mua * bit, move || SiblingMsgBitOne {
                node_index: node_next,
                h_lo: sib_lo_n2,
            });

            // ACE read: word read on READ rows.
            let ace_clk_r = ace_clk.clone();
            let ace_ctx_r = ace_ctx.clone();
            let ace_ptr_r = ace_ptr.clone();
            g.remove(f_ace_read, move || MemoryMsg::Word {
                op_value: MEMORY_READ_WORD_LABEL as u16,
                header: MemoryHeader {
                    ctx: ace_ctx_r,
                    addr: ace_ptr_r,
                    clk: ace_clk_r,
                },
                word: ace_read_word,
            });

            // ACE eval: element read on EVAL rows.
            g.remove(f_ace_eval, move || MemoryMsg::Element {
                op_value: MEMORY_READ_ELEMENT_LABEL as u16,
                header: MemoryHeader {
                    ctx: ace_ctx,
                    addr: ace_ptr,
                    clk: ace_clk,
                },
                element: ace_eval_element,
            });
        });
    });
}
