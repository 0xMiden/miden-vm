//! Hash-kernel virtual table bus (C2 / `BUS_SIBLING_TABLE` + `BUS_CHIPLETS`).
//!
//! Combines two tables on a single LogUp column:
//!
//! 1. **Sibling table** (`BUS_SIBLING_TABLE`) — Merkle update siblings. On hasher controller input
//!    rows with `s0·s1 = 1`, `s2` distinguishes MU (new path, removes siblings) from MV (old path,
//!    adds siblings). The direction bit `b = node_index − 2·node_index_next` selects which half of
//!    `rate = h[0..8]` holds the sibling, giving four gated interactions (two add, two remove).
//! 2. **ACE memory reads** (`BUS_CHIPLETS`) — on ACE chiplet rows, the block selector distinguishes
//!    word reads (`f_ace_read`) from element reads used by EVAL rows (`f_ace_eval`). Both are
//!    removed from the chiplets bus.
//!
//! Selector wiring mirrors [`super::wiring`]: `s_ctrl = chiplets[0]`, `s_perm = perm_seg`,
//! virtual `s0 = 1 − s_ctrl − s_perm`, and `s1..s3 = chiplets[1..4]`.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt, MainCols,
    constraints::{
        logup_msg::{MemoryHeader, MemoryMsg, SiblingMsgBitOne, SiblingMsgBitZero},
        lookup::{LookupBuilder, LookupColumn, LookupGroup},
    },
    trace::{
        CHIPLETS_OFFSET,
        chiplets::{
            HASHER_MRUPDATE_ID_COL_IDX, HASHER_NODE_INDEX_COL_IDX, HASHER_SELECTOR_COL_RANGE,
            HASHER_STATE_COL_RANGE, NUM_ACE_SELECTORS,
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
const MRUPDATE_ID_COL: usize = HASHER_MRUPDATE_ID_COL_IDX - CHIPLETS_OFFSET;

/// Emit the hash-kernel virtual table bus (C2).
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_hash_kernel_table<LB>(
    builder: &mut LB,
    local: &MainCols<LB::Var>,
    next: &MainCols<LB::Var>,
) where
    LB: LookupBuilder<F = Felt>,
{
    // Controller flag: hasher responses come from controller rows only (`s_ctrl = 1`).
    let controller_flag: LB::Expr = local.chiplets[0].into();

    // Virtual non-hasher selector `s0 = 1 − s_ctrl − s_perm` and `s1..s3` for the ACE gate.
    let s_ctrl: LB::Expr = local.chiplets[0].into();
    let s_perm: LB::Expr = local.perm_seg.into();
    let virtual_s0: LB::Expr = LB::Expr::ONE - s_ctrl - s_perm;
    let s1: LB::Expr = local.chiplets[1].into();
    let s2: LB::Expr = local.chiplets[2].into();
    let s3: LB::Expr = local.chiplets[3].into();

    // Hasher-internal sub-selectors (controller overlay `s0/s1/s2` at chiplets[S_START..+3]).
    let hs0: LB::Expr = local.chiplets[S_START].into();
    let hs1: LB::Expr = local.chiplets[S_START + 1].into();
    let hs2: LB::Expr = local.chiplets[S_START + 2].into();

    // Hasher state, node_index, mrupdate_id.
    let h: [LB::Expr; 8] = array::from_fn(|i| local.chiplets[H_START + i].into());
    let node_index: LB::Expr = local.chiplets[IDX_COL].into();
    let node_index_next: LB::Expr = next.chiplets[IDX_COL].into();
    let mrupdate_id: LB::Expr = local.chiplets[MRUPDATE_ID_COL].into();

    // Sibling flags — on controller rows, `s0·s1 = 1` selects MU/MV input rows. The new
    // layout has dropped the old 32-row cycle row filter; all MU/MV input rows participate.
    let f_mu_all: LB::Expr = controller_flag.clone() * hs0.clone() * hs1.clone() * hs2.clone();
    let f_mv_all: LB::Expr = controller_flag * hs0 * hs1 * (LB::Expr::ONE - hs2);

    // Direction bit b = node_index − 2·node_index_next.
    let bit: LB::Expr = node_index.clone() - node_index_next.double();
    let one_minus_bit: LB::Expr = LB::Expr::ONE - bit.clone();

    // sib_lo = h[0..4] (rate0), sib_hi = h[4..8] (rate1).
    let sib_lo: [LB::Expr; 4] = array::from_fn(|i| h[i].clone());
    let sib_hi: [LB::Expr; 4] = array::from_fn(|i| h[4 + i].clone());

    // ACE row gate and per-row flags.
    let is_ace_row: LB::Expr = virtual_s0 * s1 * s2 * (LB::Expr::ONE - s3);
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
            // --- SIBLING TABLE ---
            // MV adds (old path), MU removes (new path). Each splits on bit into the
            // BitZero (sibling at h[4..8]) and BitOne (sibling at h[0..4]) variants.
            {
                let mr = mrupdate_id.clone();
                let ni = node_index.clone();
                let hi = sib_hi.clone();
                let gate = f_mv_all.clone() * one_minus_bit.clone();
                g.add(gate, move || SiblingMsgBitZero {
                    mrupdate_id: mr,
                    node_index: ni,
                    h_hi: hi,
                });
            }
            {
                let mr = mrupdate_id.clone();
                let ni = node_index.clone();
                let lo = sib_lo.clone();
                let gate = f_mv_all.clone() * bit.clone();
                g.add(gate, move || SiblingMsgBitOne {
                    mrupdate_id: mr,
                    node_index: ni,
                    h_lo: lo,
                });
            }
            {
                let mr = mrupdate_id.clone();
                let ni = node_index.clone();
                let hi = sib_hi;
                let gate = f_mu_all.clone() * one_minus_bit;
                g.remove(gate, move || SiblingMsgBitZero {
                    mrupdate_id: mr,
                    node_index: ni,
                    h_hi: hi,
                });
            }
            {
                let mr = mrupdate_id;
                let ni = node_index;
                let lo = sib_lo;
                let gate = f_mu_all * bit;
                g.remove(gate, move || SiblingMsgBitOne {
                    mrupdate_id: mr,
                    node_index: ni,
                    h_lo: lo,
                });
            }

            // --- ACE MEMORY READS (BUS_CHIPLETS) ---
            // Word read on READ rows.
            {
                let clk = ace_clk.clone();
                let ctx = ace_ctx.clone();
                let addr = ace_ptr.clone();
                g.remove(f_ace_read, move || MemoryMsg::Word {
                    op_value: MEMORY_READ_WORD_LABEL as u16,
                    header: MemoryHeader { ctx, addr, clk },
                    word: ace_read_word,
                });
            }

            // Element read on EVAL rows.
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
