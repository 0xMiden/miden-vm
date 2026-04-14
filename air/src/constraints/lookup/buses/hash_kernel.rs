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
//! Per-chiplet gating flows through [`ChipletTraceContext::chiplet_active`]: the controller
//! input gate is `chiplet_active.controller`, and the ACE row gate is `chiplet_active.ace`.
//! Hasher sub-selectors, hasher state, `node_index`, and `mrupdate_id` all come from the
//! typed [`local.controller()`](crate::constraints::columns::MainCols::controller) overlay.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt,
    constraints::{
        logup_msg::{MemoryHeader, MemoryMsg, SiblingMsgBitOne, SiblingMsgBitZero},
        lookup::{LookupBuilder, LookupColumn, LookupGroup, buses::ChipletTraceContext},
        utils::BoolNot,
    },
    trace::chiplets::{
        ace::{ACE_INSTRUCTION_ID1_OFFSET, ACE_INSTRUCTION_ID2_OFFSET},
        memory::{MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL},
    },
};

/// Emit the hash-kernel virtual table bus (C2).
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_hash_kernel_table<LB>(
    builder: &mut LB,
    ctx: &ChipletTraceContext<LB>,
) where
    LB: LookupBuilder<F = Felt>,
{
    let local = ctx.local;
    let next = ctx.next;

    // --- Sibling-table setup ---

    // Typed hasher-controller overlay: sub-selectors `s0/s1/s2`, state lanes, `node_index`,
    // `mrupdate_id`. Next-row `node_index` for the direction-bit computation.
    let ctrl = local.controller();
    let ctrl_next = next.controller();

    let hs0: LB::Expr = ctrl.s0.into();
    let hs1: LB::Expr = ctrl.s1.into();
    let hs2: LB::Expr = ctrl.s2.into();

    // Sibling flags — on controller rows, `s0·s1 = 1` selects MU/MV input rows. The new
    // layout has dropped the old 32-row cycle row filter; all MU/MV input rows participate.
    let controller_flag = ctx.chiplet_active.controller.clone();
    let f_mu_all: LB::Expr = controller_flag.clone() * hs0.clone() * hs1.clone() * hs2.clone();
    let f_mv_all: LB::Expr = controller_flag * hs0 * hs1 * hs2.not();

    // Direction bit `b = node_index − 2·node_index_next`.
    let node_index: LB::Expr = ctrl.node_index.into();
    let node_index_next: LB::Expr = ctrl_next.node_index.into();
    let bit: LB::Expr = node_index.clone() - node_index_next.double();
    let one_minus_bit: LB::Expr = bit.not();

    // `sib_lo = h[0..4]` (rate0), `sib_hi = h[4..8]` (rate1).
    let sib_lo: [LB::Expr; 4] = array::from_fn(|i| ctrl.state[i].into());
    let sib_hi: [LB::Expr; 4] = array::from_fn(|i| ctrl.state[4 + i].into());
    let mrupdate_id: LB::Expr = ctrl.mrupdate_id.into();

    // --- ACE memory-read setup ---

    // Typed ACE chiplet overlay.
    let ace = local.ace();
    let block_sel: LB::Expr = ace.s_block.into();

    // ACE row gate comes from the shared `chiplet_active` snapshot; per-mode split by
    // `block_sel`.
    let is_ace_row = ctx.chiplet_active.ace.clone();
    let f_ace_read: LB::Expr = is_ace_row.clone() * block_sel.not();
    let f_ace_eval: LB::Expr = is_ace_row * block_sel;

    // ACE memory-header fields (shared by both READ word and EVAL element interactions).
    let ace_clk: LB::Expr = ace.clk.into();
    let ace_ctx: LB::Expr = ace.ctx.into();
    let ace_ptr: LB::Expr = ace.ptr.into();

    // ACE READ rows expose a 4-element word pulled from the `v_0` / `v_1` pairs.
    let ace_read_word: [LB::Expr; 4] =
        [ace.v_0.0.into(), ace.v_0.1.into(), ace.v_1.0.into(), ace.v_1.1.into()];

    // ACE EVAL rows combine `id_1 / id_2 / eval_op` into a single element. `id_2` reads
    // through the typed EVAL overlay (same physical column as the READ overlay's
    // `num_eval`, but the EVAL interpretation is the one the bus wants).
    let ace_eval_element: LB::Expr = Into::<LB::Expr>::into(ace.id_1)
        + Into::<LB::Expr>::into(ace.eval().id_2) * LB::Expr::from(ACE_INSTRUCTION_ID1_OFFSET)
        + (Into::<LB::Expr>::into(ace.eval_op) + LB::Expr::ONE)
            * LB::Expr::from(ACE_INSTRUCTION_ID2_OFFSET);

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
