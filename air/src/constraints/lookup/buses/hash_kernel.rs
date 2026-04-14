//! Hash-kernel virtual table bus (C2 / `BUS_SIBLING_TABLE` + `BUS_CHIPLETS`).
//!
//! Combines two tables on a single LogUp column:
//!
//! 1. **Sibling table** (`BUS_SIBLING_TABLE`) — Merkle update siblings. On hasher controller input
//!    rows with `s0·s1 = 1`, `s2` distinguishes MU (new path, removes siblings) from MV (old path,
//!    adds siblings). The direction bit `b = node_index − 2·node_index_next` selects which half of
//!    `rate = [rate_0, rate_1]` holds the sibling, giving four gated interactions (two add, two
//!    remove).
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
    constraints::{
        logup_msg::{MemoryHeader, MemoryMsg, SiblingMsgBitOne, SiblingMsgBitZero},
        lookup::{
            LookupColumn, LookupGroup,
            chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
        },
        utils::BoolNot,
    },
    trace::chiplets::{
        ace::{ACE_INSTRUCTION_ID1_OFFSET, ACE_INSTRUCTION_ID2_OFFSET},
        memory::{MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL},
    },
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Sibling-table interactions live on hasher controller rows (`chiplet_active.controller`),
/// where the MV/MU split is further mutually exclusive (`s2` vs `1-s2`) and the direction
/// bit `b` vs `1-b` cuts within each side — at most one of the four fires per row.
/// ACE memory reads live on ACE rows (`chiplet_active.ace`), with `f_ace_read` and
/// `f_ace_eval` mutually exclusive via `block_sel`. Controller rows and ACE rows are
/// mutually exclusive via the top-level `chiplet_active` snapshot. Per-row max: 1.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 1;

/// Emit the hash-kernel virtual table bus (C2).
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_hash_kernel_table<LB>(
    builder: &mut LB,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
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

    // Raw `Var` captures for the sibling payload fields (Copy). Each closure does its own
    // `.into()` so the per-closure construction ends as a flat struct literal. Hasher state
    // is split by convention into `rate_0 (4), rate_1 (4), cap (4)` — sibling messages only
    // use the rate halves.
    let rate_0: [LB::Var; 4] = array::from_fn(|i| ctrl.state[i]);
    let rate_1: [LB::Var; 4] = array::from_fn(|i| ctrl.state[4 + i]);
    let mrupdate_id = ctrl.mrupdate_id;
    let node_index = ctrl.node_index;

    // Direction bit `b = node_index − 2·node_index_next`. The bit / one_minus_bit combine
    // multiplicatively into the sibling flags below — they're computed once and cloned into
    // each `g.add` / `g.remove` flag argument.
    let node_index_next: LB::Expr = ctrl_next.node_index.into();
    let bit: LB::Expr = node_index.into() - node_index_next.double();
    let one_minus_bit: LB::Expr = bit.not();

    // --- ACE memory-read setup ---

    // Typed ACE chiplet overlay.
    let ace = local.ace();
    let block_sel: LB::Expr = ace.s_block.into();

    // ACE row gate comes from the shared `chiplet_active` snapshot; per-mode split by
    // `block_sel`.
    let is_ace_row = ctx.chiplet_active.ace.clone();
    let f_ace_read: LB::Expr = is_ace_row.clone() * block_sel.not();
    let f_ace_eval: LB::Expr = is_ace_row * block_sel;

    // Raw `Var` captures for ACE payload fields — each producing closure converts them
    // via `.into()` inside its body.
    let ace_clk = ace.clk;
    let ace_ctx = ace.ctx;
    let ace_ptr = ace.ptr;
    let ace_v0 = ace.v_0;
    let ace_v1 = ace.v_1;
    let ace_id_1 = ace.id_1;
    let ace_id_2 = ace.eval().id_2;
    let ace_eval_op = ace.eval_op;

    builder.column(|col| {
        col.group(|g| {
            // --- SIBLING TABLE ---
            // MV adds (old path), MU removes (new path). Each splits on bit into the
            // BitZero (sibling at rate_1) and BitOne (sibling at rate_0) variants.
            let gate = f_mv_all.clone() * one_minus_bit.clone();
            g.add(gate, move || {
                let mrupdate_id: LB::Expr = mrupdate_id.into();
                let node_index: LB::Expr = node_index.into();
                let h_hi = array::from_fn(|i| rate_1[i].into());
                SiblingMsgBitZero { mrupdate_id, node_index, h_hi }
            });

            let gate = f_mv_all * bit.clone();
            g.add(gate, move || {
                let mrupdate_id: LB::Expr = mrupdate_id.into();
                let node_index: LB::Expr = node_index.into();
                let h_lo = array::from_fn(|i| rate_0[i].into());
                SiblingMsgBitOne { mrupdate_id, node_index, h_lo }
            });

            let gate = f_mu_all.clone() * one_minus_bit;
            g.remove(gate, move || {
                let mrupdate_id: LB::Expr = mrupdate_id.into();
                let node_index: LB::Expr = node_index.into();
                let h_hi = array::from_fn(|i| rate_1[i].into());
                SiblingMsgBitZero { mrupdate_id, node_index, h_hi }
            });

            let gate = f_mu_all * bit;
            g.remove(gate, move || {
                let mrupdate_id: LB::Expr = mrupdate_id.into();
                let node_index: LB::Expr = node_index.into();
                let h_lo = array::from_fn(|i| rate_0[i].into());
                SiblingMsgBitOne { mrupdate_id, node_index, h_lo }
            });

            // --- ACE MEMORY READS (BUS_CHIPLETS) ---
            // Word read on READ rows.
            g.remove(f_ace_read, move || {
                let clk = ace_clk.into();
                let ctx = ace_ctx.into();
                let addr = ace_ptr.into();
                let word = [ace_v0.0.into(), ace_v0.1.into(), ace_v1.0.into(), ace_v1.1.into()];
                MemoryMsg::Word {
                    op_value: MEMORY_READ_WORD_LABEL as u16,
                    header: MemoryHeader { ctx, addr, clk },
                    word,
                }
            });

            // Element read on EVAL rows.
            g.remove(f_ace_eval, move || {
                let clk = ace_clk.into();
                let ctx = ace_ctx.into();
                let addr = ace_ptr.into();
                let id_1: LB::Expr = ace_id_1.into();
                let id_2: LB::Expr = ace_id_2.into();
                let eval_op: LB::Expr = ace_eval_op.into();
                let element = id_1
                    + id_2 * LB::Expr::from(ACE_INSTRUCTION_ID1_OFFSET)
                    + (eval_op + LB::Expr::ONE) * LB::Expr::from(ACE_INSTRUCTION_ID2_OFFSET);
                MemoryMsg::Element {
                    op_value: MEMORY_READ_ELEMENT_LABEL as u16,
                    header: MemoryHeader { ctx, addr, clk },
                    element,
                }
            });
        });
    });
}
