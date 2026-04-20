//! Hash-kernel virtual table bus (C2 / `BUS_SIBLING_TABLE` + `BUS_CHIPLETS` +
//! `BUS_RANGE_CHECK`).
//!
//! Combines three tables on a single LogUp column:
//!
//! 1. **Sibling table** (`BUS_SIBLING_TABLE`) — Merkle update siblings. On hasher controller input
//!    rows with `s0·s1 = 1`, `s2` distinguishes MU (new path, removes siblings) from MV (old path,
//!    adds siblings). The direction bit `b = node_index − 2·node_index_next` selects which half of
//!    `rate = [rate_0, rate_1]` holds the sibling, giving four gated interactions (two add, two
//!    remove).
//! 2. **ACE memory reads** (`BUS_CHIPLETS`) — on ACE chiplet rows, the block selector distinguishes
//!    word reads (`f_ace_read`) from element reads used by EVAL rows (`f_ace_eval`). Both are
//!    removed from the chiplets bus.
//! 3. **Memory-side range checks** (`BUS_RANGE_CHECK`) — on memory chiplet rows, a five-remove
//!    batch consumes the two delta limbs `d0`/`d1` and the three word-address decomposition values
//!    `w0`, `w1`, and `4·w1`. Together these enforce `d0, d1, w0, w1 ∈ [0, 2^16)` plus `w1 ∈ [0,
//!    2^14)` (via the `4·w1` check), which bounds `word_addr = 4·(w0 + 2^16·w1)` to the 32-bit
//!    memory address space.
//!
//! Per-chiplet gating flows through [`ChipletBusContext::chiplet_active`]: the controller
//! input gate is `chiplet_active.controller`, the ACE row gate is `chiplet_active.ace`, and
//! the memory row gate is `chiplet_active.memory`. Hasher sub-selectors, hasher state,
//! `node_index`, and `mrupdate_id` come from the typed
//! [`local.controller()`](crate::constraints::columns::MainCols::controller) overlay;
//! memory delta limbs come from [`local.memory()`](crate::constraints::columns::MainCols::memory).
//! `w0` / `w1` are not in the typed `MemoryCols` view (their physical columns live in
//! `chiplets[18..20]`, past the end of the memory overlay, shared with the ACE chiplet
//! column space), so they are read directly from the raw chiplet slice.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    constraints::{
        logup_msg::{MemoryHeader, MemoryMsg, RangeMsg, SiblingMsgBitOne, SiblingMsgBitZero},
        lookup::chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
        utils::BoolNot,
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
    trace::{
        CHIPLETS_OFFSET,
        chiplets::{
            MEMORY_WORD_ADDR_HI_COL_IDX, MEMORY_WORD_ADDR_LO_COL_IDX,
            ace::{ACE_INSTRUCTION_ID1_OFFSET, ACE_INSTRUCTION_ID2_OFFSET},
            memory::{MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL},
        },
    },
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Three row-type-disjoint interaction sets, mutually exclusive via the chiplet tri-state:
/// - **Sibling-table** on hasher controller rows (`chiplet_active.controller`): the MV/MU split is
///   mutually exclusive (`s2` vs `1-s2`) and the direction bit cuts within each side, so at most
///   one of the four fires per row → 1 fraction.
/// - **ACE memory reads** on ACE rows (`chiplet_active.ace`): `f_ace_read` / `f_ace_eval` are
///   mutually exclusive via `block_sel` → 1 fraction.
/// - **Memory-side range checks** on memory rows (`chiplet_active.memory`): a 5-remove batch (`d0`,
///   `d1`, `w0`, `w1`, `4·w1`) fires unconditionally when the outer batch flag is active → 5
///   fractions.
///
/// Row-type disjointness means only one set fires per row, so the per-row max is
/// `max(1, 1, 5) = 5`.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 5;

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

    // --- Memory-side range-check setup ---

    let mem_active = ctx.chiplet_active.memory.clone();
    let mem = local.memory();
    let mem_d0 = mem.d0;
    let mem_d1 = mem.d1;
    let mem_w0 = local.chiplets[MEMORY_WORD_ADDR_LO_COL_IDX - CHIPLETS_OFFSET];
    let mem_w1 = local.chiplets[MEMORY_WORD_ADDR_HI_COL_IDX - CHIPLETS_OFFSET];

    builder.next_column(
        |col| {
            col.group(
                "sibling_ace_memory",
                |g| {
                    // --- SIBLING TABLE ---
                    // MV adds (old path), MU removes (new path). Each splits on bit into the
                    // BitZero (sibling at rate_1) and BitOne (sibling at rate_0) variants.
                    let gate = f_mv_all.clone() * one_minus_bit.clone();
                    g.add(
                        "sibling_mv_b0",
                        gate,
                        move || {
                            let mrupdate_id: LB::Expr = mrupdate_id.into();
                            let node_index: LB::Expr = node_index.into();
                            let h_hi = array::from_fn(|i| rate_1[i].into());
                            SiblingMsgBitZero { mrupdate_id, node_index, h_hi }
                        },
                        Deg::NONE,
                    );

                    let gate = f_mv_all * bit.clone();
                    g.add(
                        "sibling_mv_b1",
                        gate,
                        move || {
                            let mrupdate_id: LB::Expr = mrupdate_id.into();
                            let node_index: LB::Expr = node_index.into();
                            let h_lo = array::from_fn(|i| rate_0[i].into());
                            SiblingMsgBitOne { mrupdate_id, node_index, h_lo }
                        },
                        Deg::NONE,
                    );

                    let gate = f_mu_all.clone() * one_minus_bit;
                    g.remove(
                        "sibling_mu_b0",
                        gate,
                        move || {
                            let mrupdate_id: LB::Expr = mrupdate_id.into();
                            let node_index: LB::Expr = node_index.into();
                            let h_hi = array::from_fn(|i| rate_1[i].into());
                            SiblingMsgBitZero { mrupdate_id, node_index, h_hi }
                        },
                        Deg::NONE,
                    );

                    let gate = f_mu_all * bit;
                    g.remove(
                        "sibling_mu_b1",
                        gate,
                        move || {
                            let mrupdate_id: LB::Expr = mrupdate_id.into();
                            let node_index: LB::Expr = node_index.into();
                            let h_lo = array::from_fn(|i| rate_0[i].into());
                            SiblingMsgBitOne { mrupdate_id, node_index, h_lo }
                        },
                        Deg::NONE,
                    );

                    // --- ACE MEMORY READS (BUS_CHIPLETS) ---
                    // Word read on READ rows.
                    g.remove(
                        "ace_mem_read_word",
                        f_ace_read,
                        move || {
                            let clk = ace_clk.into();
                            let ctx = ace_ctx.into();
                            let addr = ace_ptr.into();
                            let word = [
                                ace_v0.0.into(),
                                ace_v0.1.into(),
                                ace_v1.0.into(),
                                ace_v1.1.into(),
                            ];
                            MemoryMsg::Word {
                                op_value: MEMORY_READ_WORD_LABEL as u16,
                                header: MemoryHeader { ctx, addr, clk },
                                word,
                            }
                        },
                        Deg::NONE,
                    );

                    // Element read on EVAL rows.
                    g.remove(
                        "ace_mem_eval_element",
                        f_ace_eval,
                        move || {
                            let clk = ace_clk.into();
                            let ctx = ace_ctx.into();
                            let addr = ace_ptr.into();
                            let id_1: LB::Expr = ace_id_1.into();
                            let id_2: LB::Expr = ace_id_2.into();
                            let eval_op: LB::Expr = ace_eval_op.into();
                            let element = id_1
                                + id_2 * LB::Expr::from(ACE_INSTRUCTION_ID1_OFFSET)
                                + (eval_op + LB::Expr::ONE)
                                    * LB::Expr::from(ACE_INSTRUCTION_ID2_OFFSET);
                            MemoryMsg::Element {
                                op_value: MEMORY_READ_ELEMENT_LABEL as u16,
                                header: MemoryHeader { ctx, addr, clk },
                                element,
                            }
                        },
                        Deg::NONE,
                    );

                    // --- MEMORY-SIDE RANGE CHECKS (BUS_RANGE_CHECK) ---
                    // Five removes per memory-active row:
                    // - `d0`, `d1` — the two 16-bit delta limbs used by the memory chiplet's
                    //   sorted-access constraints.
                    // - `w0`, `w1`, `4·w1` — the word-address decomposition limbs. The `4·w1` check
                    //   additionally enforces `w1 ∈ [0, 2^14)`, which bounds `word_addr = 4·(w0 +
                    //   2^16·w1) < 2^32`.
                    g.batch(
                        "memory_range_checks",
                        mem_active,
                        move |b| {
                            b.remove("mem_d0", RangeMsg { value: mem_d0.into() }, Deg::NONE);
                            b.remove("mem_d1", RangeMsg { value: mem_d1.into() }, Deg::NONE);
                            let w0: LB::Expr = mem_w0.into();
                            let w1: LB::Expr = mem_w1.into();
                            let w1_mul4 = w1.clone() * LB::Expr::from_u16(4);
                            b.remove("mem_w0", RangeMsg { value: w0 }, Deg::NONE);
                            b.remove("mem_w1", RangeMsg { value: w1 }, Deg::NONE);
                            b.remove("mem_w1_mul4", RangeMsg { value: w1_mul4 }, Deg::NONE);
                        },
                        Deg::NONE,
                    );
                },
                Deg::NONE,
            );
        },
        Deg::NONE,
    );
}
