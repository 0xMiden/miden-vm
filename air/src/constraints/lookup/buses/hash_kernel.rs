//! Hash-kernel virtual table bus. Shares one column across
//! `BusId::{SiblingTable, RangeCheck}` plus the shared chiplets column for ACE reads.
//!
//! Combines three tables on a single LogUp column:
//!
//! 1. Merkle controller inputs. Update rows emit exactly one sibling interaction, selected by the
//!    update kind and direction bit. Level-0 rows batch that sibling (when present) with the two
//!    top-limb canonical-index range checks from the reused capacity lanes.
//! 2. ACE memory reads (chiplet-responses column). On ACE chiplet rows, the block selector
//!    distinguishes word reads (`f_ace_read`) from element reads used by EVAL rows (`f_ace_eval`).
//!    Both are removed from the chiplets bus.
//! 3. Memory-side range checks (`BusId::RangeCheck`). On memory chiplet rows, a five-remove batch
//!    consumes the two delta limbs `d0`/`d1` and the three word-address decomposition values `w0`,
//!    `w1`, and `4·w1`. Together these enforce `d0, d1, w0, w1 ∈ [0, 2^16)` plus `w1 ∈ [0, 2^14)`
//!    (via the `4·w1` check), which bounds `word_addr = 4·(w0 + 2^16·w1)` to the 32-bit memory
//!    address space.
//!
//! Per-chiplet gating flows through [`ChipletBusContext::chiplet_active`]: the controller
//! input gate is `chiplet_active.controller`, the ACE row gate is `chiplet_active.ace`, and
//! the memory row gate is `chiplet_active.memory`. Hasher sub-selectors, hasher state,
//! `node_index`, and `mrupdate_id` come from the typed
//! [`local.controller()`](crate::constraints::columns::ChipletCols::controller) overlay;
//! memory delta limbs come from
//! [`local.memory()`](crate::constraints::columns::ChipletCols::memory).
//! `w0` / `w1` are not in the typed `MemoryCols` view (their physical columns live in
//! `chiplets[18..20]`, past the end of the memory overlay, shared with the ACE chiplet
//! column space), so they are read directly from the raw chiplet slice.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    constraints::{
        lookup::{
            chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
            messages::{MemoryMsg, RangeMsg, SiblingFromRatesMsg},
        },
        utils::BoolNot,
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
    trace::chiplets::ace::{ACE_INSTRUCTION_ID1_OFFSET, ACE_INSTRUCTION_ID2_OFFSET},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Three row-type-disjoint interaction sets, mutually exclusive via the chiplet tri-state:
/// - Merkle controller input rows: one sibling-table fraction on update rows, plus two top-limb
///   canonical-index range checks on level 0. Max: 3 fractions.
/// - ACE memory reads on ACE rows (`chiplet_active.ace`): `f_ace_read` / `f_ace_eval` are mutually
///   exclusive via `block_sel`. Max: 1 fraction.
/// - Memory-side range checks on memory rows (`chiplet_active.memory`): a 5-remove batch (`d0`,
///   `d1`, `w0`, `w1`, `4·w1`) is active under the outer batch flag. Max: 5 fractions.
///
/// Row-type disjointness means only one set fires per row, so the per-row max remains
/// `max(3, 1, 5) = 5`.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 5;

/// Emit the hash-kernel virtual table bus.
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

    // MRUPDATE sibling-table interactions. `s2` selects the sign: MV adds the old-path sibling
    // with +1, while MU removes the new-path sibling with -1.
    let controller_flag = ctx.chiplet_active.controller.clone();
    let hs0: LB::Expr = ctrl.s0.into();
    let hs1: LB::Expr = ctrl.s1.into();
    let hs2: LB::Expr = ctrl.s2.into();
    let is_boundary: LB::Expr = ctrl.is_boundary.into();
    let later_level = is_boundary.not();
    let f_update_all = controller_flag.clone() * hs0.clone() * hs1.clone();
    let f_update_later_levels = f_update_all * later_level;
    // Keep the input selector explicit. The two update branches still merge exactly:
    //   controller * s0 * s1 * (1 - s2) * is_boundary
    //     + controller * s0 * s1 * s2 * is_boundary
    //     = controller * s0 * s1 * is_boundary.
    let f_update_level0 = controller_flag.clone() * hs0.clone() * hs1.clone() * is_boundary.clone();
    let f_mp_level0 = controller_flag * hs0 * hs1.not() * hs2.clone() * is_boundary;
    let update_multiplicity = LB::Expr::ONE - hs2.double();

    // Hasher state is split by convention into `rate_0 (4), rate_1 (4), cap (4)`.
    // Sibling messages only use the rate halves.
    let rate_0: [LB::Var; 4] = array::from_fn(|i| ctrl.state[i]);
    let rate_1: [LB::Var; 4] = array::from_fn(|i| ctrl.state[4 + i]);
    let mrupdate_id = ctrl.mrupdate_id;
    let node_index = ctrl.node_index;
    let slack_3 = ctrl.capacity()[3];

    // Direction bit `b = node_index - 2 * node_index_next`. The sibling message uses this
    // constrained bit to select the rate half carrying the sibling.
    let node_index_next: LB::Expr = ctrl_next.node_index.into();
    let bit: LB::Expr = node_index.into() - node_index_next.double();

    // --- ACE memory-read setup ---

    // Typed ACE chiplet overlay.
    let ace = local.ace();
    let block_sel: LB::Expr = ace.s_block.into();

    // ACE row gate comes from the shared `chiplet_active` snapshot; per-mode split by
    // `block_sel`.
    let is_ace_row = ctx.chiplet_active.ace.clone();
    let f_ace_read: LB::Expr = is_ace_row.clone() * block_sel.not();
    let f_ace_eval: LB::Expr = is_ace_row * block_sel;

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
    let mem_w0 = local.memory_word_addr_lo();
    let mem_w1 = local.memory_word_addr_hi();

    builder.next_column(
        |col| {
            col.group(
                "sibling_ace_memory",
                |g| {
                    // --- MERKLE UPDATE SIBLINGS + LEVEL-0 INDEX RANGE CHECKS ---
                    //
                    // A single signed interaction handles both MRUPDATE legs: boolean `s2 = 0`
                    // gives multiplicity +1 for MV, while `s2 = 1` gives -1 for MU. The constrained
                    // direction bit selects the sibling from the two rate halves.
                    let later_level_bit = bit.clone();
                    g.insert(
                        "sibling_update",
                        f_update_later_levels,
                        update_multiplicity.clone(),
                        move || SiblingFromRatesMsg {
                            direction_bit: later_level_bit,
                            mrupdate_id: mrupdate_id.into(),
                            node_index: node_index.into(),
                            rate_0: rate_0.map(Into::into),
                            rate_1: rate_1.map(Into::into),
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // At level 0, one batch carries the sibling interaction and both checks of the
                    // top slack limb.
                    g.batch(
                        "sibling_update_level0",
                        f_update_level0,
                        move |b| {
                            b.insert(
                                "sibling_update",
                                update_multiplicity,
                                SiblingFromRatesMsg {
                                    direction_bit: bit,
                                    mrupdate_id: mrupdate_id.into(),
                                    node_index: node_index.into(),
                                    rate_0: rate_0.map(Into::into),
                                    rate_1: rate_1.map(Into::into),
                                },
                                Deg { v: 5, u: 6 },
                            );

                            let slack_3: LB::Expr = slack_3.into();
                            b.remove(
                                "merkle_index_slack_3",
                                RangeMsg { value: slack_3.clone() },
                                Deg { v: 4, u: 5 },
                            );
                            b.remove(
                                "merkle_index_slack_3_double",
                                RangeMsg { value: slack_3.double() },
                                Deg { v: 4, u: 5 },
                            );
                        },
                        Deg { v: 7, u: 8 },
                    );

                    g.batch(
                        "mpverify_level0_index_range",
                        f_mp_level0,
                        move |b| {
                            let slack_3: LB::Expr = slack_3.into();
                            b.remove(
                                "merkle_index_slack_3",
                                RangeMsg { value: slack_3.clone() },
                                Deg { v: 5, u: 6 },
                            );
                            b.remove(
                                "merkle_index_slack_3_double",
                                RangeMsg { value: slack_3.double() },
                                Deg { v: 5, u: 6 },
                            );
                        },
                        Deg { v: 6, u: 7 },
                    );

                    // --- ACE MEMORY READS (chiplet-responses column) ---
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
                            MemoryMsg::read_word(ctx, addr, clk, word)
                        },
                        Deg { v: 5, u: 6 },
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

                            // ACE EVAL rows read the packed instruction
                            // `id_1 + id_2 * 2^30 + (eval_op + 1) * 2^60`.
                            let id_2_slot = id_2 * LB::Expr::from(ACE_INSTRUCTION_ID1_OFFSET);
                            let eval_op_slot = (eval_op + LB::Expr::ONE)
                                * LB::Expr::from(ACE_INSTRUCTION_ID2_OFFSET);
                            let element = id_1 + id_2_slot + eval_op_slot;
                            MemoryMsg::read_element(ctx, addr, clk, element)
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // --- MEMORY-SIDE RANGE CHECKS (BusId::RangeCheck) ---
                    // Five removes per memory-active row:
                    // - `d0`, `d1`: the two 16-bit delta limbs used by the memory chiplet's
                    //   sorted-access constraints.
                    // - `w0`, `w1`, `4·w1`: the word-address decomposition limbs. The `4·w1` check
                    //   additionally enforces `w1 ∈ [0, 2^14)`, which bounds `word_addr = 4·(w0 +
                    //   2^16·w1) < 2^32`.
                    g.batch(
                        "memory_range_checks",
                        mem_active,
                        move |b| {
                            b.remove(
                                "mem_d0",
                                RangeMsg { value: mem_d0.into() },
                                Deg { v: 3, u: 4 },
                            );
                            b.remove(
                                "mem_d1",
                                RangeMsg { value: mem_d1.into() },
                                Deg { v: 3, u: 4 },
                            );
                            let w0: LB::Expr = mem_w0.into();
                            let w1: LB::Expr = mem_w1.into();
                            let w1_mul4 = w1.clone() * LB::Expr::from_u16(4);
                            b.remove("mem_w0", RangeMsg { value: w0 }, Deg { v: 3, u: 4 });
                            b.remove("mem_w1", RangeMsg { value: w1 }, Deg { v: 3, u: 4 });
                            b.remove(
                                "mem_w1_mul4",
                                RangeMsg { value: w1_mul4 },
                                Deg { v: 3, u: 4 },
                            );
                        },
                        Deg { v: 7, u: 8 }, // (V, U) = (4 + 3, 5 + 3); mem_active flag deg 3
                    );
                },
                Deg { v: 7, u: 8 },
            );
        },
        Deg { v: 7, u: 8 },
    );
}
