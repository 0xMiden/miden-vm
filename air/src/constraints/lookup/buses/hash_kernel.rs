//! Hash-kernel virtual table bus.
//!
//! Combines five row-disjoint interaction families on a single LogUp column:
//!
//! 1. **Sibling table** (`BusId::SiblingTable`) - Merkle update siblings on controller rows; see
//!    [`super::super::operations::merkle`].
//! 2. **ACE memory reads** - on ACE chiplet rows, the block selector distinguishes word reads
//!    (`f_ace_read`) from element reads used by EVAL rows (`f_ace_eval`). Both are removed from the
//!    chiplets bus.
//! 3. **AEAD stream memory I/O** (`BusId::{MemoryReadWord, MemoryWriteWord}`) - on stream rows;
//!    see [`super::super::operations::aead_stream`].
//! 4. **Normal bitwise AND8 checks** (`BusId::And8Lookup`) - on normal bitwise rows, four removes
//!    bind the bytewise `a & b` witnesses to the shared AND8 lookup table.
//! 5. **Memory-side range checks** (`BusId::RangeCheck`) - on memory chiplet rows, a five-remove
//!    batch consumes the two delta limbs `d0`/`d1` and the three word-address decomposition values
//!    `w0`, `w1`, and `4·w1`. Together these enforce `d0, d1, w0, w1 ∈ [0, 2^16)` plus `w1 ∈ [0,
//!    2^14)` (via the `4·w1` check), which bounds `word_addr = 4·(w0 + 2^16·w1)` to the 32-bit
//!    memory address space.
//!
//! Per-chiplet gating flows through [`ChipletBusContext::chiplet_active`]: the controller
//! gate is `chiplet_active.controller`, the ACE row gate is `chiplet_active.ace`, stream rows
//! use the derived AEAD stream flag, and the memory row gate is `chiplet_active.memory`. Hasher
//! sub-selectors, hasher state, `node_index`, and `mrupdate_id` come from the typed
//! [`local.controller()`](crate::constraints::columns::ChipletCols::controller) overlay;
//! memory delta limbs come from
//! [`local.memory()`](crate::constraints::columns::ChipletCols::memory).
//! `w0` / `w1` are not in the typed `MemoryCols` view (their physical columns live in
//! `chiplets[18..20]`, past the end of the memory overlay, shared with the ACE chiplet
//! column space), so they are read directly from the raw chiplet slice.

use super::super::operations::{aead_stream, merkle};

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    constraints::{
        chiplets::columns::PeriodicCols,
        lookup::{
            chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
            messages::{BytePairLookupMsg, MemoryMsg, RangeMsg},
        },
        utils::BoolNot,
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
    trace::chiplets::ace::{ACE_INSTRUCTION_ID1_OFFSET, ACE_INSTRUCTION_ID2_OFFSET},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Five row-type-disjoint interaction sets, mutually exclusive via chiplet active flags:
/// - **Sibling-table** on hasher controller rows (`chiplet_active.controller`): the MV/MU split is
///   mutually exclusive (`s2` vs `1-s2`) and the direction bit cuts within each side, so at most
///   one of the four fires per row -> 1 fraction.
/// - **ACE memory reads** on ACE rows (`chiplet_active.ace`): `f_ace_read` / `f_ace_eval` are
///   mutually exclusive via `block_sel` -> 1 fraction.
/// - **AEAD stream memory I/O** on stream rows: one memory interaction on each of phases 0, 3, 4,
///   and 7, so this contributes at most 1 fraction per row.
/// - **Normal bitwise AND8 checks** on normal bitwise rows: a 4-remove batch fires once per one-row
///   bitwise operation -> 4 fractions.
/// - **Memory-side range checks** on memory rows (`chiplet_active.memory`): a 5-remove batch (`d0`,
///   `d1`, `w0`, `w1`, `4 * w1`) fires unconditionally when the outer batch flag is active -> 5
///   fractions.
///
/// Row-type disjointness means only one set fires per row, so the per-row max is
/// `max(1, 1, 1, 4, 5) = 5`.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 5;

/// Emit the hash-kernel virtual table bus.
pub(in crate::constraints::lookup) fn emit_hash_kernel_table<LB>(
    builder: &mut LB,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
{
    let local = ctx.local;
    let periodic: &PeriodicCols<LB::PeriodicVar> = builder.periodic_values().borrow();
    let aead_phase: [LB::Expr; 8] = periodic.aead_stream.phases.map(Into::into);

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
    let bitwise = local.bitwise();
    let normal_bitwise_gate = ctx.chiplet_active.bitwise.clone();

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
                    merkle::emit_siblings::<LB, _>(g, ctx);

                    // --- ACE MEMORY READS ---
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
                            let element = id_1
                                + id_2 * LB::Expr::from(ACE_INSTRUCTION_ID1_OFFSET)
                                + (eval_op + LB::Expr::ONE)
                                    * LB::Expr::from(ACE_INSTRUCTION_ID2_OFFSET);
                            MemoryMsg::read_element(ctx, addr, clk, element)
                        },
                        Deg { v: 5, u: 6 },
                    );

                    aead_stream::emit_memory_io::<LB, _>(g, ctx, &aead_phase);

                    // --- NORMAL BITWISE AND8 CHECKS (BusId::And8Lookup) ---
                    //
                    // The response column emits `BitwiseMsg`. This column carries the four AND8
                    // removals, reusing row-disjoint capacity instead of widening the chiplet
                    // lookup shape.
                    g.batch(
                        "bitwise_and8_lookups",
                        normal_bitwise_gate,
                        |b| {
                            for idx in 0..4 {
                                b.remove(
                                    "bitwise_and8_byte",
                                    BytePairLookupMsg::from_and(
                                        bitwise.a_bytes[idx].into(),
                                        bitwise.b_bytes[idx].into(),
                                        bitwise.and_bytes[idx].into(),
                                    ),
                                    Deg { v: 2, u: 3 },
                                );
                            }
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // --- MEMORY-SIDE RANGE CHECKS (BusId::RangeCheck) ---
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
