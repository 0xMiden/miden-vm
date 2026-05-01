//! Merged block-hash + op-group column: block-hash queue (G_block_hash) + op-group table
//! (G_op_group) as one mutually-exclusive group.
//!
//! Combines what were previously two separate columns into a single column by recognizing
//! that G_block_hash and G_op_group are mutually exclusive:
//!
//! - **G_block_hash** (block-hash queue) fires only on control-flow opcodes: JOIN, SPLIT,
//!   LOOP/REPEAT, DYN/DYNCALL/CALL/SYSCALL, END.
//! - **G_op_group** (op-group table) fires only on SPAN/RESPAN (insertion side) or in-span decode
//!   rows (removal side).
//!
//! Control-flow opcodes are never in-span, and SPAN/RESPAN are not in G_block_hash's
//! variant list, so no row fires both buses. The merged group's
//! `(deg(U_g), deg(V_g))` is the elementwise max of the two individual buses:
//! `(max(8, 8), max(6, 7)) = (8, 7)`, giving a column transition of
//! `max(1 + 8, 7) = 9` — the same saturated cost the two original columns had
//! individually, but using **one** column instead of two, saving one accumulator column in
//! `ProcessorAir::num_columns` (LookupAir impl).
//!
//! The emitter uses the plain `col.group` path (no cached encoding) for both buses; the
//! merged group's degree is unchanged under either mode. The cached-encoding optimization
//! can be reintroduced later if symbolic expression growth becomes a bottleneck.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    constraints::{
        lookup::{
            main_air::{MainBusContext, MainLookupBuilder},
            messages::{BlockHashMsg, OpGroupMsg},
        },
        utils::{BoolNot, horner_eval_bits},
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// G_block_hash (control-flow opcodes): largest branch is JOIN's 2-add batch.
/// G_op_group (SPAN/RESPAN insertions + in-span decode removal): largest branch is g8's
/// 7-add batch. Insertions (batch-setup rows) and the removal (in-span decode rows) are
/// mutually exclusive by construction.
/// The module header establishes G_block_hash and G_op_group are row-disjoint — control-flow
/// opcodes are never in-span, and SPAN/RESPAN aren't control-flow. So the per-row max is
/// `max(2, 7) = 7`.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 7;

/// Emit the merged block-hash queue (G_block_hash) + op-group table (G_op_group) column as a
/// single mutually-exclusive group.
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_block_hash_and_op_group<LB>(
    builder: &mut LB,
    ctx: &MainBusContext<LB>,
) where
    LB: MainLookupBuilder,
{
    let local = ctx.local;
    let next = ctx.next;
    let op_flags = &ctx.op_flags;

    let dec = &local.decoder;
    let dec_next = &next.decoder;
    let stk = &local.stack;
    let stk_next = &next.stack;

    let addr = dec.addr;
    let addr_next = dec_next.addr;
    // `dec.hasher_state` is the rate portion of the sponge, split into two halves of 4:
    // `h_0 = h[0..4]` (first child) and `h_1 = h[4..8]` (second child).
    let h_0: [LB::Var; 4] = array::from_fn(|i| dec.hasher_state[i]);
    let h_1: [LB::Var; 4] = array::from_fn(|i| dec.hasher_state[4 + i]);
    let s0 = stk.get(0);

    // G_block_hash per-row-type flags. `f_loop_body` / `f_child` are sums of single-use
    // op flags, bound locally since each is consumed once inside its `.add(...)` call.
    let f_join = op_flags.join();
    let f_split = op_flags.split();
    let f_loop_body = op_flags.loop_op() * s0 + op_flags.repeat();
    let f_child = op_flags.dyn_op() + op_flags.dyncall() + op_flags.call() + op_flags.syscall();
    let f_end = op_flags.end();
    let f_push = op_flags.push();

    // G_op_group per-batch-size selectors — `c0` is used in three places (g8 gate, g4's
    // `(1 - c0)`, g2's `(1 - c0)`), `c1`/`c2` in two places each. Kept as named `LB::Expr`
    // bindings per the style rule (used 2+ times).
    let c0: LB::Expr = dec.batch_flags[0].into();
    let c1: LB::Expr = dec.batch_flags[1].into();
    let c2: LB::Expr = dec.batch_flags[2].into();

    // `group_count` is consumed by the 3 insertion batches AND the removal, so 4+ places.
    let gc: LB::Expr = dec.group_count.into();

    // G_op_group removal flag: `in_span · (gc - gc_next)`. Computed once outside the
    // removal closure because it's the `flag` argument of `g.remove`, not part of the
    // message construction.
    let in_span: LB::Expr = dec.in_span.into();
    let gc_next: LB::Expr = dec_next.group_count.into();
    let f_rem = in_span * (gc.clone() - gc_next);

    builder.next_column(
        |col| {
            col.group(
                "merged_interactions",
                |g| {
                    // =================== G_block_hash BLOCK HASH QUEUE ===================

                    // JOIN: two children — `h_0` first, `h_1` second.
                    g.batch(
                        "join",
                        f_join,
                        |b| {
                            let parent: LB::Expr = addr_next.into();
                            let first_hash = h_0.map(LB::Expr::from);
                            let second_hash = h_1.map(LB::Expr::from);
                            b.add(
                                "join_first_child",
                                BlockHashMsg::FirstChild {
                                    parent: parent.clone(),
                                    child_hash: first_hash,
                                },
                                Deg { n: 5, d: 6 },
                            );
                            b.add(
                                "join_second_child",
                                BlockHashMsg::Child { parent, child_hash: second_hash },
                                Deg { n: 5, d: 6 },
                            );
                        },
                        Deg { n: 1, d: 2 },
                    );

                    // SPLIT: `s0`-muxed selection between `h_0` and `h_1`.
                    g.add(
                        "split",
                        f_split,
                        || {
                            let parent = addr_next.into();
                            let s0: LB::Expr = s0.into();
                            let one_minus_s0 = s0.not();
                            let child_hash = array::from_fn(|i| {
                                s0.clone() * h_0[i].into() + one_minus_s0.clone() * h_1[i].into()
                            });
                            BlockHashMsg::Child { parent, child_hash }
                        },
                        Deg { n: 5, d: 7 },
                    );

                    // LOOP/REPEAT body: first child is `h_0`.
                    g.add(
                        "loop_repeat",
                        f_loop_body,
                        || {
                            let parent = addr_next.into();
                            let child_hash = h_0.map(LB::Expr::from);
                            BlockHashMsg::LoopBody { parent, child_hash }
                        },
                        Deg { n: 6, d: 7 },
                    );

                    // DYN/DYNCALL/CALL/SYSCALL: single child at `h_0`.
                    g.add(
                        "dyn_dyncall_call_syscall",
                        f_child,
                        || {
                            let parent = addr_next.into();
                            let child_hash = h_0.map(LB::Expr::from);
                            BlockHashMsg::Child { parent, child_hash }
                        },
                        Deg { n: 5, d: 6 },
                    );

                    // END: pop the queue entry. `is_first_child` distinguishes the head-of-queue
                    // case via the next-row control-flow flags, and `is_loop_body` comes from the
                    // typed END overlay on the current row.
                    g.remove(
                        "end",
                        f_end,
                        || {
                            let parent = addr_next.into();
                            let child_hash = h_0.map(LB::Expr::from);
                            // RESPAN can directly follow END (the decoder only blocks the
                            // pair conditionally on `delta_group_count`), so include
                            // `respan_next` here — otherwise an END→RESPAN pair encodes a
                            // false-positive `is_first_child = 1` and unbalances the bus.
                            let is_first_child = LB::Expr::ONE
                                - op_flags.end_next()
                                - op_flags.repeat_next()
                                - op_flags.respan_next()
                                - op_flags.halt_next();
                            let is_loop_body = dec.end_block_flags().is_loop_body.into();
                            BlockHashMsg::End {
                                parent,
                                child_hash,
                                is_first_child,
                                is_loop_body,
                            }
                        },
                        Deg { n: 4, d: 8 },
                    );

                    // =================== G_op_group OP GROUP TABLE ===================

                    // g8: c0 triggers a 7-add batch (groups 1..=7). Groups 1..=3 come from `h_0`
                    // and groups 4..=7 from `h_1`.
                    let gc8 = gc.clone();
                    g.batch(
                        "g8_batch",
                        c0.clone(),
                        move |b| {
                            let batch_id: LB::Expr = addr_next.into();
                            for i in 1u16..=3 {
                                let group_value = h_0[i as usize].into();
                                b.add(
                                    "g8_group",
                                    OpGroupMsg::new(&batch_id, gc8.clone(), i, group_value),
                                    Deg { n: 1, d: 2 },
                                );
                            }
                            for i in 4u16..=7 {
                                let group_value = h_1[(i - 4) as usize].into();
                                b.add(
                                    "g8_group",
                                    OpGroupMsg::new(&batch_id, gc8.clone(), i, group_value),
                                    Deg { n: 1, d: 2 },
                                );
                            }
                        },
                        Deg { n: 6, d: 7 },
                    );

                    // g4: (1 - c0) · c1 · (1 - c2) triggers a 3-add batch (groups 1..=3 from
                    // `h_0`).
                    let gc4 = gc.clone();
                    g.batch(
                        "g4_batch",
                        c0.not() * c1.clone() * c2.not(),
                        move |b| {
                            let batch_id: LB::Expr = addr_next.into();
                            for i in 1u16..=3 {
                                let group_value = h_0[i as usize].into();
                                b.add(
                                    "g4_group",
                                    OpGroupMsg::new(&batch_id, gc4.clone(), i, group_value),
                                    Deg { n: 3, d: 4 },
                                );
                            }
                        },
                        Deg { n: 2, d: 3 },
                    );

                    // g2: (1 - c0) · (1 - c1) · c2 is a single add for group 1 (from `h_0[1]`).
                    let gc2 = gc.clone();
                    let f_g2 = c0.not() * c1.not() * c2;
                    g.add(
                        "g2",
                        f_g2,
                        move || {
                            let batch_id: LB::Expr = addr_next.into();
                            let group_value = h_0[1].into();
                            OpGroupMsg::new(&batch_id, gc2, 1, group_value)
                        },
                        Deg { n: 3, d: 4 },
                    );

                    // Removal: `in_span · (gc - gc_next)`-gated muxed removal whose group_value is
                    // `is_push · stk_next[0] + (1 - is_push) · (h0_next · 128 + opcode_next)`.
                    g.remove(
                        "op_group_removal",
                        f_rem,
                        move || {
                            let opcode_next = horner_eval_bits::<7, _, LB::Expr>(&dec_next.op_bits);
                            let stk_next_0: LB::Expr = stk_next.get(0).into();
                            let h0_next: LB::Expr = dec_next.hasher_state[0].into();
                            let group_value = f_push.clone() * stk_next_0
                                + f_push.not() * (h0_next * LB::Expr::from_u16(128) + opcode_next);
                            let batch_id = addr.into();
                            OpGroupMsg { batch_id, group_pos: gc, group_value }
                        },
                        Deg { n: 2, d: 8 },
                    );
                },
                Deg { n: 7, d: 8 },
            );
        },
        Deg { n: 7, d: 8 },
    );
}
