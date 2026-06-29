//! Block-hash table and op-group table interactions sharing one lookup column.
//!
//! - Block-hash table rows come from control-flow opcodes: JOIN, SPLIT, LOOP/REPEAT,
//!   DYN/DYNCALL/CALL/SYSCALL, and END.
//! - Op-group table rows come from SPAN/RESPAN batch setup rows and in-span decode rows.
//!
//! These row sets are disjoint: control-flow opcodes are never in-span, and SPAN/RESPAN
//! are not block-hash table variants. The column degree is therefore the elementwise max
//! of the two tables. Block-hash contributes `(V_g, U_g) = (6, 8)` and op-group
//! contributes `(7, 8)`, so the shared column contributes `(7, 8)`.
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
/// - Block-hash table: JOIN emits the largest batch, with 2 fractions.
/// - Op-group table: g8 emits the largest batch, with 7 fractions.
///
/// The two row sets are disjoint, so the per-row max is `max(2, 7) = 7`.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 7;

/// Emit the shared block-hash table and op-group table column.
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

    let f_join = op_flags.join();
    let f_split = op_flags.split();
    // LOOP unconditionally enqueues the body (do-while semantics) and REPEAT enqueues each
    // subsequent iteration.
    let f_loop_body = op_flags.loop_op() + op_flags.repeat();
    let f_child = op_flags.dyn_op() + op_flags.dyncall() + op_flags.call() + op_flags.syscall();
    let f_end = op_flags.end();
    let f_push = op_flags.push();

    // Op-group batch-size selectors.
    let c0: LB::Expr = dec.batch_flags[0].into();
    let c1: LB::Expr = dec.batch_flags[1].into();
    let c2: LB::Expr = dec.batch_flags[2].into();

    let gc: LB::Expr = dec.group_count.into();

    // Op-group removal flag: `in_span * (gc - gc_next)`.
    let in_span: LB::Expr = dec.in_span.into();
    let gc_next: LB::Expr = dec_next.group_count.into();
    let f_rem = in_span * (gc.clone() - gc_next);

    builder.next_column(
        |col| {
            col.group(
                "merged_interactions",
                |g| {
                    // =================== BLOCK HASH TABLE ===================

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
                                Deg { v: 5, u: 6 },
                            );
                            b.add(
                                "join_second_child",
                                BlockHashMsg::Child { parent, child_hash: second_hash },
                                Deg { v: 5, u: 6 },
                            );
                        },
                        Deg { v: 6, u: 7 }, // (V, U) = (1 + 5, 2 + 5)
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
                        Deg { v: 5, u: 7 },
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
                        Deg { v: 5, u: 6 },
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
                        Deg { v: 5, u: 6 },
                    );

                    // END: remove the current child from the block-hash table.
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
                        Deg { v: 4, u: 8 },
                    );

                    // =================== OP GROUP TABLE ===================

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
                                    Deg { v: 1, u: 2 },
                                );
                            }
                            for i in 4u16..=7 {
                                let group_value = h_1[(i - 4) as usize].into();
                                b.add(
                                    "g8_group",
                                    OpGroupMsg::new(&batch_id, gc8.clone(), i, group_value),
                                    Deg { v: 1, u: 2 },
                                );
                            }
                        },
                        Deg { v: 7, u: 8 }, // (V, U) = (6 + 1, 7 + 1)
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
                                    Deg { v: 3, u: 4 },
                                );
                            }
                        },
                        Deg { v: 5, u: 6 }, // (V, U) = (2 + 3, 3 + 3)
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
                        Deg { v: 3, u: 4 },
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
                        Deg { v: 2, u: 8 },
                    );
                },
                Deg { v: 7, u: 8 },
            );
        },
        Deg { v: 7, u: 8 },
    );
}
