//! Merged M_2+5 column: block-hash queue (G_block_hash) + op-group table (G_op_group) as one ME
//! group.
//!
//! Combines what were previously two separate columns (M2 and M5) into a single
//! column by recognizing that G_block_hash and G_op_group are mutually exclusive:
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
//! individually, but using **one** column instead of two.
//!
//! This folds the original M2 (transition 9) and M5 (transition 9) into a
//! single M_2+5 column at transition 9, saving one accumulator column in
//! `MidenLookupAir::num_columns`.
//!
//! Implementation note: the emitter uses the plain `col.group` path (no cached
//! encoding) for both buses. G_block_hash's original `emit_block_hash_queue` used
//! cached encoding as an expression-size optimization; since G_op_group has no
//! cached path and the merged ME group's final degree is identical under
//! either mode, dropping the cached path is the simpler option. The
//! cached-encoding optimization can be reintroduced later if symbolic
//! expression growth becomes a bottleneck.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt, MainCols,
    constraints::{
        logup_msg::{BlockHashMsg, OpGroupMsg},
        lookup::{LookupBatch, LookupBuilder, LookupColumn, LookupGroup},
        op_flags::OpFlags,
    },
};

/// Emit the merged M_2+5 column: block-hash queue (G_block_hash) + op-group table (G_op_group)
/// as a single ME group on one column.
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_block_hash_and_op_group<LB>(
    builder: &mut LB,
    local: &MainCols<LB::Var>,
    next: &MainCols<LB::Var>,
) where
    LB: LookupBuilder<F = Felt>,
{
    let dec = &local.decoder;
    let dec_next = &next.decoder;
    let stk = &local.stack;
    let stk_next = &next.stack;

    // --- G_block_hash (block-hash queue) setup ---
    let addr = dec.addr;
    let addr_next = dec_next.addr;
    let h: [LB::Var; 8] = array::from_fn(|i| dec.hasher_state[i]);
    let s0 = stk.get(0);
    let is_loop_body_flag = dec.end_block_flags().is_loop_body;

    let h_first: [LB::Expr; 4] = array::from_fn(|i| h[i].into());
    let h_second: [LB::Expr; 4] = array::from_fn(|i| h[4 + i].into());
    let parent: LB::Expr = addr_next.into();
    let s0_e: LB::Expr = s0.into();
    let split_h: [LB::Expr; 4] = array::from_fn(|i| {
        s0_e.clone() * h[i].into() + (LB::Expr::ONE - s0_e.clone()) * h[i + 4].into()
    });

    // OpFlags::new bundles current-row flags AND degree-4 next-row control-flow flags
    // (`end_next` / `repeat_next` / `halt_next`), so we only need a single instance.
    let op_flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);

    let f_join = op_flags.join();
    let f_split = op_flags.split();
    let f_loop_body = op_flags.loop_op() * s0 + op_flags.repeat();
    let f_child = op_flags.dyn_op() + op_flags.dyncall() + op_flags.call() + op_flags.syscall();
    let f_end = op_flags.end();
    let f_push = op_flags.push();

    let is_first_child: LB::Expr =
        LB::Expr::ONE - op_flags.end_next() - op_flags.repeat_next() - op_flags.halt_next();
    let is_loop_body_e: LB::Expr = is_loop_body_flag.into();

    // --- G_op_group (op-group table) setup ---
    let batch_id: LB::Expr = addr_next.into();
    let c0: LB::Expr = dec.batch_flags[0].into();
    let c1: LB::Expr = dec.batch_flags[1].into();
    let c2: LB::Expr = dec.batch_flags[2].into();
    let gc_e: LB::Expr = dec.group_count.into();
    let gc_next_e: LB::Expr = dec_next.group_count.into();
    let in_span: LB::Expr = dec.in_span.into();

    builder.column(|col| {
        col.group(|g| {
            // =================== G_block_hash BLOCK HASH QUEUE ===================
            g.batch(f_join, |b| {
                b.add(BlockHashMsg::FirstChild {
                    parent: parent.clone(),
                    child_hash: h_first.clone(),
                });
                b.add(BlockHashMsg::Child {
                    parent: parent.clone(),
                    child_hash: h_second.clone(),
                });
            });
            g.add(f_split, || BlockHashMsg::Child {
                parent: parent.clone(),
                child_hash: split_h.clone(),
            });
            g.add(f_loop_body, || BlockHashMsg::LoopBody {
                parent: parent.clone(),
                child_hash: h_first.clone(),
            });
            g.add(f_child, || BlockHashMsg::Child {
                parent: parent.clone(),
                child_hash: h_first.clone(),
            });
            g.remove(f_end, || BlockHashMsg::End {
                parent: parent.clone(),
                child_hash: h_first.clone(),
                is_first_child: is_first_child.clone(),
                is_loop_body: is_loop_body_e.clone(),
            });

            // =================== G_op_group OP GROUP TABLE ===================
            // g8: c0 triggers a 7-add batch (groups 1..=7).
            let batch_id8 = batch_id.clone();
            let gc8 = gc_e.clone();
            g.batch(c0.clone(), move |b| {
                for i in 1u16..=7 {
                    b.add(OpGroupMsg::new(&batch_id8, gc8.clone(), i, h[i as usize].into()));
                }
            });

            // g4: (1 - c0) · c1 · (1 - c2) triggers a 3-add batch (groups 1..=3).
            let batch_id4 = batch_id.clone();
            let gc4 = gc_e.clone();
            g.batch(
                (LB::Expr::ONE - c0.clone()) * c1.clone() * (LB::Expr::ONE - c2.clone()),
                move |b| {
                    for i in 1u16..=3 {
                        b.add(OpGroupMsg::new(&batch_id4, gc4.clone(), i, h[i as usize].into()));
                    }
                },
            );

            // g2: (1 - c0) · (1 - c1) · c2 is a single add for group 1.
            let batch_id2 = batch_id;
            let gc2 = gc_e.clone();
            let h1_var = h[1];
            let f_g2 = (LB::Expr::ONE - c0) * (LB::Expr::ONE - c1) * c2;
            g.add(f_g2, move || OpGroupMsg::new(&batch_id2, gc2, 1, h1_var.into()));

            // Removal: `in_span · (gc - gc_next)` gates a muxed removal whose
            // group_value is `is_push · stk_next[0] + (1 - is_push) · (h0_next · 128 +
            // opcode_next)`.
            let f_rem = in_span * (gc_e.clone() - gc_next_e);
            let h0_next: LB::Expr = dec_next.hasher_state[0].into();
            let opcode_next: LB::Expr = (0..7).fold(LB::Expr::ZERO, |acc, i| {
                let bit: LB::Expr = dec_next.op_bits[i].into();
                acc + bit * LB::Expr::from_u16(1u16 << i)
            });
            let group_value = f_push.clone() * stk_next.get(0).into()
                + (LB::Expr::ONE - f_push) * (h0_next * LB::Expr::from_u16(128) + opcode_next);
            let addr_e: LB::Expr = addr.into();
            g.remove(f_rem, move || OpGroupMsg {
                batch_id: addr_e,
                group_pos: gc_e,
                group_value,
            });
        });
    });
}
