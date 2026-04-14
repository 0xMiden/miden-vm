//! Block-stack table + range table bus (M1 / `BUS_BLOCK_STACK_TABLE` + `BUS_RANGE_CHECK` on
//! the same column).
//!
//! Two sibling [`super::super::LookupColumn::group`] calls inside one
//! [`super::super::LookupBuilder::column`] closure — the column's running `(U, V)` is folded
//! across both groups automatically.
//!
//! - `block_stack` opens 7 mutually-exclusive variants (JOIN/SPLIT/SPAN/DYN, LOOP, DYNCALL,
//!   CALL/SYSCALL, two END cases, and a RESPAN batch), all on `BUS_BLOCK_STACK_TABLE`.
//! - `range_table` opens a single always-active insertion with the range-table multiplicity on
//!   `BUS_RANGE_CHECK`.

use miden_core::field::PrimeCharacteristicRing;

use crate::constraints::{
    logup_msg::{BlockStackMsg, RangeMsg},
    lookup::{
        LookupBatch, LookupColumn, LookupGroup,
        main_air::{MainBusContext, MainLookupBuilder},
    },
};

/// Emit the block-stack + range-table bus (M1).
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_block_stack_and_range_table<LB>(
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

    // Raw Vars (Copy — no clones needed). `dec.hasher_state` holds `[h0..h7]` with
    // `h[4..8]` doubling as the end-block flags (see `end_block_flags()`). DYNCALL reads
    // `h[4]`/`h[5]` as `fmp`/`depth`; the END variants read `is_loop`/`is_call`/`is_syscall`
    // through the typed `EndBlockFlags` overlay.
    let addr = dec.addr;
    let addr_next = dec_next.addr;
    let h4 = dec.hasher_state[4];
    let h5 = dec.hasher_state[5];
    let h1_next = dec_next.hasher_state[1];
    let end_flags = dec.end_block_flags();

    let s0 = stk.get(0);
    let b0 = stk.b0;
    let b1 = stk.b1;
    let b0_next = stk_next.b0;
    let b1_next = stk_next.b1;

    let sys_ctx = local.system.ctx;
    let sys_ctx_next = next.system.ctx;

    // `fn_hash` is used twice (DYNCALL, CALL/SYSCALL) and `fn_hash_next` once (END-after-
    // CALL/SYSCALL); keep them as `[Var; 4]` and convert inside each closure.
    let fn_hash = local.system.fn_hash;
    let fn_hash_next = next.system.fn_hash;

    let range_m = local.range.multiplicity;
    let range_v = local.range.value;

    builder.column(|col| {
        // ---- Group 1: block-stack table (BUS_BLOCK_STACK_TABLE) ----
        col.group(|g| {
            // JOIN/SPLIT/SPAN/DYN: simple push with `is_loop = 0`.
            let f = op_flags.join() + op_flags.split() + op_flags.span() + op_flags.dyn_op();
            g.add(f, || {
                let block_id = addr_next.into();
                let parent_id = addr.into();
                let is_loop = LB::Expr::ZERO;
                BlockStackMsg::Simple { block_id, parent_id, is_loop }
            });

            // LOOP: push with is_loop = s0.
            g.add(op_flags.loop_op(), || {
                let block_id = addr_next.into();
                let parent_id = addr.into();
                let is_loop = s0.into();
                BlockStackMsg::Simple { block_id, parent_id, is_loop }
            });

            // DYNCALL: full push with h[4]/h[5] as fmp/depth.
            g.add(op_flags.dyncall(), || {
                let block_id = addr_next.into();
                let parent_id = addr.into();
                let is_loop = LB::Expr::ZERO;
                let ctx = sys_ctx.into();
                let fmp = h4.into();
                let depth = h5.into();
                let fn_hash = fn_hash.map(LB::Expr::from);
                BlockStackMsg::Full {
                    block_id,
                    parent_id,
                    is_loop,
                    ctx,
                    fmp,
                    depth,
                    fn_hash,
                }
            });

            // CALL/SYSCALL: full push saving the caller context.
            let f = op_flags.call() + op_flags.syscall();
            g.add(f, || {
                let block_id = addr_next.into();
                let parent_id = addr.into();
                let is_loop = LB::Expr::ZERO;
                let ctx = sys_ctx.into();
                let fmp = b0.into();
                let depth = b1.into();
                let fn_hash = fn_hash.map(LB::Expr::from);
                BlockStackMsg::Full {
                    block_id,
                    parent_id,
                    is_loop,
                    ctx,
                    fmp,
                    depth,
                    fn_hash,
                }
            });

            // END (simple blocks): pop with the stored is_loop.
            let f = op_flags.end()
                * (LB::Expr::ONE - end_flags.is_call.into() - end_flags.is_syscall.into());
            g.remove(f, || {
                let block_id = addr.into();
                let parent_id = addr_next.into();
                let is_loop = end_flags.is_loop.into();
                BlockStackMsg::Simple { block_id, parent_id, is_loop }
            });

            // END (after CALL/SYSCALL): pop with restored caller context.
            let f = op_flags.end() * (end_flags.is_call.into() + end_flags.is_syscall.into());
            g.remove(f, || {
                let block_id = addr.into();
                let parent_id = addr_next.into();
                let is_loop = end_flags.is_loop.into();
                let ctx = sys_ctx_next.into();
                let fmp = b0_next.into();
                let depth = b1_next.into();
                let fn_hash = fn_hash_next.map(LB::Expr::from);
                BlockStackMsg::Full {
                    block_id,
                    parent_id,
                    is_loop,
                    ctx,
                    fmp,
                    depth,
                    fn_hash,
                }
            });

            // RESPAN: simultaneous push + pop — one batch under the RESPAN flag.
            g.batch(op_flags.respan(), |b| {
                let block_id_add = addr_next.into();
                let parent_id_add = h1_next.into();
                let is_loop_add = LB::Expr::ZERO;
                b.add(BlockStackMsg::Simple {
                    block_id: block_id_add,
                    parent_id: parent_id_add,
                    is_loop: is_loop_add,
                });
                let block_id_rem = addr.into();
                let parent_id_rem = h1_next.into();
                let is_loop_rem = LB::Expr::ZERO;
                b.remove(BlockStackMsg::Simple {
                    block_id: block_id_rem,
                    parent_id: parent_id_rem,
                    is_loop: is_loop_rem,
                });
            });
        });

        // ---- Group 2: range-table response (BUS_RANGE_CHECK) ----
        //
        // Always-active insertion with multiplicity `range_m`. Mirrors the legacy
        // `RationalSet::always(challenges, |b| b.insert(range_m, RangeMsg { ... }))` by
        // gating the single insertion with `LB::Expr::ONE`.
        col.group(|g| {
            g.insert(LB::Expr::ONE, range_m.into(), || {
                let value = range_v.into();
                RangeMsg { value }
            });
        });
    });
}
