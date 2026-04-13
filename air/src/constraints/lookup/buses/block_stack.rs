//! Block-stack table + range table bus (M1 / `BUS_BLOCK_STACK_TABLE` + `BUS_RANGE_CHECK` on
//! the same column).
//!
//! Two sibling [`super::super::LookupColumn::group`] calls inside one
//! [`super::super::LookupBuilder::column`] closure — the column's running `(U, V)` is folded
//! across both groups automatically.
//!
//! - `block_stack` opens 7 mutually-exclusive variants (JOIN/SPLIT/SPAN/DYN, LOOP, DYNCALL,
//!   CALL/SYSCALL, two END cases, and a RESPAN batch), all on `BUS_BLOCK_STACK_TABLE`.
//! - `range_table` opens a single always-active insertion with the range-table multiplicity
//!   on `BUS_RANGE_CHECK`.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt, MainTraceRow,
    constraints::{
        logup_msg::{BlockStackMsg, RangeMsg},
        lookup::{LookupBatch, LookupBuilder, LookupColumn, LookupGroup},
        op_flags::{ExprDecoderAccess, OpFlags},
    },
    trace::decoder::{
        ADDR_COL_IDX, HASHER_STATE_RANGE, IS_CALL_FLAG_COL_IDX, IS_LOOP_FLAG_COL_IDX,
        IS_SYSCALL_FLAG_COL_IDX,
    },
};

/// Emit the block-stack + range-table bus (M1).
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_block_stack_and_range_table<LB>(
    builder: &mut LB,
    local: &MainTraceRow<LB::Var>,
    next: &MainTraceRow<LB::Var>,
) where
    LB: LookupBuilder<F = Felt>,
{
    let dec = &local.decoder;
    let dec_next = &next.decoder;
    let stk = &local.stack;
    let stk_next = &next.stack;

    let addr = dec[ADDR_COL_IDX];
    let addr_next = dec_next[ADDR_COL_IDX];
    let h: [LB::Var; 8] = array::from_fn(|i| dec[HASHER_STATE_RANGE.start + i]);
    let h1_next = dec_next[HASHER_STATE_RANGE.start + 1];
    let is_loop_flag: LB::Expr = dec[IS_LOOP_FLAG_COL_IDX].into();
    let is_call_flag: LB::Expr = dec[IS_CALL_FLAG_COL_IDX].into();
    let is_syscall_flag: LB::Expr = dec[IS_SYSCALL_FLAG_COL_IDX].into();

    let s0 = stk[0];
    let b0 = stk[16];
    let b1 = stk[17];
    let b0_next = stk_next[16];
    let b1_next = stk_next[17];

    let ctx = local.ctx;
    let ctx_next = next.ctx;

    let fn_hash: [LB::Expr; 4] = local.fn_hash.map(Into::into);
    let fn_hash_next: [LB::Expr; 4] = next.fn_hash.map(Into::into);

    let range_m = local.range[0];
    let range_v = local.range[1];

    // Op-flag reconstruction for the local row — the block-stack variants all gate off
    // `local`-row flags.
    let op_flags = OpFlags::new(ExprDecoderAccess::<LB::Var, LB::Expr>::new(local));

    builder.column(|col| {
        // ---- Group 1: block-stack table (BUS_BLOCK_STACK_TABLE) ----
        col.group(|g| {
            // JOIN/SPLIT/SPAN/DYN: simple push with `is_loop = 0`.
            let f = op_flags.join() + op_flags.split() + op_flags.span() + op_flags.dyn_op();
            g.add(f, || BlockStackMsg::Simple {
                block_id: addr_next.into(),
                parent_id: addr.into(),
                is_loop: LB::Expr::ZERO,
            });

            // LOOP: push with is_loop = s0.
            g.add(op_flags.loop_op(), || BlockStackMsg::Simple {
                block_id: addr_next.into(),
                parent_id: addr.into(),
                is_loop: s0.into(),
            });

            // DYNCALL: full push with h[4]/h[5] as fmp/depth.
            g.add(op_flags.dyncall(), || BlockStackMsg::Full {
                block_id: addr_next.into(),
                parent_id: addr.into(),
                is_loop: LB::Expr::ZERO,
                ctx: ctx.into(),
                fmp: h[4].into(),
                depth: h[5].into(),
                fn_hash: fn_hash.clone(),
            });

            // CALL/SYSCALL: full push saving the caller context.
            let f = op_flags.call() + op_flags.syscall();
            g.add(f, || BlockStackMsg::Full {
                block_id: addr_next.into(),
                parent_id: addr.into(),
                is_loop: LB::Expr::ZERO,
                ctx: ctx.into(),
                fmp: b0.into(),
                depth: b1.into(),
                fn_hash: fn_hash.clone(),
            });

            // END (simple blocks): pop with the stored is_loop.
            let f =
                op_flags.end() * (LB::Expr::ONE - is_call_flag.clone() - is_syscall_flag.clone());
            g.remove(f, || BlockStackMsg::Simple {
                block_id: addr.into(),
                parent_id: addr_next.into(),
                is_loop: is_loop_flag.clone(),
            });

            // END (after CALL/SYSCALL): pop with restored caller context.
            let f = op_flags.end() * (is_call_flag.clone() + is_syscall_flag.clone());
            g.remove(f, || BlockStackMsg::Full {
                block_id: addr.into(),
                parent_id: addr_next.into(),
                is_loop: is_loop_flag.clone(),
                ctx: ctx_next.into(),
                fmp: b0_next.into(),
                depth: b1_next.into(),
                fn_hash: fn_hash_next.clone(),
            });

            // RESPAN: simultaneous push + pop — one batch under the RESPAN flag.
            g.batch(op_flags.respan(), |b| {
                b.add(BlockStackMsg::Simple {
                    block_id: addr_next.into(),
                    parent_id: h1_next.into(),
                    is_loop: LB::Expr::ZERO,
                });
                b.remove(BlockStackMsg::Simple {
                    block_id: addr.into(),
                    parent_id: h1_next.into(),
                    is_loop: LB::Expr::ZERO,
                });
            });
        });

        // ---- Group 2: range-table response (BUS_RANGE_CHECK) ----
        //
        // Always-active insertion with multiplicity `range_m`. Mirrors the legacy
        // `RationalSet::always(challenges, |b| b.insert(range_m, RangeMsg { ... }))` by
        // gating the single insertion with `LB::Expr::ONE`.
        col.group(|g| {
            g.insert(LB::Expr::ONE, range_m.into(), || RangeMsg { value: range_v.into() });
        });
    });
}
