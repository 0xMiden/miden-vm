//! ACE wiring bus (C3 / `BUS_ACE_WIRING`).
//!
//! Two READ/EVAL wire interactions gated by the ACE chiplet selector + its per-row block
//! selector.
//!
//! The two batches are folded into a single `ace_flag`-gated batch with
//! `sblock`-muxed multiplicities: `wire_0` fires with the same multiplicity `m_0`
//! on both READ and EVAL rows, so it factors out; `wire_1` and `wire_2` get
//! `sblock`-parameterized multiplicities that recover the original rational at
//! every row. This drops the outer selector from degree 5 (`is_read`/`is_eval`)
//! to degree 4 (`ace_flag`), bringing the column transition from 9 to 8.
//!
//! Algebraic equivalence:
//!
//! ```text
//!   is_read · (m_0/wire_0 + m_1/wire_1)
//! + is_eval · (m_0/wire_0 − 1/wire_1 − 1/wire_2)
//!   = ace_flag · [ m_0/wire_0
//!                + ((1 − sblock)·m_1 − sblock)/wire_1
//!                + (−sblock)/wire_2 ]
//! ```
//!
//! The `wire_2` payload reads the physical columns shared with the READ overlay's `m_1`
//! slot — under `sblock = 1` (EVAL) they hold `v_2`, and under `sblock = 0` (READ) the
//! `wire_2` interaction is fully suppressed via the `−sblock` multiplicity, so the
//! interpretation collapses to the READ-mode one.

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt,
    constraints::{
        logup_msg::AceWireMsg,
        lookup::{
            LookupBatch, LookupBuilder, LookupColumn, LookupGroup, buses::ChipletTraceContext,
        },
        utils::BoolNot,
    },
};

/// Emit the ACE wiring bus (C3).
pub(in crate::constraints::lookup) fn emit_ace_wiring<LB>(
    builder: &mut LB,
    ctx: &ChipletTraceContext<LB>,
) where
    LB: LookupBuilder<F = Felt>,
{
    let local = ctx.local;
    let ace_flag = ctx.chiplet_active.ace.clone();

    // Typed ACE chiplet overlay. `read()` exposes `m_0` / `m_1`, `eval()` exposes `v_2`;
    // wiring uses both overlays because its `sblock`-muxed multiplicities combine the
    // READ and EVAL row interpretations onto one column.
    let ace = local.ace();
    let ace_read = ace.read();
    let ace_eval = ace.eval();

    let sblock: LB::Expr = ace.s_block.into();

    // Shared fields across all three wires.
    let clk: LB::Expr = ace.clk.into();
    let sys_ctx: LB::Expr = ace.ctx.into();
    let m0: LB::Expr = ace_read.m_0.into();
    let m1: LB::Expr = ace_read.m_1.into();

    let wire_0 = AceWireMsg {
        clk: clk.clone(),
        ctx: sys_ctx.clone(),
        id: ace.id_0.into(),
        v0: ace.v_0.0.into(),
        v1: ace.v_0.1.into(),
    };
    let wire_1 = AceWireMsg {
        clk: clk.clone(),
        ctx: sys_ctx.clone(),
        id: ace.id_1.into(),
        v0: ace.v_1.0.into(),
        v1: ace.v_1.1.into(),
    };
    let wire_2 = AceWireMsg {
        clk,
        ctx: sys_ctx,
        id: ace_eval.id_2.into(),
        v0: ace_eval.v_2.0.into(),
        v1: ace_eval.v_2.1.into(),
    };

    builder.column(|col| {
        col.group(|g| {
            // Single `ace_flag`-gated batch with `sblock`-muxed multiplicities
            // for wire_1 and wire_2. `wire_0`'s `m_0` is invariant across the
            // READ/EVAL split, so it lives in the batch as a plain trace-column
            // multiplicity.
            let wire_1_mult = sblock.not() * m1 - sblock.clone();
            let wire_2_mult = LB::Expr::ZERO - sblock;
            g.batch(ace_flag, move |b| {
                b.insert(m0, wire_0);
                b.insert(wire_1_mult, wire_1);
                b.insert(wire_2_mult, wire_2);
            });
        });
    });
}
