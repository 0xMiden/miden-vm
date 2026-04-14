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

use crate::constraints::{
    logup_msg::AceWireMsg,
    lookup::{
        LookupBatch, LookupColumn, LookupGroup,
        chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
    },
    utils::BoolNot,
};

/// Emit the ACE wiring bus (C3).
pub(in crate::constraints::lookup) fn emit_ace_wiring<LB>(
    builder: &mut LB,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
{
    let local = ctx.local;
    let ace_flag = ctx.chiplet_active.ace.clone();

    // Typed ACE chiplet overlay. `read()` exposes `m_0` / `m_1`, `eval()` exposes `v_2`;
    // wiring uses both overlays because its `sblock`-muxed multiplicities combine the
    // READ and EVAL row interpretations onto one column.
    let ace = local.ace();
    let ace_read = ace.read();
    let ace_eval = ace.eval();

    // Raw `Var` captures — every field below is Copy and flows directly into a struct
    // field inside the batch closure, so we skip the per-field `LB::Expr` conversion up
    // front and do it lazily. Prefixed with `ace_` where the shorter name would clash
    // with the outer function parameter `ctx`.
    let ace_clk = ace.clk;
    let ace_ctx = ace.ctx;
    let id_0 = ace.id_0;
    let id_1 = ace.id_1;
    let id_2 = ace_eval.id_2;
    let v_0 = ace.v_0;
    let v_1 = ace.v_1;
    let v_2 = ace_eval.v_2;
    let m_0 = ace_read.m_0;
    let m_1 = ace_read.m_1;

    // `sblock` mixes into the wire_1 / wire_2 multiplicities; keep it as an `LB::Expr`
    // since the `wire_1_mult` expression needs arithmetic against the already-converted
    // `m_1`.
    let sblock: LB::Expr = ace.s_block.into();

    builder.column(|col| {
        col.group(|g| {
            // Single `ace_flag`-gated batch with `sblock`-muxed multiplicities
            // for wire_1 and wire_2. `wire_0`'s `m_0` is invariant across the
            // READ/EVAL split, so it lives in the batch as a plain trace-column
            // multiplicity.
            g.batch(ace_flag, move |b| {
                let m_0: LB::Expr = m_0.into();
                let m_1: LB::Expr = m_1.into();
                let wire_1_mult = sblock.not() * m_1 - sblock.clone();
                let wire_2_mult = LB::Expr::ZERO - sblock;

                let wire_0 = AceWireMsg {
                    clk: ace_clk.into(),
                    ctx: ace_ctx.into(),
                    id: id_0.into(),
                    v0: v_0.0.into(),
                    v1: v_0.1.into(),
                };
                b.insert(m_0, wire_0);

                let wire_1 = AceWireMsg {
                    clk: ace_clk.into(),
                    ctx: ace_ctx.into(),
                    id: id_1.into(),
                    v0: v_1.0.into(),
                    v1: v_1.1.into(),
                };
                b.insert(wire_1_mult, wire_1);

                let wire_2 = AceWireMsg {
                    clk: ace_clk.into(),
                    ctx: ace_ctx.into(),
                    id: id_2.into(),
                    v0: v_2.0.into(),
                    v1: v_2.1.into(),
                };
                b.insert(wire_2_mult, wire_2);
            });
        });
    });
}
