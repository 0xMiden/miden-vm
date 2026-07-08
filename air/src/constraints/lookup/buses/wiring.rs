//! `v_wiring` shared bus column (`BusId::{AceWiring, HasherPermLinkInput,
//! HasherPermLinkOutput}`).
//!
//! ACE rows and hasher-controller rows are mutually exclusive in the chiplets selector system, so
//! both buses can share one group without multiplying sibling `(V, U)` pairs.
//!
//! ## ACE wiring (`BusId::AceWiring`)
//!
//! Two READ/EVAL wire interactions gated by the ACE chiplet selector + its per-row block
//! selector, folded into a single `ace_flag`-gated batch with `sblock`-muxed multiplicities:
//! `wire_0` fires with the same multiplicity `m_0` on both READ and EVAL rows, so it
//! factors out; `wire_1` and `wire_2` get `sblock`-parameterized multiplicities that recover
//! the original rational at every row. This drops the outer selector from degree 5
//! (`is_read`/`is_eval`) to degree 4 (`ace_flag`), bringing the batch's contribution to
//! `(deg(U_g), deg(V_g)) = (7, 8)`.
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
//!
//! ## Hasher perm-link (`BusId::HasherPermLink{Input,Output}`)
//!
//! Binds hasher controller rows to the Poseidon2 permutation AIR. The `perm_id` column ties each
//! controller input/output row pair to one permutation cycle.
//!
//! - **Controller input** (`controller_active * is_input`, multiplicity `+1`): controller side of a
//!   `(perm_id, input_state)` message. Routed to `BusId::HasherPermLinkInput`.
//! - **Controller output** (`controller_active * is_output`, multiplicity `+1`): controller side of
//!   a `(perm_id, output_state)` message. Routed to `BusId::HasherPermLinkOutput`.
//!
//! Each controller pair contributes one input message and one output message with the same
//! `perm_id`. The Poseidon2 AIR removes those messages on rows 0 and 15 of the matching
//! permutation instance, and its transition constraints tie the row-15 state to the row-0 state.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    constraints::{
        lookup::{
            chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
            messages::{AceWireMsg, HasherPermLinkMsg},
        },
        utils::BoolNot,
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
    trace::chiplets::hasher::STATE_WIDTH,
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Single group hosts both buses. ACE and hasher-controller rows are mutually exclusive, so on any
/// given row only one of:
/// - **ACE wiring batch** on ACE rows: 3 fractions (wire_0 / wire_1 / wire_2 push unconditionally
///   when the outer `ace_flag` fires).
/// - **Perm-link** on hasher controller rows: 1 fraction (one of ctrl_input / ctrl_output, split by
///   `s0`).
///
/// Per-row max is therefore `max(3, 1) = 3`.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 3;

/// Emit the `v_wiring` shared column: ACE wiring + hasher perm-link.
pub(in crate::constraints::lookup) fn emit_v_wiring<LB>(
    builder: &mut LB,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
{
    let local = ctx.local;

    // ---- ACE wiring captures (Group 1) ----
    let ace_flag = ctx.chiplet_active.ace.clone();

    // Typed ACE chiplet overlay. `read()` exposes `m_0` / `m_1`, `eval()` exposes `v_2`;
    // wiring uses both overlays because its `sblock`-muxed multiplicities combine the
    // READ and EVAL row interpretations onto one column.
    let ace = local.ace();
    let ace_read = ace.read();
    let ace_eval = ace.eval();

    // Prefixed with `ace_` where the shorter name would clash with the outer function
    // parameter `ctx`.
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

    // ---- Perm-link captures ----
    // Controller-side row-kind flags. `is_input = s0` (deg 1); `is_output = (1-s0)*(1-s1)`
    // (deg 2). Padding rows (`s0=0, s1=1`) are excluded automatically by both expressions.
    let ctrl = local.controller();
    let s0c: LB::Expr = ctrl.s0.into();
    let s1c: LB::Expr = ctrl.s1.into();
    let is_input = s0c.clone();
    let is_output = (LB::Expr::ONE - s0c) * (LB::Expr::ONE - s1c);

    let controller_flag = ctx.chiplet_active.controller.clone();

    let f_ctrl_input = controller_flag.clone() * is_input;
    let f_ctrl_output = controller_flag * is_output;

    let ctrl_state: [LB::Var; STATE_WIDTH] = array::from_fn(|i| ctrl.state[i]);
    let perm_id = ctrl.perm_id;

    builder.next_column(
        |col| {
            // ACE rows and controller rows are mutually exclusive, so this group has at most one
            // active batch per row.
            col.group(
                "ace_perm_link",
                |g| {
                    // ---- ACE wiring (BusId::AceWiring) ----
                    //
                    // Single `ace_flag`-gated batch with `sblock`-muxed multiplicities for wire_1
                    // and wire_2. `wire_0`'s `m_0` is invariant across the READ/EVAL split, so it
                    // lives in the batch as a plain trace-column multiplicity.
                    g.batch(
                        "ace_wiring",
                        ace_flag,
                        move |b| {
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
                            b.insert("wire_0", m_0, wire_0, Deg { v: 5, u: 5 });

                            let wire_1 = AceWireMsg {
                                clk: ace_clk.into(),
                                ctx: ace_ctx.into(),
                                id: id_1.into(),
                                v0: v_1.0.into(),
                                v1: v_1.1.into(),
                            };
                            b.insert("wire_1", wire_1_mult, wire_1, Deg { v: 6, u: 5 });

                            let wire_2 = AceWireMsg {
                                clk: ace_clk.into(),
                                ctx: ace_ctx.into(),
                                id: id_2.into(),
                                v0: v_2.0.into(),
                                v1: v_2.1.into(),
                            };
                            b.insert("wire_2", wire_2_mult, wire_2, Deg { v: 5, u: 5 });
                        },
                        Deg { v: 8, u: 7 }, // (V, U) = (4 + 4, 3 + 4); ace_flag deg 4
                    );

                    // ---- Hasher perm-link (BusId::HasherPermLink{Input,Output}) ----

                    // Controller input: +1 / encode(perm_id, ctrl.state) on HasherPermLinkInput.
                    g.add(
                        "perm_ctrl_input",
                        f_ctrl_input,
                        move || {
                            let state: [LB::Expr; STATE_WIDTH] = ctrl_state.map(Into::into);
                            HasherPermLinkMsg::Input { perm_id: perm_id.into(), state }
                        },
                        Deg { v: 2, u: 3 },
                    );

                    // Controller output: +1 / encode(perm_id, ctrl.state) on HasherPermLinkOutput.
                    g.add(
                        "perm_ctrl_output",
                        f_ctrl_output,
                        move || {
                            let state: [LB::Expr; STATE_WIDTH] = ctrl_state.map(Into::into);
                            HasherPermLinkMsg::Output { perm_id: perm_id.into(), state }
                        },
                        Deg { v: 3, u: 4 },
                    );
                },
                Deg { v: 8, u: 7 },
            );
        },
        Deg { v: 8, u: 7 },
    );
}
