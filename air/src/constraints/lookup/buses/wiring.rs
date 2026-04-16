//! `v_wiring` shared bus column (C3 / `BUS_ACE_WIRING` + `BUS_HASHER_PERM_LINK`).
//!
//! Both buses live inside **one** [`super::super::LookupColumn::group`] call. The chiplet
//! tri-state (`s_ctrl + s_perm + s0_virtual = 1`) makes ACE rows, hasher controller rows,
//! and hasher permutation rows pairwise mutually exclusive, so the simple-group
//! composition `U_g += (d_i − 1)·f_i`, `V_g += m_i·f_i` is sound: at most one of the five
//! interactions fires per row, and the column's running `(U, V)` takes MAX over per-
//! interaction degrees rather than summing them (which a sibling-group split would do).
//! The two buses' denominators use distinct `bus_prefix[bus]` additive bases, so even
//! though they share the same accumulator their contributions are linearly independent in
//! the extension field and cannot cancel across buses.
//!
//! ## ACE wiring (`BUS_ACE_WIRING`)
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
//! ## Hasher perm-link (`BUS_HASHER_PERM_LINK`)
//!
//! Binds hasher controller rows to permutation sub-chiplet rows. Without this bus the
//! permutation segment is structurally independent from the controller, and a malicious
//! prover could pair any controller `(state_in, state_out)` with any perm-cycle execution
//! (or skip the cycle entirely). Four mutually exclusive interactions:
//!
//! - **Controller input** (`s_ctrl · is_input`, multiplicity `+1`, `label = 0`) — controller side
//!   of a (state_in, state_out) pair.
//! - **Controller output** (`s_ctrl · is_output`, multiplicity `+1`, `label = 1`).
//! - **Permutation row 0** (`s_perm · is_init_ext`, multiplicity `−m`, `label = 0`) — input
//!   boundary of a Poseidon2 cycle. `m` is read from `PermutationCols.multiplicity` and is constant
//!   within the cycle by [`crate::constraints::chiplets::permutation`].
//! - **Permutation row 15** (`s_perm · (1 − periodic_sum)`, multiplicity `−m`, `label = 1`) —
//!   output boundary of the same cycle.
//!
//! The widest perm-link contribution is `f_ctrl_output` with gate degree 3 — strictly below
//! the ACE batch's `(7, 8)` — so merging into the same group leaves the column's transition
//! at `max(1 + 7, 8) = 8`.

use core::{array, borrow::Borrow};

use miden_core::field::PrimeCharacteristicRing;

use crate::constraints::{
    chiplets::columns::PeriodicCols,
    logup_msg::{AceWireMsg, HasherPermLinkMsg},
    lookup::{
        LookupBatch, LookupColumn, LookupGroup,
        chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
    },
    utils::BoolNot,
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Single group hosts both buses. The chiplet tri-state makes ACE, hasher-controller, and
/// hasher-permutation rows pairwise mutually exclusive, so on any given row only one of:
/// - **ACE wiring batch** on ACE rows: 3 fractions (wire_0 / wire_1 / wire_2 push unconditionally
///   when the outer `ace_flag` fires).
/// - **Perm-link** on hasher controller rows: 1 fraction (one of ctrl_input / ctrl_output, split by
///   `s0`).
/// - **Perm-link** on hasher permutation rows: 1 fraction (one of row 0 / row 15, split by the
///   periodic cycle schedule).
///
/// Per-row max is therefore `max(3, 1, 1) = 3`.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 3;

/// Emit the `v_wiring` shared column (C3): ACE wiring + hasher perm-link.
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

    // ---- Perm-link captures (Group 2) ----

    // Periodic Poseidon2 cycle selectors. `is_init_ext` is 1 on cycle row 0 only; the four
    // selectors together cover rows 0..14, so `1 - sum` is 1 only on the cycle boundary
    // row 15. The `permutation/mod.rs` cycle-alignment constraints pin perm row 0 to cycle
    // row 0 and perm row 15 to cycle row 15.
    let (perm_row0_select, perm_row15_select): (LB::Expr, LB::Expr) = {
        let periodic: &PeriodicCols<LB::PeriodicVar> = builder.periodic_values().borrow();
        let h = periodic.hasher;
        let is_init_ext: LB::Expr = h.is_init_ext.into();
        let is_ext: LB::Expr = h.is_ext.into();
        let is_packed_int: LB::Expr = h.is_packed_int.into();
        let is_int_ext: LB::Expr = h.is_int_ext.into();
        let not_cycle_end = is_init_ext.clone() + is_ext + is_packed_int + is_int_ext;
        (is_init_ext, LB::Expr::ONE - not_cycle_end)
    };

    // Controller-side row-kind flags. `is_input = s0` (deg 1); `is_output = (1-s0)*(1-s1)`
    // (deg 2). Padding rows (`s0=0, s1=1`) are excluded automatically by both expressions.
    let ctrl = local.controller();
    let s0c: LB::Expr = ctrl.s0.into();
    let s1c: LB::Expr = ctrl.s1.into();
    let is_input = s0c.clone();
    let is_output = (LB::Expr::ONE - s0c) * (LB::Expr::ONE - s1c);

    let controller_flag = ctx.chiplet_active.controller.clone();
    let permutation_flag = ctx.chiplet_active.permutation.clone();

    let f_ctrl_input = controller_flag.clone() * is_input;
    let f_ctrl_output = controller_flag * is_output;
    let f_perm_row0 = permutation_flag.clone() * perm_row0_select;
    let f_perm_row15 = permutation_flag * perm_row15_select;

    let ctrl_state: [LB::Var; 12] = array::from_fn(|i| ctrl.state[i]);
    let perm = local.permutation();
    let perm_state: [LB::Var; 12] = array::from_fn(|i| perm.state[i]);
    let perm_mult = perm.multiplicity;

    builder.next_column(|col| {
        // Single group hosts both buses. ACE rows (`chiplet_active.ace`), controller rows
        // (`chiplet_active.controller`), and permutation rows (`chiplet_active.permutation`)
        // are pairwise mutually exclusive via the chiplet tri-state, so the simple-group
        // composition is sound. Merging into one group takes MAX over per-interaction
        // degrees instead of multiplying sibling `(U_g, V_g)` pairs — critical for keeping
        // this column's transition inside the degree-9 budget.
        col.group(|g| {
            // ---- ACE wiring (BUS_ACE_WIRING) ----
            //
            // Single `ace_flag`-gated batch with `sblock`-muxed multiplicities for wire_1
            // and wire_2. `wire_0`'s `m_0` is invariant across the READ/EVAL split, so it
            // lives in the batch as a plain trace-column multiplicity.
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

            // ---- Hasher perm-link (BUS_HASHER_PERM_LINK) ----

            // Controller input: +1 / encode(label=0, ctrl.state).
            g.add(f_ctrl_input, move || {
                let state: [LB::Expr; 12] = ctrl_state.map(Into::into);
                HasherPermLinkMsg { label: LB::Expr::ZERO, state }
            });

            // Controller output: +1 / encode(label=1, ctrl.state).
            g.add(f_ctrl_output, move || {
                let state: [LB::Expr; 12] = ctrl_state.map(Into::into);
                HasherPermLinkMsg { label: LB::Expr::ONE, state }
            });

            // Perm row 0: -m / encode(label=0, perm.state). Multiplicity is `0 - m` so the
            // LogUp accumulator subtracts the fraction.
            let perm_mult_input: LB::Expr = LB::Expr::ZERO - perm_mult.into();
            g.insert(f_perm_row0, perm_mult_input, move || {
                let state: [LB::Expr; 12] = perm_state.map(Into::into);
                HasherPermLinkMsg { label: LB::Expr::ZERO, state }
            });

            // Perm row 15: -m / encode(label=1, perm.state).
            let perm_mult_output: LB::Expr = LB::Expr::ZERO - perm_mult.into();
            g.insert(f_perm_row15, perm_mult_output, move || {
                let state: [LB::Expr; 12] = perm_state.map(Into::into);
                HasherPermLinkMsg { label: LB::Expr::ONE, state }
            });
        });
    });
}
