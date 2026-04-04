//! ACE wiring bus constraint.
//!
//! This module enforces the running-sum constraint for the ACE wiring bus (v_wiring).
//! The wiring bus verifies the wiring of the arithmetic circuit (which node feeds which gate).
//! It does this by enforcing that every node (id, value) inserted into the ACE DAG is later
//! consumed the claimed number of times, via a LogUp running‑sum relation.
//!
//! ## Wire message format
//!
//! Each wire is encoded as:
//! `alpha + beta^0 * clk + beta^1 * ctx + beta^2 * id + beta^3 * v0 + beta^4 * v1`
//!
//! Where:
//! - clk: memory access clock cycle
//! - ctx: memory access context
//! - id: node identifier
//! - v0, v1: extension field element coefficients
//!
//! ## LogUp protocol
//!
//! **READ blocks (sblock = 0):**
//! - Insert wire_0 with multiplicity m0.
//! - Insert wire_1 with multiplicity m1.
//!
//! **EVAL blocks (sblock = 1):**
//! - Insert wire_0 with multiplicity m0.
//! - Remove wire_1 with multiplicity 1.
//! - Remove wire_2 with multiplicity 1.
//!
//! Boundary constraints for v_wiring are handled by the wrapper AIR (aux_finals).

use miden_crypto::stark::air::{ExtensionBuilder, WindowAccess};

use crate::{
    MainCols, MidenAirBuilder,
    constraints::{bus::indices::V_WIRING, chiplets::selectors::ChipletSelectors, utils::BoolNot},
    trace::{Challenges, bus_types::ACE_WIRING_BUS},
};

// ENTRY POINTS
// ================================================================================================

/// Enforces the ACE wiring bus constraint.
pub fn enforce_wiring_bus_constraint<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    _next: &MainCols<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // ---------------------------------------------------------------------
    // Auxiliary trace access.
    // ---------------------------------------------------------------------

    let (v_local, v_next) = {
        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();
        (aux_local[V_WIRING], aux_next[V_WIRING])
    };

    // ---------------------------------------------------------------------
    // Chiplet selectors.
    // ---------------------------------------------------------------------

    let ace_flag = selectors.ace.is_active.clone();

    let ace = local.ace();

    // Block selector: sblock = 0 for READ, sblock = 1 for EVAL.
    let sblock: AB::Expr = ace.s_block.into();
    let is_eval = sblock.clone();
    let is_read = sblock.not();

    // ---------------------------------------------------------------------
    // Load ACE columns.
    // ---------------------------------------------------------------------

    let clk: AB::Expr = ace.clk.into();
    let ctx: AB::Expr = ace.ctx.into();

    let wire_0 = AceWire {
        id: ace.id_0.into(),
        v0: ace.v_0.0.into(),
        v1: ace.v_0.1.into(),
    };
    let wire_1 = AceWire {
        id: ace.id_1.into(),
        v0: ace.v_1.0.into(),
        v1: ace.v_1.1.into(),
    };
    let wire_2 = AceWire {
        id: ace.eval().id_2.into(),
        v0: ace.eval().v_2.0.into(),
        v1: ace.eval().v_2.1.into(),
    };
    let m0: AB::Expr = ace.read().m_0.into();
    // On READ rows this column stores m1 (fan-out for wire_1). On EVAL rows it is v2_1,
    // but we only use it under the READ gate below.
    let m1: AB::Expr = ace.read().m_1.into();

    // ---------------------------------------------------------------------
    // Wire value computation.
    // ---------------------------------------------------------------------

    let wire_0: AB::ExprEF = encode_wire::<AB>(challenges, &clk, &ctx, &wire_0);
    let wire_1: AB::ExprEF = encode_wire::<AB>(challenges, &clk, &ctx, &wire_1);
    let wire_2: AB::ExprEF = encode_wire::<AB>(challenges, &clk, &ctx, &wire_2);

    // ---------------------------------------------------------------------
    // Transition constraint.
    // ---------------------------------------------------------------------
    //
    // LogUp definition:
    //   v' - v = Σ (num_i / den_i)
    //
    // READ rows:
    //   v' - v = m0 / wire_0 + m1 / wire_1
    //
    // EVAL rows:
    //   v' - v = m0 / wire_0 - 1 / wire_1 - 1 / wire_2
    //
    // Multiply by the common denominator wire_0 * wire_1 * wire_2 to stay in a
    // single polynomial form; the READ/EVAL gates select the appropriate RHS.

    let v_local_ef: AB::ExprEF = v_local.into();
    let v_next_ef: AB::ExprEF = v_next.into();
    let delta = v_next_ef.clone() - v_local_ef.clone();

    // RHS under the common denominator:
    // - READ:  m0 * w1 * w2 + m1 * w0 * w2
    // - EVAL:  m0 * w1 * w2 - w0 * w2 - w0 * w1
    let read_terms =
        wire_1.clone() * wire_2.clone() * m0.clone() + wire_0.clone() * wire_2.clone() * m1;
    let eval_terms = wire_1.clone() * wire_2.clone() * m0
        - wire_0.clone() * wire_2.clone()
        - wire_0.clone() * wire_1.clone();

    // Gates: non-ACE rows must contribute zero; READ/EVAL are mutually exclusive.
    let read_gate = ace_flag.clone() * is_read;
    let eval_gate = ace_flag * is_eval;

    let common_den = wire_0.clone() * wire_1.clone() * wire_2.clone();
    let rhs = read_terms * read_gate + eval_terms * eval_gate;
    let wiring_constraint = delta * common_den - rhs;

    builder.when_transition().assert_zero_ext(wiring_constraint);
}

// INTERNAL HELPERS
// ================================================================================================

/// ACE wire triplet (id, v0, v1).
struct AceWire<Expr> {
    id: Expr,
    v0: Expr,
    v1: Expr,
}

/// Encode an ACE wire using the wiring-bus challenge vector.
fn encode_wire<AB>(
    challenges: &Challenges<AB::ExprEF>,
    clk: &AB::Expr,
    ctx: &AB::Expr,
    wire: &AceWire<AB::Expr>,
) -> AB::ExprEF
where
    AB: MidenAirBuilder,
{
    challenges.encode(
        ACE_WIRING_BUS,
        [clk.clone(), ctx.clone(), wire.id.clone(), wire.v0.clone(), wire.v1.clone()],
    )
}
