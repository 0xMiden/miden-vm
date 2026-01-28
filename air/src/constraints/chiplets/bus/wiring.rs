//! ACE Wiring bus constraint.
//!
//! This module enforces the running sum constraint for the ACE chiplet wiring bus (v_wiring).
//! The wiring bus tracks node definitions and consumptions in the ACE circuit using LogUp.
//!
//! ## Wire Message Format
//!
//! Each wire is encoded as:
//! `alphas[0] + alphas[1] * clk + alphas[2] * ctx + alphas[3] * id + alphas[4] * v0 + alphas[5] *
//! v1`
//!
//! Where:
//! - clk: Memory access clock cycle
//! - ctx: Memory access context
//! - id: Node identifier
//! - v0, v1: Extension field element coefficients
//!
//! ## LogUp Protocol
//!
//! The bus uses LogUp to track node definitions and consumptions:
//!
//! **READ blocks (sblock = 0):**
//! - Insert wire_0: (clk, ctx, id0, v0_0, v0_1) with multiplicity m0
//! - Insert wire_1: (clk, ctx, id1, v1_0, v1_1) with multiplicity m1
//!
//! **EVAL blocks (sblock = 1):**
//! - Insert wire_0: (clk, ctx, id0, v0_0, v0_1) with multiplicity m0
//! - Remove wire_1: (clk, ctx, id1, v1_0, v1_1) with multiplicity 1
//! - Remove wire_2: (clk, ctx, id2, v2_0, v2_1) with multiplicity 1
//!
//! **Outside ACE chiplet:** no constraints applied (v_wiring is unconstrained)
//!
//! ## Boundary Constraints
//!
//! - v_wiring is forced to 0 on ACE entry and ACE exit transitions

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;
use p3_matrix::Matrix;

use crate::{
    Felt, MainTraceRow,
    constraints::{bus::indices::V_WIRING, chiplets::selectors::ace_chiplet_flag},
    trace::chiplets::ace::{
        CLK_IDX, CTX_IDX, ID_0_IDX, ID_1_IDX, ID_2_IDX, M_0_IDX, M_1_IDX, SELECTOR_BLOCK_IDX,
        V_0_0_IDX, V_0_1_IDX, V_1_0_IDX, V_1_1_IDX, V_2_0_IDX, V_2_1_IDX,
    },
};

// CONSTANTS
// ================================================================================================

// ACE chiplet offset from CHIPLETS_OFFSET (after s0, s1, s2, s3).
const ACE_OFFSET: usize = 4;

/// Number of random challenges needed for wiring bus.
/// Format: alpha[0] + alpha[1]*clk + alpha[2]*ctx + alpha[3]*id + alpha[4]*v0 + alpha[5]*v1
pub const NUM_WIRING_ALPHAS: usize = 6;

// ENTRY POINTS
// ================================================================================================

/// Enforces the ACE wiring bus constraint.
///
/// This constraint tracks wire connections in the ACE chiplet using LogUp:
/// - READ blocks: insert two nodes with multiplicities m0, m1
/// - EVAL blocks: insert one node (m0), remove two nodes (multiplicity 1 each)
pub fn enforce_wiring_bus_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // =========================================================================
    // AUXILIARY TRACE ACCESS
    // =========================================================================

    let (v_local, v_next, alphas) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        let v_local = aux_local[V_WIRING];
        let v_next = aux_next[V_WIRING];

        let challenges = builder.permutation_randomness();
        // We need 6 random elements for wire encoding
        let alphas: [AB::ExprEF; NUM_WIRING_ALPHAS] = [
            challenges[0].into(),
            challenges[1].into(),
            challenges[2].into(),
            challenges[3].into(),
            challenges[4].into(),
            challenges[5].into(),
        ];
        (v_local, v_next, alphas)
    };

    // =========================================================================
    // CHIPLET SELECTORS
    // =========================================================================

    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s2: AB::Expr = local.chiplets[2].clone().into();
    let s3: AB::Expr = local.chiplets[3].clone().into();

    // ACE chiplet active: s0 * s1 * s2 * !s3
    let ace_flag = ace_chiplet_flag(s0, s1, s2, s3);
    let s0_next: AB::Expr = next.chiplets[0].clone().into();
    let s1_next: AB::Expr = next.chiplets[1].clone().into();
    let s2_next: AB::Expr = next.chiplets[2].clone().into();
    let s3_next: AB::Expr = next.chiplets[3].clone().into();
    let ace_flag_next = ace_chiplet_flag(s0_next, s1_next, s2_next, s3_next);

    // Block selector: sblock = 0 for READ, sblock = 1 for EVAL
    let sblock: AB::Expr = load_ace_col::<AB>(local, SELECTOR_BLOCK_IDX);
    let is_read = AB::Expr::ONE - sblock.clone();
    let is_eval = sblock;

    // =========================================================================
    // LOAD ACE COLUMNS
    // =========================================================================

    let clk: AB::Expr = load_ace_col::<AB>(local, CLK_IDX);
    let ctx: AB::Expr = load_ace_col::<AB>(local, CTX_IDX);

    // Wire 0: (id0, v0_0, v0_1) with multiplicity m0
    let id0: AB::Expr = load_ace_col::<AB>(local, ID_0_IDX);
    let v0_0: AB::Expr = load_ace_col::<AB>(local, V_0_0_IDX);
    let v0_1: AB::Expr = load_ace_col::<AB>(local, V_0_1_IDX);
    let m0: AB::Expr = load_ace_col::<AB>(local, M_0_IDX);

    // Wire 1: (id1, v1_0, v1_1) with multiplicity m1 (READ) or 1 (EVAL consume)
    let id1: AB::Expr = load_ace_col::<AB>(local, ID_1_IDX);
    let v1_0: AB::Expr = load_ace_col::<AB>(local, V_1_0_IDX);
    let v1_1: AB::Expr = load_ace_col::<AB>(local, V_1_1_IDX);
    let m1: AB::Expr = load_ace_col::<AB>(local, M_1_IDX);

    // Wire 2: (id2, v2_0, v2_1) - only used in EVAL
    let id2: AB::Expr = load_ace_col::<AB>(local, ID_2_IDX);
    let v2_0: AB::Expr = load_ace_col::<AB>(local, V_2_0_IDX);
    let v2_1: AB::Expr = load_ace_col::<AB>(local, V_2_1_IDX);

    // =========================================================================
    // WIRE VALUE COMPUTATION
    // =========================================================================

    // wire_value = alpha[0] + alpha[1]*clk + alpha[2]*ctx + alpha[3]*id + alpha[4]*v0 + alpha[5]*v1
    let wire_0: AB::ExprEF =
        compute_wire_value::<AB>(&alphas, clk.clone(), ctx.clone(), id0, v0_0, v0_1);
    let wire_1: AB::ExprEF =
        compute_wire_value::<AB>(&alphas, clk.clone(), ctx.clone(), id1, v1_0, v1_1);
    let wire_2: AB::ExprEF = compute_wire_value::<AB>(&alphas, clk, ctx, id2, v2_0, v2_1);

    // =========================================================================
    // TRANSITION CONSTRAINT
    // =========================================================================
    //
    // Using LogUp fractional sum:
    //   v' = v + sum(multiplicity_i / wire_i)
    //
    // READ block: v' = v + m0/wire_0 + m1/wire_1
    //   => (v' - v) * wire_0 * wire_1 = m0 * wire_1 + m1 * wire_0
    //
    // EVAL block: v' = v + m0/wire_0 - 1/wire_1 - 1/wire_2
    //   => (v' - v) * wire_0 * wire_1 * wire_2 = m0 * wire_1 * wire_2 - wire_0 * wire_2 - wire_0 *
    // wire_1
    //
    // Outside ACE: v' = v
    //   => v' - v = 0

    let v_local_ef: AB::ExprEF = v_local.into();
    let v_next_ef: AB::ExprEF = v_next.into();
    let delta = v_next_ef.clone() - v_local_ef.clone();

    // READ constraint: (v' - v) * wire_0 * wire_1 = m0 * wire_1 + m1 * wire_0
    let read_lhs = delta.clone() * wire_0.clone() * wire_1.clone();
    let read_rhs = wire_1.clone() * m0.clone() + wire_0.clone() * m1;
    let read_constraint = read_lhs - read_rhs;

    // EVAL constraint:
    // (v' - v) * wire_0 * wire_1 * wire_2 = m0 * wire_1 * wire_2 - wire_0 * wire_2 - wire_0 *
    // wire_1
    let eval_lhs = delta.clone() * wire_0.clone() * wire_1.clone() * wire_2.clone();
    let eval_rhs = wire_1.clone() * wire_2.clone() * m0
        - wire_0.clone() * wire_2.clone()
        - wire_0.clone() * wire_1.clone();
    let eval_constraint = eval_lhs - eval_rhs;

    // Apply constraints with appropriate flags.
    builder
        .when_transition()
        .assert_zero_ext(read_constraint * (ace_flag.clone() * is_read));
    builder
        .when_transition()
        .assert_zero_ext(eval_constraint * (ace_flag.clone() * is_eval));

    // Boundary constraints for the ACE chiplet:
    // The wiring bus is only meaningful during ACE execution, so we force it to be 0 on
    // entry to ACE and on exit from ACE. This replaces global boundary constraints and
    // keeps the bus unconstrained when ACE is never used.
    let enter_ace = (AB::Expr::ONE - ace_flag.clone()) * ace_flag_next.clone();
    let exit_ace = ace_flag * (AB::Expr::ONE - ace_flag_next);
    builder.when_transition().assert_zero_ext(v_next_ef.clone() * enter_ace);
    builder.when_transition().assert_zero_ext(v_next_ef * exit_ace);
}

// INTERNAL HELPERS
// ================================================================================================

/// Compute wire value encoding.
fn compute_wire_value<AB>(
    alphas: &[AB::ExprEF; NUM_WIRING_ALPHAS],
    clk: AB::Expr,
    ctx: AB::Expr,
    id: AB::Expr,
    v0: AB::Expr,
    v1: AB::Expr,
) -> AB::ExprEF
where
    AB: MidenAirBuilder<F = Felt>,
{
    alphas[0].clone()
        + alphas[1].clone() * clk
        + alphas[2].clone() * ctx
        + alphas[3].clone() * id
        + alphas[4].clone() * v0
        + alphas[5].clone() * v1
}

/// Load a column from the ACE section of chiplets.
fn load_ace_col<AB>(row: &MainTraceRow<AB::Var>, ace_col_idx: usize) -> AB::Expr
where
    AB: MidenAirBuilder<F = Felt>,
{
    let local_idx = ACE_OFFSET + ace_col_idx;
    row.chiplets[local_idx].clone().into()
}
