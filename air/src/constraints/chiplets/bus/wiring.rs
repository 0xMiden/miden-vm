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
//! `alpha[0] + alpha[1] * clk + alpha[2] * ctx + alpha[3] * id + alpha[4] * v0 + alpha[5] * v1`
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

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::{air::MidenAirBuilder, matrix::Matrix};

use crate::{
    Felt, MainTraceRow,
    constraints::{
        bus::{MessageEncoder, alphas_from_challenges, indices::V_WIRING},
        chiplets::selectors::ace_chiplet_flag,
        tagging::{
            TagGroup, TaggingAirBuilderExt, ids::TAG_WIRING_BUS_BASE, tagged_assert_zero_ext,
        },
    },
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
const NUM_WIRING_ALPHAS: usize = 6;

/// Tag IDs and namespaces for wiring bus constraints.
const WIRING_BUS_BASE_ID: usize = TAG_WIRING_BUS_BASE;
const WIRING_BUS_NAME: &str = "chiplets.bus.wiring.transition";
const WIRING_BUS_NAMES: [&str; 1] = [WIRING_BUS_NAME; 1];
const WIRING_BUS_TAGS: TagGroup = TagGroup {
    base: WIRING_BUS_BASE_ID,
    names: &WIRING_BUS_NAMES,
};

// ENTRY POINTS
// ================================================================================================

/// Enforces the ACE wiring bus constraint.
pub fn enforce_wiring_bus_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    _next: &MainTraceRow<AB::Var>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // ---------------------------------------------------------------------
    // Auxiliary trace access.
    // ---------------------------------------------------------------------

    let (v_local, v_next, alphas) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        let v_local = aux_local[V_WIRING];
        let v_next = aux_next[V_WIRING];

        let challenges = builder.permutation_randomness();
        let alphas: [AB::ExprEF; NUM_WIRING_ALPHAS] =
            alphas_from_challenges::<AB, NUM_WIRING_ALPHAS>(challenges);
        (v_local, v_next, alphas)
    };

    // ---------------------------------------------------------------------
    // Chiplet selectors.
    // ---------------------------------------------------------------------

    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s2: AB::Expr = local.chiplets[2].clone().into();
    let s3: AB::Expr = local.chiplets[3].clone().into();
    let ace_flag = ace_chiplet_flag(s0, s1, s2, s3);

    // Block selector: sblock = 0 for READ, sblock = 1 for EVAL.
    let sblock: AB::Expr = load_ace_col::<AB>(local, SELECTOR_BLOCK_IDX);
    let is_eval = sblock.clone();
    let is_read = AB::Expr::ONE - sblock;

    // ---------------------------------------------------------------------
    // Load ACE columns.
    // ---------------------------------------------------------------------

    let clk: AB::Expr = load_ace_col::<AB>(local, CLK_IDX);
    let ctx: AB::Expr = load_ace_col::<AB>(local, CTX_IDX);

    let wire_0 = load_ace_wire::<AB>(local, ID_0_IDX, V_0_0_IDX, V_0_1_IDX);
    let wire_1 = load_ace_wire::<AB>(local, ID_1_IDX, V_1_0_IDX, V_1_1_IDX);
    let wire_2 = load_ace_wire::<AB>(local, ID_2_IDX, V_2_0_IDX, V_2_1_IDX);
    let m0: AB::Expr = load_ace_col::<AB>(local, M_0_IDX);
    // On READ rows this column stores m1 (fan-out for wire_1). On EVAL rows it is v2_1,
    // but we only use it under the READ gate below.
    let m1: AB::Expr = load_ace_col::<AB>(local, M_1_IDX);

    // ---------------------------------------------------------------------
    // Wire value computation.
    // ---------------------------------------------------------------------

    let encoder = MessageEncoder::<AB, 5>::from_challenges(&alphas);
    let wire_0: AB::ExprEF = encode_wire::<AB>(&encoder, &clk, &ctx, &wire_0);
    let wire_1: AB::ExprEF = encode_wire::<AB>(&encoder, &clk, &ctx, &wire_1);
    let wire_2: AB::ExprEF = encode_wire::<AB>(&encoder, &clk, &ctx, &wire_2);

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

    let mut idx = 0;
    tagged_assert_zero_ext(builder, &WIRING_BUS_TAGS, &mut idx, wiring_constraint);
}

// INTERNAL HELPERS
// ================================================================================================

/// ACE wire triplet (id, v0, v1).
struct AceWire<Expr> {
    id: Expr,
    v0: Expr,
    v1: Expr,
}

/// Load an ACE wire (id, v0, v1) from the chiplet slice.
fn load_ace_wire<AB>(
    row: &MainTraceRow<AB::Var>,
    id_idx: usize,
    v0_idx: usize,
    v1_idx: usize,
) -> AceWire<AB::Expr>
where
    AB: MidenAirBuilder<F = Felt>,
{
    AceWire {
        id: load_ace_col::<AB>(row, id_idx),
        v0: load_ace_col::<AB>(row, v0_idx),
        v1: load_ace_col::<AB>(row, v1_idx),
    }
}

/// Encode an ACE wire using the wiring-bus challenge vector.
fn encode_wire<AB>(
    encoder: &MessageEncoder<AB, 5>,
    clk: &AB::Expr,
    ctx: &AB::Expr,
    wire: &AceWire<AB::Expr>,
) -> AB::ExprEF
where
    AB: MidenAirBuilder<F = Felt>,
{
    encoder.encode([clk.clone(), ctx.clone(), wire.id.clone(), wire.v0.clone(), wire.v1.clone()])
}

/// Load a column from the ACE section of chiplets.
fn load_ace_col<AB>(row: &MainTraceRow<AB::Var>, ace_col_idx: usize) -> AB::Expr
where
    AB: MidenAirBuilder<F = Felt>,
{
    let local_idx = ACE_OFFSET + ace_col_idx;
    row.chiplets[local_idx].clone().into()
}
