//! Controller sub-chiplet constraints (dispatch side).
//!
//! The hasher uses a dispatch/compute split architecture: the **controller** (this module)
//! records permutation requests as compact (input, output) row pairs and responds to the
//! chiplets bus; the **permutation** sub-chiplet executes the actual Poseidon2 cycles.
//! A LogUp perm-link bus on the shared `v_wiring` column binds the two regions.
//!
//! The controller is active when `s_ctrl = chiplets[0] = 1`, which covers ALL controller
//! rows (input, output, and padding).
//!
//! ## Sub-modules
//!
//! - [`flags`]: Pre-computed [`ControllerFlags`](flags::ControllerFlags) struct
//! - [`merkle`]: Merkle tree constraints (input, output, and cross-step)
//!
//! ## Constraint organization by gate
//!
//! | Gate | Constraints |
//! |------|-------------|
//! | `when_first_row` | first-row boundary (row 0 is controller input) |
//! | `is_active` (all ctrl rows) | s0/s1/s2 sub-selector booleanity |
//! | `on_input` (input rows) | adjacency, index decomposition, direction_bit booleanity/confinement, sponge index zero, Merkle capacity zeroing, lifecycle booleanity |
//! | `on_output` / `on_hout` / `on_sout` (output rows) | output non-adjacency, HOUT node_index=0, direction_bit confinement, lifecycle booleanity |
//! | `on_padding` (padding rows) | padding stability, is_boundary/direction_bit confinement |
//! | `is_transition` (consecutive ctrl rows) | mrupdate_id progression, respan capacity, cross-step Merkle index, digest routing |

pub mod flags;
pub mod merkle;

use flags::ControllerFlags;
use miden_crypto::stark::air::AirBuilder;

use crate::{
    MainCols, MidenAirBuilder,
    constraints::{
        chiplets::{columns::ControllerCols, selectors::ChipletFlags},
        utils::BoolNot,
    },
};

// ENTRY POINT
// ================================================================================================

/// Enforce all controller sub-chiplet constraints.
///
/// Receives pre-computed [`ChipletFlags`] from `build_chiplet_selectors`. The `s_ctrl`
/// column (`chiplets[0]`) is never referenced directly by constraint code.
pub fn enforce_controller_constraints<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let cols: &ControllerCols<AB::Var> = local.controller();
    let cols_next: &ControllerCols<AB::Var> = next.controller();

    let cf = ControllerFlags::new(flags, cols, cols_next);

    // =====================================================================
    // GLOBAL CONSTRAINTS
    // =====================================================================

    // --- First-row boundary ---
    // The first row of the trace must be a controller input row (s_ctrl=1 and s0=1).
    // on_input = is_active * s0 = s_ctrl * s0; asserting on_input=1 forces both
    // factors to be 1 because the only solution to a product of booleans equaling 1
    // is all factors = 1.
    // NOTE: this assumes the controller is the first chiplet section in the trace.
    // The transition rules (s_ctrl → s_ctrl' + s_perm' = 1) and the trace layout
    // guarantee this, but a reordering of chiplet sections would require moving
    // this constraint.
    builder.when_first_row().assert_one(cf.on_input.clone());

    // =====================================================================
    // ALL-ROW CONSTRAINTS (gated by is_active = s_ctrl)
    // =====================================================================

    // --- Sub-selector booleanity ---
    // s0, s1, s2 are binary on all controller rows. On permutation rows, these
    // columns hold S-box witnesses and are unconstrained.
    {
        let builder = &mut builder.when(cf.is_active.clone());
        builder.assert_bool(cols.s0);
        builder.assert_bool(cols.s1);
        builder.assert_bool(cols.s2);
    }

    // =====================================================================
    // INPUT-ROW CONSTRAINTS (gated by on_input or sub-flags)
    // =====================================================================

    // --- Controller adjacency (input → output) ---
    // On input rows (s0=1), the next row must be an output row (s0=0, s1=0).
    // This pairs with the output non-adjacency constraint below to guarantee
    // strictly alternating (input, output) pairs.
    {
        let builder = &mut builder.when(cf.on_input.clone());
        builder.assert_zero(cols_next.s0);
        builder.assert_zero(cols_next.s1);
    }

    // --- Merkle input constraints (index decomposition, capacity zeroing) ---
    merkle::enforce_node_index_constraints(builder, cols, cols_next, &cf);
    merkle::enforce_merkle_input_state(builder, cols, &cf);

    // --- direction_bit confinement on sponge input rows ---
    // Sponge operations (LINEAR_HASH, 2-to-1, HPERM) don't use direction_bit.
    builder.when(cf.on_sponge.clone()).assert_zero(cols.direction_bit);

    // --- is_boundary booleanity on input rows ---
    builder.when(cf.on_input.clone()).assert_bool(cols.is_boundary);

    // =====================================================================
    // OUTPUT-ROW CONSTRAINTS (gated by on_output / on_hout / on_sout)
    // =====================================================================

    // --- HOUT, SOUT, lifecycle, direction_bit confinement ---
    merkle::enforce_output_constraints(builder, cols, &cf);

    // --- Output non-adjacency ---
    // An output row cannot be followed by another output row. Combined with the
    // adjacency constraint (input → output) above, this guarantees strictly
    // alternating (input, output) pairs.
    // is_transition gates on s_ctrl' to avoid reading controller columns on perm/s0
    // rows where s0/s1 hold S-box witnesses.
    // Degree: is_transition(3) * on_output(3) * f_output_next(2) = 8. The s_ctrl
    // factor appears in both is_transition and on_output but s_ctrl is boolean so
    // s_ctrl² = s_ctrl; the effective gate is on_output * s_ctrl' * f_output_next.
    builder
        .when(cf.is_transition.clone())
        .when(cf.on_output.clone())
        .assert_zero(cf.f_output_next.clone());

    // =====================================================================
    // PADDING-ROW CONSTRAINTS (gated by on_padding)
    // =====================================================================

    // --- Padding stability ---
    // A padding row may only be followed by another controller row that is also
    // padding (or by the first permutation row, which ends the controller section).
    // We gate on `flags.is_transition` = `is_transition * s_ctrl * s_ctrl'`, so the
    // constraint vanishes on the last padding row when the next row is a permutation
    // row (where `cols_next.s0/s1` hold S-box witnesses, not selectors).
    // Degree: is_transition(3) * on_padding(3) * selector(1) = 7.
    {
        let gate = flags.is_transition.clone() * cf.on_padding.clone();
        let builder = &mut builder.when(gate);

        // No input row (s0_next=1) after padding.
        builder.assert_zero(cols_next.s0);

        // No output row (s1_next=0) after padding — next must have s1=1.
        builder.assert_one(cols_next.s1);
    }

    // --- Padding confinement ---
    // is_boundary and direction_bit must be zero on padding rows.
    {
        let builder = &mut builder.when(cf.on_padding.clone());
        builder.assert_zero(cols.is_boundary);
        builder.assert_zero(cols.direction_bit);
    }

    // =====================================================================
    // TRANSITION CONSTRAINTS (gated by is_transition)
    //
    // is_transition fires on consecutive controller rows (input→output,
    // output→next_input, padding→padding). The specific sub-type is
    // distinguished by the on_output / on_input flags and is_boundary.
    // =====================================================================

    // --- mrupdate_id progression ---
    // On controller→controller transitions: mrupdate_id_next = mrupdate_id + f_mv_start_next.
    // f_mv_start_next = f_mv_next * is_boundary_next (MV input with is_boundary=1).
    // Degree: is_transition(3) * (diff + f_mv_start)(4) = 7.
    {
        let f_mv_start_next = cf.f_mv_next.clone() * cols_next.is_boundary;
        builder
            .when(cf.is_transition.clone())
            .assert_eq(cols_next.mrupdate_id, AB::Expr::from(cols.mrupdate_id) + f_mv_start_next);
    }

    // --- Respan capacity preservation ---
    // During multi-batch linear hashing (RESPAN), each new batch overwrites the rate
    // (h0..h7) but the capacity (h8..h11) must carry over from the previous permutation
    // output. Without this, a prover could inject arbitrary capacity values on
    // continuation rows, corrupting the sponge state.
    // f_sponge_next restricts this to LINEAR_HASH continuations only (Merkle ops zero
    // capacity at each level). is_transition guarantees both rows are controller rows.
    // Degree: is_transition(3) * f_sponge_next(3) * (1-is_boundary')(1) * diff(1) = 8.
    {
        let gate = cf.is_transition.clone()
            * cf.f_sponge_next.clone()
            * AB::Expr::from(cols_next.is_boundary).not();

        let cap: [AB::Expr; 4] = core::array::from_fn(|i| cols.capacity()[i].into());
        let cap_next: [AB::Expr; 4] = core::array::from_fn(|i| cols_next.capacity()[i].into());

        let builder = &mut builder.when(gate);
        for i in 0..4 {
            builder.assert_eq(cap_next[i].clone(), cap[i].clone());
        }
    }

    // --- Cross-step Merkle index and digest routing ---
    merkle::enforce_cross_step_merkle_index(builder, cols, cols_next, &cf);
    merkle::enforce_merkle_digest_routing(builder, cols, cols_next, &cf);
}
