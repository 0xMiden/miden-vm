//! Controller sub-chiplet Merkle path and digest constraints.
//!
//! Merkle constraints apply only to controller rows (`s_ctrl = 1`). On permutation rows
//! (`s_perm = 1`), these columns hold witnesses and are constrained by the permutation
//! sub-chiplet instead.
//!
//! Constraints are organized by row type:
//!
//! - **Input-row constraints** (`on_input` / `on_sponge` / `on_merkle_input`): index decomposition,
//!   direction bit booleanity, sponge index zero, capacity zeroing
//! - **Output-row constraints** (`on_hout` / `on_sout` / `on_output`): HOUT node_index zero,
//!   direction_bit confinement, lifecycle booleanity
//! - **Transition constraints** (`is_transition`): cross-step Merkle index continuity,
//!   direction_bit forward propagation, digest routing

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use super::flags::ControllerFlags;
use crate::{
    MidenAirBuilder,
    constraints::{chiplets::columns::ControllerCols, utils::BoolNot},
};

// INPUT-ROW CONSTRAINTS
// ================================================================================================

/// Enforces node index constraints on controller input rows.
///
/// - Index decomposition: `idx = 2 * idx_next + direction_bit` on Merkle input rows
/// - Direction bit booleanity on Merkle input rows
/// - Sponge input index zero
pub fn enforce_node_index_constraints<AB>(
    builder: &mut AB,
    cols: &ControllerCols<AB::Var>,
    cols_next: &ControllerCols<AB::Var>,
    cf: &ControllerFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Index decomposition + booleanity on Merkle input rows.
    {
        let builder = &mut builder.when(cf.on_merkle_input.clone());

        // idx = 2 * idx_next + direction_bit
        builder.assert_eq(
            cols.node_index,
            AB::Expr::from(cols_next.node_index).double() + cols.direction_bit,
        );

        // direction_bit is binary
        builder.assert_bool(cols.direction_bit);
    }

    // Sponge input node_index must be zero.
    builder.when(cf.on_sponge.clone()).assert_zero(cols.node_index);
}

/// Enforces capacity zeroing on Merkle input rows.
///
/// All 4 capacity lanes h[8..12] must be zero on Merkle input rows, ensuring each
/// 2-to-1 compression in the Merkle path starts with a clean sponge capacity.
///
/// Degree: on_merkle_input(4) * capacity(1) = 5.
pub fn enforce_merkle_input_state<AB>(
    builder: &mut AB,
    cols: &ControllerCols<AB::Var>,
    cf: &ControllerFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let builder = &mut builder.when(cf.on_merkle_input.clone());
    for c in cols.capacity() {
        builder.assert_zero(c);
    }
}

// OUTPUT-ROW CONSTRAINTS
// ================================================================================================

/// Enforces constraints on output rows.
///
/// - HOUT `node_index = 0`
/// - HOUT `direction_bit = 0`
/// - SOUT+boundary `direction_bit = 0`
/// - Output `is_boundary` booleanity
pub fn enforce_output_constraints<AB>(
    builder: &mut AB,
    cols: &ControllerCols<AB::Var>,
    cf: &ControllerFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // is_boundary booleanity on output rows.
    builder.when(cf.on_output.clone()).assert_bool(cols.is_boundary);

    // HOUT: node_index = 0 and direction_bit = 0.
    {
        let builder = &mut builder.when(cf.on_hout.clone());
        builder.assert_zero(cols.node_index);
        builder.assert_zero(cols.direction_bit);
    }

    // SOUT+boundary: direction_bit = 0 on final RETURN_STATE output rows.
    builder
        .when(cf.on_sout.clone())
        .when(cols.is_boundary)
        .assert_zero(cols.direction_bit);
}

// TRANSITION CONSTRAINTS (cross-step)
// ================================================================================================

/// Enforces cross-step Merkle index continuity.
///
/// On non-final output rows, if the next row is a Merkle input, the node index
/// must carry over: `idx_next = idx`.
///
/// NOTE: `f_merkle_input_next` is read from `cf` without an explicit `is_active_next`
/// gate. This is safe because `cf.on_output` already gates on `is_active` (= `s_ctrl`),
/// and the transition rules enforce that the next row after a controller row must be
/// either another controller row or a permutation row — never a non-hasher row.
pub fn enforce_cross_step_merkle_index<AB>(
    builder: &mut AB,
    cols: &ControllerCols<AB::Var>,
    cols_next: &ControllerCols<AB::Var>,
    cf: &ControllerFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Gate: on_output(3) * (1-is_boundary)(1) * f_merkle_input_next(3) = 7
    // Constraint degree: gate(7) * diff(1) = 8
    builder
        .when(cf.on_output.clone())
        .when(AB::Expr::from(cols.is_boundary).not())
        .when(cf.f_merkle_input_next.clone())
        .assert_eq(cols_next.node_index, cols.node_index);
}

/// Enforces Merkle digest routing and direction_bit forward propagation.
///
/// ## Forward Propagation
///
/// On non-final output → next-input Merkle boundaries, the `direction_bit` on the output
/// must equal the `direction_bit` on the next input row. This makes `b_{i+1}` (the next
/// step's direction bit) available on the output row for digest routing.
///
/// ## Digest Routing
///
/// The digest from output_i (in rate0, `h[0..4]`) must appear in the correct rate half of
/// input_{i+1}, selected by direction_bit:
/// - `direction_bit = 0`: digest goes to rate0 of input_{i+1} (`h_next[j]`)
/// - `direction_bit = 1`: digest goes to rate1 of input_{i+1} (`h_next[4+j]`)
///
/// Uses a lightweight Merkle-next selector (`s1' + s2'`, degree 1) instead of the full
/// `f_merkle_input` (degree 3) to keep routing within the system's max degree of 9. See
/// inline comments for the soundness argument.
pub fn enforce_merkle_digest_routing<AB>(
    builder: &mut AB,
    cols: &ControllerCols<AB::Var>,
    cols_next: &ControllerCols<AB::Var>,
    cf: &ControllerFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Lightweight Merkle-next selector: `s1' + s2'` (degree 1).
    // Nonzero exactly on Merkle inputs (MP: s1=0,s2=1; MV: s1=1,s2=0; MU: s1=1,s2=1).
    // Zero on sponge inputs (s1=0,s2=0). Non-unit value on MU (s1+s2=2) is harmless.
    //
    // Soundness: a malicious prover could mislabel a Merkle input as sponge (s1=s2=0)
    // to zero this selector and bypass routing. This is caught by the bus: any (1,0,0)
    // input row fires f_sponge and generates a sponge bus message with no matching
    // decoder request.
    let merkle_next_lite: AB::Expr = AB::Expr::from(cols_next.s1) + AB::Expr::from(cols_next.s2);

    // Gate: on_output(3) * (1-is_boundary)(1) * merkle_next_lite(1) = 5
    let gate = cf.on_output.clone() * AB::Expr::from(cols.is_boundary).not() * merkle_next_lite;

    // Forward propagation: direction_bit on output = direction_bit on next input.
    // Constraint degree: gate(5) * diff(1) = 6
    builder.assert_zero(
        gate.clone()
            * (AB::Expr::from(cols.direction_bit) - AB::Expr::from(cols_next.direction_bit)),
    );

    // Digest routing: for each j in 0..4, enforce
    //   gate * (h_next[j] - h[j] + b * (h_next[4+j] - h_next[j])) = 0
    // where b = direction_bit on the output row.
    // Constraint degree: gate(5) * inner(2) = 7
    let b: AB::Expr = cols.direction_bit.into();
    let rate0_curr = cols.rate0();
    let rate0_next = cols_next.rate0();
    let rate1_next = cols_next.rate1();

    for j in 0..4 {
        builder.assert_zero(
            gate.clone()
                * (AB::Expr::from(rate0_next[j]) - AB::Expr::from(rate0_curr[j])
                    + b.clone() * (AB::Expr::from(rate1_next[j]) - AB::Expr::from(rate0_next[j]))),
        );
    }
}
