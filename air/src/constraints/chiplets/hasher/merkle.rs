//! Hasher chiplet Merkle path constraints.
//!
//! In the controller/permutation split architecture, Merkle constraints apply only to
//! controller rows (perm_seg=0). The constraints enforce:
//!
//! - **Index decomposition**: `idx = 2 * idx_next + direction_bit` on Merkle input rows
//! - **Direction bit booleanity**: `direction_bit * (1 - direction_bit) = 0` on Merkle input rows
//! - **Cross-step index continuity**: For non-final Merkle outputs, next input index equals current
//!   output index
//! - **Output index zero**: HOUT output rows have node_index = 0
//! - **Capacity zeroing**: Merkle input rows have capacity = 0
//! - **Forward propagation**: On non-final output -> next-input boundaries, direction_bit is
//!   propagated from the next input to the current output, making `b_{i+1}` available for routing
//! - **Digest routing**: The digest from output_i is placed in the correct rate half of input_{i+1}
//!   based on direction_bit (which equals `b_{i+1}` via forward propagation)

use miden_core::field::PrimeCharacteristicRing;

use super::HasherExprs;
use crate::MidenAirBuilder;

// CONSTRAINT FUNCTIONS
// ================================================================================================

/// Enforces node index constraints for Merkle operations on controller rows.
///
/// ## Index Decomposition Constraint
///
/// On controller input rows for Merkle operations (s0=1, s1 or s2 non-zero):
/// `idx = 2 * idx_next + direction_bit` where idx_next is the paired output row's index.
///
/// ## Direction Bit Booleanity
///
/// On Merkle input rows: `direction_bit * (1 - direction_bit) = 0`.
///
/// ## Index Zero Constraint
///
/// On sponge (non-Merkle) input rows, node_index must be zero.
///
/// ## Output Index Zero
///
/// On HOUT output rows (final output), node_index must be zero.
pub(super) fn enforce_node_index_constraints<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherExprs<AB::Expr>,
    cols_next: &HasherExprs<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let controller_flag = cols.controller_flag();

    // -------------------------------------------------------------------------
    // Output Index Constraint: index must be 0 on HOUT rows
    // -------------------------------------------------------------------------
    let f_hout = super::flags::f_hout(cols.s0.clone(), cols.s1.clone(), cols.s2.clone());
    builder.assert_zero(
        hasher_flag.clone() * controller_flag.clone() * f_hout * cols.node_index.clone(),
    );

    // -------------------------------------------------------------------------
    // Index Decomposition + Booleanity (on Merkle input rows)
    // -------------------------------------------------------------------------
    // On controller input rows (s0=1), when any Merkle op is active:
    // idx = 2 * idx_next + direction_bit
    // direction_bit is binary
    let f_merkle = super::flags::f_merkle_input(cols.s0.clone(), cols.s1.clone(), cols.s2.clone());

    // Gate degree: hasher_flag(1) * controller_flag(1) * f_merkle(3) = 5
    let gate = hasher_flag.clone() * controller_flag.clone() * f_merkle;

    // Index decomposition: idx - 2 * idx_next - direction_bit = 0
    // Constraint degree: gate(5) * diff(1) = 6
    builder.assert_zero(
        gate.clone()
            * (cols.node_index.clone()
                - AB::Expr::TWO * cols_next.node_index.clone()
                - cols.direction_bit.clone()),
    );

    // Direction bit booleanity: direction_bit * (1 - direction_bit) = 0
    // Constraint degree: gate(5) * direction_bit(1) * (1-direction_bit)(1) = 7
    builder.assert_zero(
        gate * cols.direction_bit.clone() * (AB::Expr::ONE - cols.direction_bit.clone()),
    );

    // -------------------------------------------------------------------------
    // Sponge input node_index zero constraint
    // -------------------------------------------------------------------------
    // On sponge (non-Merkle) input rows, node_index must be zero.
    // f_sponge = s0 * (1-s1) * (1-s2): sponge-mode inputs don't use node_index.
    let f_sponge = super::flags::f_sponge(cols.s0.clone(), cols.s1.clone(), cols.s2.clone());
    builder.assert_zero(
        hasher_flag.clone() * controller_flag.clone() * f_sponge * cols.node_index.clone(),
    );

    // -------------------------------------------------------------------------
    // Cross-step Merkle index continuity (output_i -> input_{i+1})
    // -------------------------------------------------------------------------
    // On non-final controller output rows, if the next row is a Merkle input row,
    // enforce idx_in_{i+1} == idx_out_i.
    let f_output = (AB::Expr::ONE - cols.s0.clone()) * (AB::Expr::ONE - cols.s1.clone());

    // NOTE: `f_merkle_next` is read from `cols_next` without an explicit `hasher_flag_next` gate.
    // This is safe by construction: on local hasher controller rows (perm_seg=0),
    // `enforce_perm_seg_constraints` enforces
    //   hasher_flag * (1 - hasher_flag_next) * (1 - perm_seg) = 0,
    // so `hasher_flag_next = 1` whenever this continuity gate can be active. Thus `cols_next`
    // selectors are guaranteed to belong to the hasher chiplet (not cross-chiplet garbage values).
    let f_merkle_next = super::flags::f_merkle_input(
        cols_next.s0.clone(),
        cols_next.s1.clone(),
        cols_next.s2.clone(),
    );

    // Gate degree: hasher_flag(1) * controller_flag(1) * f_output(2) * (1-is_boundary)(1)
    //              * f_merkle_next(3) = 8
    let continuity_gate = hasher_flag.clone()
        * controller_flag.clone()
        * f_output
        * (AB::Expr::ONE - cols.is_boundary.clone())
        * f_merkle_next;

    // Index continuity: idx_next - idx = 0
    // Constraint degree: continuity_gate(8) * diff(1) = 9
    builder.assert_zero(continuity_gate * (cols_next.node_index.clone() - cols.node_index.clone()));
}

/// Enforces capacity zeroing on Merkle input rows.
///
/// On controller input rows for Merkle operations, all 4 capacity lanes h[8..12] must be zero.
/// This ensures each 2-to-1 compression in the Merkle path starts with a clean sponge capacity.
pub(super) fn enforce_merkle_input_state<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherExprs<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let controller_flag = cols.controller_flag();
    let f_merkle = super::flags::f_merkle_input(cols.s0.clone(), cols.s1.clone(), cols.s2.clone());

    let gate = hasher_flag * controller_flag * f_merkle;
    let cap = cols.capacity();

    for c in &cap {
        builder.assert_zero(gate.clone() * c.clone());
    }
}

/// Enforces Merkle digest routing and direction_bit forward propagation.
///
/// ## Forward Propagation
///
/// On non-final output -> next-input Merkle boundaries, the direction_bit on the output row
/// must equal the direction_bit on the next input row. This makes `b_{i+1}` (the next step's
/// direction bit) available on the output row for digest routing.
///
/// ## Digest Routing
///
/// The digest from output_i (in rate0, `h[0..4]`) must appear in the correct rate half of
/// input_{i+1}, selected by direction_bit:
/// - `direction_bit = 0`: digest goes to rate0 of input_{i+1} (`h_next[j]`)
/// - `direction_bit = 1`: digest goes to rate1 of input_{i+1} (`h_next[4+j]`)
///
/// Combined constraint for each j in 0..4:
/// ```text
/// gate * (h_next[j] - h[j] + direction_bit * (h_next[4+j] - h_next[j])) = 0
/// ```
///
/// The gate uses a lightweight Merkle-next selector (`s1_next + s2_next`, degree 1) instead
/// of the full `f_merkle_input` (degree 3) to keep the routing constraints within the system's
/// max degree of 9. See inline comments for the soundness argument.
pub(super) fn enforce_merkle_digest_routing<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherExprs<AB::Expr>,
    cols_next: &HasherExprs<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let controller_flag = cols.controller_flag();
    let f_output = (AB::Expr::ONE - cols.s0.clone()) * (AB::Expr::ONE - cols.s1.clone());

    // Use a lower-degree Merkle-next selector to keep routing constraints within degree 8.
    //
    // `f_merkle_input` (degree 3) = `s0 * (s1 + s2 - s1*s2)` is too expensive here because
    // the routing inner expression is degree 2 (involves direction_bit * state_diff), making
    // the total `gate(8) * inner(2) = 10` which exceeds the system's max degree of 9.
    //
    // Instead we use `s1_next + s2_next` (degree 1): among input rows, this is nonzero
    // exactly on Merkle inputs (MP: s1=0,s2=1; MV: s1=1,s2=0; MU: s1=1,s2=1) and zero on
    // sponge inputs (s1=0,s2=0). The non-unit value on MU rows (s1+s2=2) is harmless: it
    // only scales a constraint that is already zero when the routing is correct.
    //
    // Soundness note: a malicious prover could mislabel a Merkle input as sponge (s1=s2=0)
    // to zero this selector and bypass routing. This is caught by the bus: any (1,0,0) input
    // row unconditionally fires f_sponge_start or f_sponge_respan, generating a sponge bus
    // message with a unique address that has no matching decoder request.
    let merkle_next_lite = cols_next.s1.clone() + cols_next.s2.clone();

    // Gate degree: hasher_flag(1) * controller_flag(1) * f_output(2) * (1-is_boundary)(1)
    //              * merkle_next_lite(1) = 6
    let gate = hasher_flag
        * controller_flag
        * f_output
        * (AB::Expr::ONE - cols.is_boundary.clone())
        * merkle_next_lite;

    // Forward propagation: direction_bit on output row = direction_bit on next input row.
    // Constraint degree: gate(6) * diff(1) = 7
    builder
        .assert_zero(gate.clone() * (cols.direction_bit.clone() - cols_next.direction_bit.clone()));

    // Digest routing: for each j in 0..4, enforce
    //   gate * ((1 - b) * (h_next[j] - h[j]) + b * (h_next[4+j] - h[j])) = 0
    // where b = direction_bit on the output row (= b_{i+1} via propagation).
    //
    // Expanding: gate * (h_next[j] - h[j] + b * (h_next[4+j] - h_next[j])) = 0
    // Constraint degree: gate(6) * inner(2) = 8
    let b = cols.direction_bit.clone();
    let rate0_curr = cols.rate0();
    let rate0_next = cols_next.rate0();
    let rate1_next = cols_next.rate1();

    for j in 0..4 {
        builder.assert_zero(
            gate.clone()
                * (rate0_next[j].clone() - rate0_curr[j].clone()
                    + b.clone() * (rate1_next[j].clone() - rate0_next[j].clone())),
        );
    }
}
