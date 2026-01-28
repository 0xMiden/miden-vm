//! Hasher chiplet Merkle path constraints.
//!
//! This module enforces constraints specific to Merkle tree operations:
//!
//! - **Index shifting**: Node index shifts right by 1 bit at absorb points
//! - **Index stability**: Index unchanged outside of Merkle operations
//! - **Capacity reset**: Capacity lanes reset to zero on Merkle absorb
//! - **Digest placement**: Current digest placed in rate0 or rate1 based on direction bit
//!
//! ## Merkle Operations
//!
//! | Flag | Operation | Description |
//! |------|-----------|-------------|
//! | MP   | Merkle Path | Standard path verification |
//! | MV   | Merkle Verify | Old root verification (for updates) |
//! | MU   | Merkle Update | New root computation (for updates) |
//! | MPA  | Merkle Path Absorb | Absorb next sibling (standard) |
//! | MVA  | Merkle Verify Absorb | Absorb next sibling (old path) |
//! | MUA  | Merkle Update Absorb | Absorb next sibling (new path) |

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use super::{
    flags::{f_merkle_absorb, f_merkle_active, f_mp, f_mpa, f_mu, f_mua, f_mv, f_mva, f_out},
    periodic::{P_CYCLE_ROW_0, P_CYCLE_ROW_31},
};
use crate::Felt;

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces node index constraints for Merkle operations.
///
/// ## Index Shift Constraint
///
/// On Merkle start (row 0) and absorb (row 31) operations, the index shifts right by 1 bit:
/// `i' = floor(i/2)`. The discarded bit `b = i - 2*i'` must be binary.
///
/// This encodes the tree traversal from leaf to root.
///
/// ## Index Stability Constraint
///
/// Outside of shift points (and output rows), the index must remain unchanged.
///
/// ## Degree Analysis
/// - f_merkle_active (shift flag): ~4
/// - Binary constraint on b: ~6 (shift_flag * (b^2 - b))
/// - Stability constraint: ~5
pub fn enforce_node_index_constraints<AB>(
    builder: &mut AB,
    transition_flag: AB::Expr,
    s0: AB::Expr,
    s1: AB::Expr,
    s2: AB::Expr,
    node_index: AB::Expr,
    node_index_next: AB::Expr,
    periodic: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder<F = Felt>,
{
    let cycle_row_0: AB::Expr = periodic[P_CYCLE_ROW_0].into();
    let cycle_row_31: AB::Expr = periodic[P_CYCLE_ROW_31].into();

    let one: AB::Expr = AB::Expr::ONE;

    // -------------------------------------------------------------------------
    // Compute Merkle operation flags
    // -------------------------------------------------------------------------

    // Start flags (row 0)
    let flag_mp = f_mp(cycle_row_0.clone(), s0.clone(), s1.clone(), s2.clone());
    let flag_mv = f_mv(cycle_row_0.clone(), s0.clone(), s1.clone(), s2.clone());
    let flag_mu = f_mu(cycle_row_0.clone(), s0.clone(), s1.clone(), s2.clone());

    // Absorb flags (row 31)
    let flag_mpa = f_mpa(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());
    let flag_mva = f_mva(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());
    let flag_mua = f_mua(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());

    // Output flag
    let flag_out = f_out(cycle_row_31.clone(), s0.clone(), s1.clone());

    // Combined shift flag: any Merkle start or absorb operation
    let f_shift = f_merkle_active(
        flag_mp.clone(),
        flag_mv.clone(),
        flag_mu.clone(),
        flag_mpa.clone(),
        flag_mva.clone(),
        flag_mua.clone(),
    );

    // -------------------------------------------------------------------------
    // Index Shift Constraint
    // -------------------------------------------------------------------------

    // Direction bit: b = i - 2*i'
    // This is the bit discarded when shifting index right by 1.
    let b = node_index.clone() - AB::Expr::TWO * node_index_next.clone();

    // Store builder gate for efficiency
    let mut b_trans = builder.when(transition_flag.clone());

    // Constraint 1: b must be binary when shifting (b^2 - b = 0)
    b_trans.assert_zero(f_shift.clone() * (b.square() - b.clone()));

    // -------------------------------------------------------------------------
    // Index Stability Constraint
    // -------------------------------------------------------------------------

    // Constraint 2: Index unchanged when not shifting or outputting
    // keep = 1 - f_out - f_shift
    let keep = one.clone() - flag_out.clone() - f_shift.clone();
    b_trans.assert_zero(keep * (node_index_next.clone() - node_index.clone()));

    // -------------------------------------------------------------------------
    // Output Index Constraint
    // -------------------------------------------------------------------------

    // Constraint 3: Index must be 0 on output rows
    // This ensures Merkle path traversal completed (reached root)
    builder.assert_zero(transition_flag * flag_out * node_index);
}

/// Enforces state constraints for Merkle absorb operations (MPA/MVA/MUA on row 31).
///
/// ## Capacity Reset
///
/// The capacity lanes `h[8..12]` are reset to zero for the next 2-to-1 compression.
///
/// ## Digest Placement
///
/// The current digest `h[0..4]` is copied to either rate0 or rate1 based on direction bit `b`:
/// - If `b=0`: digest goes to rate0 (`h'[0..4] = h[0..4]`), sibling to rate1 (witness)
/// - If `b=1`: digest goes to rate1 (`h'[4..8] = h[0..4]`), sibling to rate0 (witness)
///
/// ## Degree Analysis
/// - f_merkle_absorb: ~4
/// - Direction selection (f_b0, f_b1): ~5
/// - State constraint: ~6
#[allow(clippy::too_many_arguments)]
pub fn enforce_merkle_absorb_state<AB>(
    builder: &mut AB,
    transition_flag: AB::Expr,
    s0: AB::Expr,
    s1: AB::Expr,
    s2: AB::Expr,
    node_index: AB::Expr,
    node_index_next: AB::Expr,
    h_digest: &[AB::Expr; 4],
    h_next_rate0: &[AB::Expr; 4],
    h_next_rate1: &[AB::Expr; 4],
    h_next_cap: &[AB::Expr; 4],
    periodic: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder<F = Felt>,
{
    let cycle_row_31: AB::Expr = periodic[P_CYCLE_ROW_31].into();

    let one: AB::Expr = AB::Expr::ONE;

    // Absorb flags (row 31)
    let flag_mpa = f_mpa(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());
    let flag_mva = f_mva(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());
    let flag_mua = f_mua(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());

    // Combined Merkle absorb flag
    let f_absorb = f_merkle_absorb(flag_mpa, flag_mva, flag_mua);

    // Direction bit: b = i - 2*i'
    let b = node_index - AB::Expr::TWO * node_index_next;

    // -------------------------------------------------------------------------
    // Capacity Reset Constraint
    // -------------------------------------------------------------------------

    // Constraint 1: Capacity reset to zero (batched).
    // Use a combined gate to share `transition_flag * f_absorb` across all 4 lanes.
    let gate_absorb = transition_flag.clone() * f_absorb.clone();
    builder
        .when(gate_absorb)
        .assert_zeros(core::array::from_fn::<_, 4, _>(|i| h_next_cap[i].clone()));

    // -------------------------------------------------------------------------
    // Digest Placement Constraints
    // -------------------------------------------------------------------------

    // Constraint 2: If b=0, digest goes to rate0 (h'[0..4] = h[0..4])
    let f_b0 = f_absorb.clone() * (one.clone() - b.clone());
    let gate_b0 = transition_flag.clone() * f_b0;
    builder.when(gate_b0).assert_zeros(core::array::from_fn::<_, 4, _>(|i| {
        h_next_rate0[i].clone() - h_digest[i].clone()
    }));

    // Constraint 3: If b=1, digest goes to rate1 (h'[4..8] = h[0..4])
    let f_b1 = f_absorb * b;
    let gate_b1 = transition_flag * f_b1;
    builder.when(gate_b1).assert_zeros(core::array::from_fn::<_, 4, _>(|i| {
        h_next_rate1[i].clone() - h_digest[i].clone()
    }));
}
