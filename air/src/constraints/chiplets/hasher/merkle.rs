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
use miden_crypto::stark::air::AirBuilder;

use super::HasherFlags;
use crate::{
    MidenAirBuilder,
    constraints::{chiplets::columns::HasherCols, utils::BoolNot},
};

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
/// Outside of shift rows (and output rows), the index must remain unchanged.
pub(super) fn enforce_node_index_constraints<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherCols<AB::Var>,
    cols_next: &HasherCols<AB::Var>,
    flags: &HasherFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let node_index: AB::Expr = cols.node_index.into();
    let node_index_next: AB::Expr = cols_next.node_index.into();

    let builder = &mut builder.when(hasher_flag);

    // -------------------------------------------------------------------------
    // Output Index Constraint
    // -------------------------------------------------------------------------

    // Constraint 1: Index must be 0 on output rows.
    builder.when(flags.f_out.clone()).assert_zero(node_index.clone());

    // -------------------------------------------------------------------------
    // Index Shift Constraint
    // -------------------------------------------------------------------------

    let f_shift = flags.f_merkle_active();
    let f_out = flags.f_out.clone();

    // Direction bit: b = i - 2*i'
    let b = node_index.clone() - node_index_next.clone().double();

    // Constraint 2: b must be binary when shifting (b^2 - b = 0)
    builder.when(f_shift.clone()).assert_bool(b.clone());

    // -------------------------------------------------------------------------
    // Index Stability Constraint
    // -------------------------------------------------------------------------

    // Constraint 3: Index unchanged when not shifting or outputting
    // f_out and f_shift are mutually exclusive, so their sum is binary.
    let keep = (f_out + f_shift).not();
    builder.when(keep).assert_eq(node_index_next, node_index);
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
pub(super) fn enforce_merkle_absorb_state<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherCols<AB::Var>,
    cols_next: &HasherCols<AB::Var>,
    flags: &HasherFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let f_absorb = flags.f_merkle_absorb();

    let digest: [AB::Expr; 4] = cols.digest().map(Into::into);
    let rate0_next: [AB::Expr; 4] = cols_next.rate0().map(Into::into);
    let rate1_next: [AB::Expr; 4] = cols_next.rate1().map(Into::into);
    let cap_next: [AB::Expr; 4] = cols_next.capacity().map(Into::into);

    // Direction bit: b = i - 2*i'
    let node_index: AB::Expr = cols.node_index.into();
    let node_index_next: AB::Expr = cols_next.node_index.into();
    let b = node_index - node_index_next.double();

    // All constraints in this function are active during Merkle absorb.
    let absorb_builder = &mut builder.when(hasher_flag * f_absorb);

    // -------------------------------------------------------------------------
    // Capacity Reset Constraint
    // -------------------------------------------------------------------------

    // Capacity reset to zero during absorb.
    for cap in &cap_next {
        absorb_builder.assert_zero(cap.clone());
    }

    // -------------------------------------------------------------------------
    // Digest Placement Constraints
    // -------------------------------------------------------------------------

    // b=0: digest goes to rate0 (h'[0..4] = h[0..4]).
    {
        let builder = &mut absorb_builder.when(b.not());
        for i in 0..4 {
            builder.assert_eq(rate0_next[i].clone(), digest[i].clone());
        }
    }
    // b=1: digest goes to rate1 (h'[4..8] = h[0..4]).
    {
        let builder = &mut absorb_builder.when(b);
        for i in 0..4 {
            builder.assert_eq(rate1_next[i].clone(), digest[i].clone());
        }
    }
}
