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

use super::{HasherColumns, HasherFlags};
use crate::{Felt, constraints::tagging::TaggingAirBuilderExt};

// TAGGING NAMESPACES
// ================================================================================================

const MERKLE_INDEX_BINARY_NAMESPACE: &str = "chiplets.hasher.merkle.index.binary";
const MERKLE_INDEX_STABILITY_NAMESPACE: &str = "chiplets.hasher.merkle.index.stability";
const MERKLE_CAP_NAMESPACE: &str = "chiplets.hasher.merkle.capacity";
const MERKLE_RATE0_NAMESPACE: &str = "chiplets.hasher.merkle.digest.rate0";
const MERKLE_RATE1_NAMESPACE: &str = "chiplets.hasher.merkle.digest.rate1";

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
    transition_flag: AB::Expr,
    cols: &HasherColumns<AB::Expr>,
    cols_next: &HasherColumns<AB::Expr>,
    flags: &HasherFlags<AB::Expr>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    let one: AB::Expr = AB::Expr::ONE;

    // -------------------------------------------------------------------------
    // Output Index Constraint
    // -------------------------------------------------------------------------

    // Constraint 1: Index must be 0 on output rows.
    builder.tagged(super::HASHER_OUTPUT_IDX_ID, super::OUTPUT_INDEX_NAMESPACE, |builder| {
        builder.assert_zero(hasher_flag * flags.f_out.clone() * cols.node_index.clone());
    });

    // -------------------------------------------------------------------------
    // Index Shift Constraint
    // -------------------------------------------------------------------------

    let f_shift = flags.f_merkle_active();
    let f_out = flags.f_out.clone();

    // Direction bit: b = i - 2*i'
    // This is the bit discarded when shifting index right by 1.
    let b = cols.node_index.clone() - AB::Expr::TWO * cols_next.node_index.clone();

    // Constraint 2: b must be binary when shifting (b^2 - b = 0)
    builder.tagged(super::HASHER_MERKLE_INDEX_BASE_ID, MERKLE_INDEX_BINARY_NAMESPACE, |builder| {
        builder
            .when(transition_flag.clone())
            .assert_zero(f_shift.clone() * (b.square() - b.clone()));
    });

    // -------------------------------------------------------------------------
    // Index Stability Constraint
    // -------------------------------------------------------------------------

    // Constraint 3: Index unchanged when not shifting or outputting
    // keep = 1 - f_out - f_shift
    let keep = one.clone() - f_out - f_shift;
    builder.tagged(
        super::HASHER_MERKLE_INDEX_BASE_ID + 1,
        MERKLE_INDEX_STABILITY_NAMESPACE,
        |builder| {
            builder
                .when(transition_flag.clone())
                .assert_zero(keep * (cols_next.node_index.clone() - cols.node_index.clone()));
        },
    );
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
    transition_flag: AB::Expr,
    cols: &HasherColumns<AB::Expr>,
    cols_next: &HasherColumns<AB::Expr>,
    flags: &HasherFlags<AB::Expr>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    let one: AB::Expr = AB::Expr::ONE;
    let f_absorb = flags.f_merkle_absorb();

    let digest = cols.digest();
    let rate0_next = cols_next.rate0();
    let rate1_next = cols_next.rate1();
    let cap_next = cols_next.capacity();

    // Direction bit: b = i - 2*i'
    let b = cols.node_index.clone() - AB::Expr::TWO * cols_next.node_index.clone();

    // -------------------------------------------------------------------------
    // Capacity Reset Constraint
    // -------------------------------------------------------------------------

    // Constraint 1: Capacity reset to zero (batched).
    // Use a combined gate to share `transition_flag * f_absorb` across all 4 lanes.
    let gate_absorb = transition_flag.clone() * f_absorb.clone();
    let cap_ids: [usize; 4] = core::array::from_fn(|i| super::HASHER_MERKLE_ABSORB_BASE_ID + i);
    builder.tagged_list(cap_ids, MERKLE_CAP_NAMESPACE, |builder| {
        builder
            .when(gate_absorb)
            .assert_zeros(core::array::from_fn::<_, 4, _>(|i| cap_next[i].clone()));
    });

    // -------------------------------------------------------------------------
    // Digest Placement Constraints
    // -------------------------------------------------------------------------

    // Constraint 2: If b=0, digest goes to rate0 (h'[0..4] = h[0..4])
    let f_b0 = f_absorb.clone() * (one.clone() - b.clone());
    let gate_b0 = transition_flag.clone() * f_b0;
    let rate0_ids: [usize; 4] =
        core::array::from_fn(|i| super::HASHER_MERKLE_ABSORB_BASE_ID + 4 + i);
    builder.tagged_list(rate0_ids, MERKLE_RATE0_NAMESPACE, |builder| {
        builder.when(gate_b0).assert_zeros(core::array::from_fn::<_, 4, _>(|i| {
            rate0_next[i].clone() - digest[i].clone()
        }));
    });

    // Constraint 3: If b=1, digest goes to rate1 (h'[4..8] = h[0..4])
    let f_b1 = f_absorb * b;
    let gate_b1 = transition_flag * f_b1;
    let rate1_ids: [usize; 4] =
        core::array::from_fn(|i| super::HASHER_MERKLE_ABSORB_BASE_ID + 8 + i);
    builder.tagged_list(rate1_ids, MERKLE_RATE1_NAMESPACE, |builder| {
        builder.when(gate_b1).assert_zeros(core::array::from_fn::<_, 4, _>(|i| {
            rate1_next[i].clone() - digest[i].clone()
        }));
    });
}
