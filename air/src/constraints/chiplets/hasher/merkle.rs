//! Hasher chiplet Merkle path constraints.
//!
//! In the controller/permutation split architecture, Merkle constraints apply only to
//! controller rows (perm_seg=0). The constraints enforce:
//!
//! - **Index shifting**: Node index on input row = 2 * node_index on output row + discarded bit
//! - **Discarded-bit binary**: The per-step discarded bit is constrained to {0,1}
//! - **Cross-step index continuity**: For non-final Merkle outputs, next input index equals
//!   current output index
//! - **Output index zero**: HOUT output rows have node_index = 0
//! - **Capacity zeroing**: Merkle input rows have capacity = 0
//!
//! ## TODO: Digest routing constraint
//!
//! There is currently no direct constraint enforcing that the digest from step i's output
//! is placed in the correct rate half (RATE0 or RATE1) of step i+1's input based on the
//! direction bit of the NEXT input step. The monolithic 32-row hasher design had this
//! constraint inline.
//!
//! The fix likely requires a `direction_bit` trace column so that `b_{i+1}` is available at the
//! (output_i, input_{i+1}) boundary.

use miden_core::field::PrimeCharacteristicRing;

use super::HasherColumns;
use crate::{
    Felt,
    constraints::tagging::{
        TagGroup, TaggingAirBuilderExt, tagged_assert_zero, tagged_assert_zero_integrity,
        tagged_assert_zeros,
    },
};

// TAGGING NAMESPACES
// ================================================================================================

const MERKLE_INDEX_BINARY_NAMESPACE: &str = "chiplets.hasher.merkle.index.binary";
const MERKLE_INDEX_ZERO_NAMESPACE: &str = "chiplets.hasher.merkle.index.zero";
const MERKLE_CAP_NAMESPACE: &str = "chiplets.hasher.merkle.capacity";

const OUTPUT_INDEX_NAMES: [&str; 1] = [super::OUTPUT_INDEX_NAMESPACE];
const MERKLE_INDEX_CONTINUITY_NAMESPACE: &str = "chiplets.hasher.merkle.index.continuity";

const MERKLE_INDEX_NAMES: [&str; 3] = [
    MERKLE_INDEX_BINARY_NAMESPACE,
    MERKLE_INDEX_ZERO_NAMESPACE,
    MERKLE_INDEX_CONTINUITY_NAMESPACE,
];
const MERKLE_INPUT_STATE_NAMES: [&str; 4] = [MERKLE_CAP_NAMESPACE; 4];

const OUTPUT_INDEX_TAGS: TagGroup = TagGroup {
    base: super::HASHER_OUTPUT_IDX_ID,
    names: &OUTPUT_INDEX_NAMES,
};
const MERKLE_INDEX_TAGS: TagGroup = TagGroup {
    base: super::HASHER_MERKLE_INDEX_BASE_ID,
    names: &MERKLE_INDEX_NAMES,
};
const MERKLE_INPUT_STATE_TAGS: TagGroup = TagGroup {
    base: super::HASHER_MERKLE_INPUT_STATE_BASE_ID,
    names: &MERKLE_INPUT_STATE_NAMES,
};

// CONSTRAINT FUNCTIONS
// ================================================================================================

/// Enforces node index constraints for Merkle operations on controller rows.
///
/// ## Index Shift Constraint
///
/// On controller input rows for Merkle operations (s0=1, s1 or s2 non-zero), the index
/// shifts from input to output: `b = input_idx - 2 * output_idx` must be binary.
/// The output row is the NEXT row (controller pairs are adjacent).
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
    cols: &HasherColumns<AB::Expr>,
    cols_next: &HasherColumns<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let controller_flag = cols.controller_flag();

    // -------------------------------------------------------------------------
    // Output Index Constraint: index must be 0 on HOUT rows
    // -------------------------------------------------------------------------
    let f_hout = super::flags::f_hout(cols.s0.clone(), cols.s1.clone(), cols.s2.clone());
    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &OUTPUT_INDEX_TAGS,
        &mut idx,
        hasher_flag.clone() * controller_flag.clone() * f_hout * cols.node_index.clone(),
    );

    // -------------------------------------------------------------------------
    // Index Shift Constraint (on Merkle input rows)
    // -------------------------------------------------------------------------
    // On controller input rows (s0=1), when any Merkle op is active:
    // b = input_idx - 2 * output_idx_next must be binary.
    // The next row is the paired output row.
    let f_merkle = super::flags::f_merkle_input(cols.s0.clone(), cols.s1.clone(), cols.s2.clone());

    // Direction bit: b = idx - 2 * idx_next
    let b = cols.node_index.clone() - AB::Expr::TWO * cols_next.node_index.clone();

    let gate = hasher_flag.clone() * controller_flag.clone() * f_merkle;
    let mut idx = 0;
    tagged_assert_zero(builder, &MERKLE_INDEX_TAGS, &mut idx, gate * (b.square() - b));

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
    let f_merkle_next =
        super::flags::f_merkle_input(cols_next.s0.clone(), cols_next.s1.clone(), cols_next.s2.clone());

    let continuity_gate = hasher_flag.clone()
        * controller_flag.clone()
        * f_output
        * (AB::Expr::ONE - cols.is_final.clone())
        * f_merkle_next;

    tagged_assert_zero(
        builder,
        &MERKLE_INDEX_TAGS,
        &mut idx,
        continuity_gate * (cols_next.node_index.clone() - cols.node_index.clone()),
    );

    // -------------------------------------------------------------------------
    // Sponge input node_index zero constraint
    // -------------------------------------------------------------------------
    // On sponge (non-Merkle) input rows, node_index must be zero.
    // f_sponge = s0 * (1-s1) * (1-s2): sponge-mode inputs don't use node_index.
    let f_sponge = super::flags::f_sponge(cols.s0.clone(), cols.s1.clone(), cols.s2.clone());
    tagged_assert_zero(
        builder,
        &MERKLE_INDEX_TAGS,
        &mut idx,
        hasher_flag * controller_flag * f_sponge * cols.node_index.clone(),
    );
}

/// Enforces capacity zeroing on Merkle input rows.
///
/// On controller input rows for Merkle operations, all 4 capacity lanes h[8..12] must be zero.
/// This ensures each 2-to-1 compression in the Merkle path starts with a clean sponge capacity.
pub(super) fn enforce_merkle_input_state<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherColumns<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let controller_flag = cols.controller_flag();
    let f_merkle = super::flags::f_merkle_input(cols.s0.clone(), cols.s1.clone(), cols.s2.clone());

    let gate = hasher_flag * controller_flag * f_merkle;
    let cap = cols.capacity();

    let mut idx = 0;
    tagged_assert_zeros(
        builder,
        &MERKLE_INPUT_STATE_TAGS,
        &mut idx,
        MERKLE_CAP_NAMESPACE,
        core::array::from_fn::<_, 4, _>(|i| gate.clone() * cap[i].clone()),
    );
}
